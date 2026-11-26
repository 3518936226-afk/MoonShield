/// Runtime string semantics ported from moonutil moon_pkg/lexer.rs at 738607b.
/// Apache-2.0, Copyright 2026 International Digital Economy Academy.
/// Runtime .mbtx strings use JSON-style four-hex escapes; surrogate codepoints are rejected.
fn decode(raw : String, loc : @basic.Location, out : Array[Json], json_mode : Bool) -> String {
  if !raw.contains("\\") { return raw }
  if json_mode {
    let value = try Some(@json.parse("\"" + raw + "\"")) catch { _ => None }
    if value is Some(String(s)) { return s }
    emit(out, "INVALID_LITERAL", "error", "Invalid JSON string escape", loc)
    return raw
  }
  let chars = raw.to_array()
  let result = StringBuilder()
  let mut i = 0
  let mut valid = true
  while i < chars.length() {
    let c = chars[i]
    i += 1
    if c != '\\' { result.write_char(c); continue }
    if i == chars.length() { valid = false; break }
    let e = chars[i]
    i += 1
    match e {
      'n' => result.write_char('\n')
      't' => result.write_char('\t')
      'r' => result.write_char('\r')
      'f' => result.write_char('\u000c')
      'b' => result.write_char('\u0008')
      '\\' | '"' | '/' => result.write_char(e)
      'u' => {
        if i + 4 > chars.length() { valid = false; break }
        let mut value = 0
        for j = 0; j < 4; j = j + 1 {
          let x = chars[i + j].to_int()
          let digit = if x >= 48 && x <= 57 { x - 48 }
            else if x >= 65 && x <= 70 { x - 55 }
            else if x >= 97 && x <= 102 { x - 87 } else { -1 }
          if digit < 0 { valid = false }
          value = value * 16 + digit
        }
        i += 4
        if !valid || (value >= 0xd800 && value <= 0xdfff) { valid = false; break }
        if value.to_char() is Some(ch) { result.write_char(ch) } else { valid = false; break }
      }
      _ => { valid = false; break }
    }
  }
  if !valid {
    emit(out, "INVALID_LITERAL", "error", "Escape differs from the pinned Moonrun string grammar", loc)
    raw
  } else { result.to_string() }
}

fn normalize_fields(fields : Array[@config.Field], out : Array[Json], json_mode : Bool) -> Array[@config.Field] {
  fields.map(f => {
    key: decode(f.key, f.key_loc, out, json_mode), key_loc: f.key_loc,
    value: normalize_expr(f.value, out, json_mode),
  })
}

fn normalize_expr(e : @config.Expr, out : Array[Json], json_mode : Bool) -> @config.Expr {
  match e {
    String(str~, loc~) => String(str=decode(str, loc, out, json_mode), loc~)
    Array(items~, loc~) => Array(items=items.map(x => normalize_expr(x, out, json_mode)), loc~)
    Map(fields~, loc~) => Map(fields=normalize_fields(fields, out, json_mode), loc~)
    Apply(name~, name_loc~, args~, args_loc~, loc~) => Apply(name~, name_loc~, args=normalize_fields(args, out, json_mode), args_loc~, loc~)
    _ => e
  }
}

fn value_json(e : @config.Expr, redact : Bool) -> Json {
  match e {
    String(str~, ..) => if redact { "<redacted>" } else { Json::string(str) }
    Bool(value~, ..) => Json::boolean(value)
    Array(items~, ..) => Json::array(items.map(x => value_json(x, redact)))
    Map(fields~, ..) => {
      let obj : Map[String, Json] = Map([])
      for f in fields { obj[f.key] = value_json(f.value, redact || f.key == "set") }
      Json::object(obj)
    }
    _ => Json::null()
  }
}

/// One compact, immutable input result. Paths stay logical; grants are not resolved or executed.
pub fn audit(source : String, path~ : String, kind~ : String = "mbtx") -> Json {
  let mut issue = "POLICY_FORMAT_UNSUPPORTED"
  let framed : String? = if kind == "json" {
    match (try Some(@json.parse(source, reject_duplicate_keys=true)) catch { _ => None }) {
      Some(Object(fields)) => {
        // Serde Option domains accept null, but the official AST does not represent it.
        // Preserve the coverage gap explicitly rather than calling valid JSON invalid.
        if fields.iter().any(pair => pair.1 == Json::null()) {
          issue = "JSON_NULL_UNSUPPORTED"
          None
        } else {
        let trimmed = source.trim().to_owned()
        Some("permission(" + trimmed[1:trimmed.length() - 1].to_owned() + ")")
        }
      }
      Some(_) => { issue = "INVALID_TYPE"; None }
      None => { issue = "JSON_SYNTAX"; None }
    }
  } else if kind == "mbtx" {
    let (value, code) = frame(source)
    issue = code
    value
  } else { None }
  if framed is None {
    return finish({ "policy_state": "ABSENT", "permission_count": 0, "policy": Json::null(),
      "findings": [{ "code": issue,
        "severity": if issue == "NO_PERMISSION_HEADER" { "high" } else if issue.contains("UNSUPPORTED") { "warning" } else { "error" },
        "message": "Cannot establish a supported explicit policy", "range": Json::null() }] }, source, path, 0)
  }
  let result = analyze_header(framed.unwrap(), json_mode=kind == "json")
  // JSON object braces are replaced by an eleven-character permission( prefix.
  let delta = if kind == "json" { 10 - (source.iter().count() - source.trim_start().iter().count()) } else { 0 }
  finish(result, source, path, delta)
}

/// Exact documented fence algorithm from moonutil/front_matter.rs (738607b),
/// with legacy YAML explicitly unsupported, never treated as an empty policy.
fn frame(source : String) -> (String?, String) {
  let chars = source.to_array()
  let mut start = 0
  if chars.get(0) == Some('\u{feff}') { start = 1 }
  if chars.get(start) == Some('#') && chars.get(start + 1) == Some('!') {
    while start < chars.length() && chars[start] != '\n' { start += 1 }
    if start < chars.length() { start += 1 }
  }
  let mut text = String::from_array(chars[start:])
  let trimmed = text.trim_start().to_owned()
  start += text.iter().count() - trimmed.iter().count()
  text = trimmed
  let lines = text.split("\n").map(x => x.to_owned()).to_array()
  guard lines.length() > 0 && fence(lines[0]) else {
    return (None, if text.has_prefix("// policy:") || text.has_prefix("//policy:") { "LEGACY_POLICY_UNSUPPORTED" } else { "NO_PERMISSION_HEADER" })
  }
  let prefix = StringBuilder()
  for i = 0; i < start; i = i + 1 { prefix.write_char(if chars[i] == '\n' { '\n' } else { ' ' }) }
  for c in lines[0] { prefix.write_char(if c == '\r' { '\r' } else { ' ' }) }
  prefix.write_char('\n')
  let mut found = false
  let mut closing = 0
  for i = 1; i < lines.length(); i = i + 1 {
    if fence(lines[i]) { found = true; closing = i; break }
    prefix.write_string(lines[i]); prefix.write_char('\n')
  }
  if !found { return (None, "UNTERMINATED_HEADER") }
  let rest = lines[closing + 1:].join("\n").trim_start().to_owned()
  if rest.has_prefix("// policy:") || rest.has_prefix("//policy:") { return (None, "LEGACY_POLICY_UNSUPPORTED") }
  (Some(prefix.to_string()), "")
}

fn fence(line : String) -> Bool {
  let s = line.trim().to_owned()
  s.length() >= 3 && s.iter().all(c => c == '-')
}

fn source_position(source : String, offset : Int) -> Json {
  let mut line = 1
  let mut column = 1
  let mut index = 0
  for c in source {
    if index >= offset { break }
    if c == '\n' { line += 1; column = 1 } else { column += 1 }
    index += 1
  }
  { "line": line, "column": column, "offset": offset }
}

fn finish(result : Json, source : String, path : String, delta : Int) -> Json {
  guard result is Object(obj) else { return result }
  let findings = get_array(result, "findings")
  let mapped = findings.map(f => {
    if f is Object(fields) {
      if get(f, "range") is Object(range) {
        for key in ["start", "end"] {
          if range.get(key) is Some(Object(p)) && p.get("offset") is Some(Number(n, ..)) {
            range[key] = source_position(source, Int::max(0, n.to_int() - delta))
          }
        }
      }
      classify(Json::object(fields))
    } else { f }
  })
  obj["findings"] = Json::array(mapped)
  let status = assessment_status(mapped)
  if ["INVALID", "UNSUPPORTED"].contains(status) { obj["policy_state"] = Json::string(status) }
  obj["coverage"] = if mapped.any(f => text(f, "code").contains("UNSUPPORTED")) { "INCOMPLETE" } else { "SUPPORTED_RULES_ONLY" }
  obj["status"] = Json::string(status)
  obj["source"] = Json::string(path)
  obj["source_executed"] = Json::boolean(false)
  obj["offset_unit"] = "unicode_codepoints"
  obj["schema_version"] = 2
  obj["version"] = Json::string(version())
  obj["scope"] = "Policy audit only; not a proof that the script is safe."
  Json::object(obj)
}

pub fn get(j : Json, key : String) -> Json {
  if j is Object(o) { o.get(key).unwrap_or(Json::null()) } else { Json::null() }
}
pub fn text(j : Json, key : String) -> String {
  if get(j, key) is String(s) { s } else { "" }
}
pub fn get_array(j : Json, key : String) -> Array[Json] {
  if get(j, key) is Array(a) { a } else { [] }
}
