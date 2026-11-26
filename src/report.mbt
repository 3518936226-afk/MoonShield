/// Rendering never dumps candidate source or unredacted environment literal values.
pub fn combine(embedded : Json, selected : Json, inherited : Array[Json]) -> Json {
  let groups = [selected]
  for parent in inherited { groups.push(parent) }
  let findings : Array[Json] = []
  for i, group in groups {
    for f in get_array(group, "findings") {
      let o = clone_object(f)
      o["source"] = get(group, "source")
      o["role"] = if i == 0 { "selected" } else { "inherited" }
      findings.push(classify(Json::object(o)))
    }
  }
  if text(embedded, "source") != text(selected, "source") {
    for f in get_array(embedded, "findings") {
      if ["CONFIG_SYNTAX", "DUPLICATE_PERMISSION", "UNTERMINATED_HEADER", "LEGACY_POLICY_UNSUPPORTED", "POLICY_FORMAT_UNSUPPORTED", "INVALID_LITERAL"].contains(text(f, "code")) {
        let o = clone_object(f)
        o["source"] = get(embedded, "source")
        o["role"] = "overridden_header"
        findings.push(classify(Json::object(o)))
      }
    }
  }
  refresh({ "version": version(), "schema_version": 2, "target": get(embedded, "source"),
    "embedded": embedded, "selected": selected, "inherited": inherited,
    "effective_model": "Selected policy replaces embedded policy; every supplied inherited fs/net/process ceiling must additionally authorize an operation. Environment provisioning comes from the selected policy, not a merged authorization list.",
    "inherited_context": "Only explicitly supplied --inherit files are known; ambient session inheritance is not auto-discovered.",
    "path_context": { "mode": "static", "content_read": false },
    "source_executed": false, "configuration_findings": findings,
    "findings": findings.map(f => projection(f, groups)) })
}

pub fn exit_code(report : Json, fail_on~ : String = "warning") -> Int {
  if ["INVALID", "UNSUPPORTED", "ERROR"].contains(text(report, "status")) { return 1 }
  let threshold = if fail_on == "error" { 3 } else if fail_on == "high" { 2 } else { 1 }
  if get_array(report, "findings").any(f => {
    let level = match text(f, "severity") { "error" => 3; "high" => 2; "warning" => 1; _ => 0 }
    level >= threshold
  }) { 1 } else { 0 }
}

pub fn render(report : Json, format : String, lang~ : String = "en") -> String {
  match format {
    "json" => report.stringify(indent=2)
    "sarif" => sarif(report).stringify(indent=2)
    "text" => human(report, false, lang)
    _ => human(report, true, lang)
  }
}

fn uri(path : String) -> String {
  let p = path.replace_all(old="\\", new="/")
  let p = if p.has_prefix("//") { "file:" + p } else if p.length() > 2 && p.code_unit_at(1) == 58 { "file:///" + p } else if p.has_prefix("/") { "file://" + p } else { p }
  let b = StringBuilder()
  let hex = "0123456789ABCDEF"
  for ch in @utf8.encode(p) {
    let n = ch.to_int()
    if (n >= 65 && n <= 90) || (n >= 97 && n <= 122) || (n >= 48 && n <= 57) || [58, 47, 45, 95, 46, 126].contains(n) {
      b.write_char(ch.to_char())
    } else {
      b.write_char('%')
      b.write_char(hex.code_unit_at(n / 16).to_char().unwrap())
      b.write_char(hex.code_unit_at(n % 16).to_char().unwrap())
    }
  }
  b.to_string()
}

fn sarif(report : Json) -> Json {
  let results : Array[Json] = get_array(report, "findings").map(f => {
    let region = get(f, "range")
    let physical : Map[String, Json] = Map([])
    physical["artifactLocation"] = { "uri": uri(text(f, "source")) }
    if region is Object(_) {
      physical["region"] = { "startLine": get(get(region, "start"), "line"), "startColumn": get(get(region, "start"), "column"),
        "endLine": get(get(region, "end"), "line"), "endColumn": get(get(region, "end"), "column") }
    }
    { "ruleId": text(f, "code"), "level": if text(f, "severity") == "error" || text(f, "severity") == "high" { "error" } else if text(f, "severity") == "info" { "note" } else { "warning" },
      "properties": { "category": get(f, "category"), "assessment": get(f, "assessment"), "original_severity": get(f, "original_severity") },
      "message": { "text": text(f, "message") + " " + text(f, "assessment_note") }, "locations": [{ "physicalLocation": Json::object(physical) }] }
  })
  { "version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{ "tool": { "driver": { "name": "MoonShield", "version": version() } }, "results": results }] }
}
