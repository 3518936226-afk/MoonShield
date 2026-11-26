///| Official AST integration. Candidate code is data; never compiled or run.
fn position(p : @basic.Position) -> Json {
  { "line": p.lnum, "column": p.column(), "offset": p.cnum }
}

fn finding(code : String, severity : String, message : String, loc : @basic.Location) -> Json {
  { "code": code, "severity": severity, "message": message,
    "range": { "start": position(loc.start), "end": position(loc.end) } }
}

fn emit(out : Array[Json], code : String, severity : String, message : String, loc : @basic.Location) -> Unit {
  out.push(finding(code, severity, message, loc))
}

fn duplicates(fields : Array[@config.Field], out : Array[Json]) -> Unit {
  let seen : Map[String, Bool] = Map([])
  for f in fields {
    if seen.contains(f.key) { emit(out, "DUPLICATE_KEY", "error", "Duplicate decoded policy key", f.key_loc) }
    seen[f.key] = true
    match f.value {
      Map(fields~, ..) => duplicates(fields, out)
      Array(items~, ..) => for item in items { if item is Map(fields~, ..) { duplicates(fields, out) } }
      _ => ()
    }
  }
}

fn string_array(e : @config.Expr, out : Array[Json]) -> Array[String] {
  match e {
    Array(items~, ..) => {
      let result = []
      for item in items {
        if item is String(str~, ..) { result.push(str) }
        else { emit(out, "INVALID_TYPE", "error", "Expected a string array element", item.loc()) }
      }
      result
    }
    _ => { emit(out, "INVALID_TYPE", "error", "Expected an array", e.loc()); [] }
  }
}

fn broad_path(path : String) -> Bool {
  path == "" || path == "*" || path == "." || path == "./" || path == ".\\" || path == ".." || path == "/" || path == "\\" ||
  path.contains("../") || path.contains("..\\") || path.has_suffix(":/") || path.has_suffix(":\\")
}

fn emit_fs(out : Array[Json], code : String, severity : String, message : String, loc : @basic.Location, operation : String, path : String) -> Unit {
  let o = clone_object(finding(code, severity, message, loc))
  o["operation"] = Json::string(operation)
  o["grant_path"] = Json::string(path)
  out.push(Json::object(o))
}

fn fs_rules(fields : Array[@config.Field], out : Array[Json]) -> Unit {
  for f in fields {
    if f.key != "read" && f.key != "write" {
      emit(out, "UNKNOWN_FIELD", "error", "Unknown filesystem field", f.key_loc)
      continue
    }
    guard f.value is Array(items~, ..) else {
      emit(out, "INVALID_TYPE", "error", "Filesystem access must be an array", f.value.loc()); continue
    }
    for item in items {
      match item {
        String(str~, loc~) => {
          if broad_path(str) { emit_fs(out, "FS_BROAD_SCOPE", "high", "Broad or parent filesystem scope", loc, f.key, str) }
          else if str.contains(":") || str.has_prefix("/") || str.has_prefix("\\") {
            emit_fs(out, "FS_ABSOLUTE_SCOPE", "warning", "Absolute host path requires manual review", loc, f.key, str)
          } else {
            emit_fs(out, "FS_LITERAL_SCOPE", "warning", "Literal path may grant a directory subtree; filesystem scope is not resolved statically", loc, f.key, str)
          }
        }
        Map(fields=glob_fields, loc~) => {
          if glob_fields.length() != 1 || glob_fields[0].key != "glob" {
            emit(out, "INVALID_FS_RULE", "error", "Path rule object must contain exactly one glob string", loc)
          } else if glob_fields[0].value is String(str~, loc~) {
            if broad_path(str) || str.contains("*") || str.contains("?") || str.contains("[") || str.contains("{") {
              emit_fs(out, "FS_GLOB_SCOPE", "warning", "Pattern grants require manual scope review", loc, f.key, str)
            } else {
              emit_fs(out, "FS_GLOB_SCOPE", "warning", "Glob target and exclusions require filesystem scope review", loc, f.key, str)
            }
          } else { emit(out, "INVALID_TYPE", "error", "glob must be a string", loc) }
        }
        _ => emit(out, "INVALID_TYPE", "error", "Expected a path string or glob object", item.loc())
      }
    }
  }
}

fn env_rules(fields : Array[@config.Field], out : Array[Json]) -> Unit {
  for f in fields {
    match f.key {
      "from_host" | "required_from_host" => {
        let names = string_array(f.value, out)
        for name in names {
          if name == "*" { emit(out, "ENV_HOST_ALL", "high", "All host environment variables are requested", f.value.loc()) }
          if name.to_upper() == "PATH" { emit(out, "ENV_PATH", "warning", "Host PATH can influence executable lookup", f.value.loc()) }
        }
      }
      "set" => {
        if f.value is Map(fields=values, ..) {
          for v in values {
            if v.value is String(_) { emit(out, "ENV_LITERAL", "warning", "Literal environment value present; value omitted from report", v.value.loc()) }
            else { emit(out, "INVALID_TYPE", "error", "Environment literal must be a string", v.value.loc()) }
          }
        } else { emit(out, "INVALID_TYPE", "error", "env.set must be an object", f.value.loc()) }
      }
      _ => emit(out, "UNKNOWN_FIELD", "error", "Unknown environment field", f.key_loc)
    }
  }
}

fn process_rules(fields : Array[@config.Field], out : Array[Json]) -> Unit {
  let mut spawn_present = false
  let mut allow_present = false
  let mut virtualize = false
  let mut ipc = false
  for f in fields {
    match f.key {
      "spawn" => {
        if f.value is Bool(value~, loc~) {
          spawn_present = value
          if value { emit(out, "PROCESS_ALLOW_ALL", "high", "Unrestricted host process creation", loc) }
        } else { emit(out, "INVALID_TYPE", "error", "process.spawn must be boolean", f.value.loc()) }
      }
      "allow" => {
        guard f.value is Array(items~, ..) else {
          emit(out, "INVALID_TYPE", "error", "process.allow must be an array", f.value.loc()); continue
        }
        allow_present = !items.is_empty()
        for item in items {
          guard item is Map(fields=entry, ..) else {
            emit(out, "INVALID_TYPE", "error", "Process rule must be an object", item.loc()); continue
          }
          let mut program = None
          let mut has_prefix = false
          for rule in entry {
            match rule.key {
              "program" => {
                if rule.value is String(str~, ..) { program = Some(str) }
                else { emit(out, "INVALID_TYPE", "error", "Program must be a string", rule.value.loc()) }
              }
              "args_prefix" => {
                let args = string_array(rule.value, out)
                has_prefix = !args.is_empty()
              }
              _ => emit(out, "UNKNOWN_FIELD", "error", "Unknown process rule field", rule.key_loc)
            }
          }
          match program {
            None | Some("") => emit(out, "INVALID_PROGRAM", "error", "A nonempty program is required", item.loc())
            Some(program) => {
              emit(out, "PROCESS_HOST_CAPABILITY", "warning", "Allowed native children retain host account capabilities", item.loc())
              if !has_prefix { emit(out, "PROCESS_UNBOUNDED_ARGS", "high", "Program allowed without a nonempty argument prefix", item.loc()) }
              let base = program.replace_all(old="\\", new="/").split("/").last().unwrap_or("").to_owned().to_lower()
              if ["cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe", "sh", "bash", "python", "python.exe", "node", "node.exe"].contains(base) {
                emit(out, "PROCESS_INTERPRETER", "high", "Shell or interpreter can execute arbitrary instructions", item.loc())
              }
              if !program.contains("/") && !program.contains("\\") {
                emit(out, "PROCESS_LOOKUP", "warning", "Bare program name depends on host executable lookup", item.loc())
              }
            }
          }
        }
      }
      "virtualize" | "ipc" => {
        if f.value is Bool(value~, loc~) {
          if f.key == "virtualize" { virtualize = value } else { ipc = value }
          if value { emit(out, "PROCESS_EXECUTION_MODE", "warning", "Execution-mode feature requires runtime-specific review", loc) }
        } else { emit(out, "INVALID_TYPE", "error", "Execution-mode switch must be boolean", f.value.loc()) }
      }
      _ => emit(out, "UNKNOWN_FIELD", "error", "Unknown process field", f.key_loc)
    }
  }
  if spawn_present && allow_present {
    emit(out, "PROCESS_CONFLICT", "error", "process.spawn and process.allow cannot coexist", fields[0].key_loc)
  }
  if virtualize && ipc { emit(out, "PROCESS_MODE_CONFLICT", "error", "IPC and virtualization cannot be combined", fields[0].key_loc) }
}

fn analyze_header(text : String, json_mode~ : Bool = false) -> Json {
  let parsed = @config.parse_moon_pkg(text, validate=false)
  let findings = []
  for d in parsed.diagnostics.errors { emit(findings, "CONFIG_SYNTAX", "error", "Official configuration parser rejected syntax", d.loc) }
  for d in parsed.diagnostics.warnings { emit(findings, "CONFIG_WARNING", "warning", "Official configuration parser emitted a warning", d.loc) }
  let mut policy : Json = Json::null()
  let mut count = 0
  let mut empty = false
  for stmt in parsed.ast.0 {
    let stmt = match stmt {
      Expr(e) => @config.Statement::Expr(normalize_expr(e, findings, json_mode))
      Assign(f) => @config.Statement::Assign(normalize_fields([f], findings, json_mode)[0])
      _ => stmt
    }
    match stmt {
      Expr(Apply(name="permission", args~, loc~, ..)) => {
        count += 1
        empty = args.is_empty()
        duplicates(args, findings)
        policy = value_json(@config.Expr::Map(fields=args, loc~), false)
        for domain in args {
          guard domain.value is Map(fields~, ..) else {
            emit(findings, "INVALID_TYPE", "error", "Permission domain must be an object", domain.value.loc()); continue
          }
          let start = findings.length()
          match domain.key {
            "fs" => fs_rules(fields, findings)
            "env" => env_rules(fields, findings)
            "process" => process_rules(fields, findings)
            "net" => net_rules(fields, findings)
            _ => emit(findings, "UNKNOWN_FIELD", "error", "Unknown permission domain", domain.key_loc)
          }
          for i = start; i < findings.length(); i = i + 1 {
            let o = clone_object(findings[i])
            o["domain"] = Json::string(domain.key)
            findings[i] = Json::object(o)
          }
        }
        if count > 1 { emit(findings, "DUPLICATE_PERMISSION", "error", "Multiple permission declarations are ambiguous", loc) }
      }
      Import(_) => ()
      _ => {
        // A statement outside imports/permission cannot be silently treated as empty policy.
        let loc = match stmt { Assign(f) => f.key_loc; Expr(e) => e.loc(); Import(loc~, ..) => loc }
        emit(findings, "UNSUPPORTED_DECLARATION", "warning", "Header declaration outside the supported audit subset", loc)
      }
    }
  }
  if count == 0 { findings.push({ "code": "NO_PERMISSION", "severity": "high", "message": "No explicit policy: runtime may keep ambient host access", "range": Json::null() }) }
  let state = if !parsed.diagnostics.errors.is_empty() { "INVALID" }
    else if count == 0 { "ABSENT" } else if count > 1 { "INVALID" }
    else if empty { "EMPTY" } else { "PRESENT" }
  { "schema_version": 1, "parser": "moonbitlang/moon_config@0.4.6",
    "policy_state": state, "findings": findings, "permission_count": count, "policy": policy }
}

fn net_rules(fields : Array[@config.Field], out : Array[Json]) -> Unit {
  for f in fields {
    if !["dns", "connect", "bind"].contains(f.key) {
      emit(out, "UNKNOWN_FIELD", "error", "Unknown network field", f.key_loc)
      continue
    }
    let entries = string_array(f.value, out)
    for value in entries {
      emit(out, if value.contains("*") { "NETWORK_WILDCARD" } else { "NETWORK_ACCESS" },
        if value.contains("*") { "high" } else { "warning" },
        "Network access grant; endpoint validity and actual resolved addresses require runtime validation", f.value.loc())
    }
  }
}

