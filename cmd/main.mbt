fn option(args : Array[String], key : String, fallback~ : String = "") -> String {
  for i = 0; i + 1 < args.length(); i = i + 1 { if args[i] == key { return args[i + 1] } }
  fallback
}
fn options(args : Array[String], key : String) -> Array[String] {
  let result = []
  for i = 0; i + 1 < args.length(); i = i + 1 { if args[i] == key { result.push(args[i + 1]) } }
  result
}
fn absolute(path : String) -> String raise { @path.Path(path).resolve().to_string() }
fn kind(path : String) -> String {
  if path.to_lower().has_suffix(".json") { "json" } else if path.to_lower().has_suffix(".mbtx") { "mbtx" } else { "unsupported" }
}
async fn input(path : String) -> Json {
  let file = absolute(path)
  if @fs.file_size(file) > 1048576L { fail("Input exceeds the 1 MiB limit") }
  @shield.audit(@fs.read_text(file), path=file, kind=kind(file))
}
async fn inspect(path : String, args : Array[String]) -> Json {
  let embedded = input(path)
  let selected_path = option(args, "--policy")
  let selected = if selected_path == "" { embedded } else { input(selected_path) }
  let inherited : Array[Json] = []
  for name in options(args, "--inherit") { inherited.push(input(name)) }
  let report = @shield.combine(embedded, selected, inherited)
  if option(args, "--path-context", fallback="static") == "inspect" { path_context(report) } else { report }
}

fn comparable_path(path : String) -> String {
  let p = path.replace_all(old="\\", new="/")
  // Shipped adapter is Windows-only. Preserve case for paths without Windows roots.
  if (p.length() > 1 && p.code_unit_at(1) == 58) || p.has_prefix("//") { p.to_lower() } else { p }
}

/// Metadata only; candidate data files are never opened/read by this adapter.
async fn path_context(report : Json) -> Json {
  let observations : Array[Json] = []
  for index, f in @shield.get_array(report, "findings") {
    if @shield.text(f, "code") != "FS_LITERAL_SCOPE" || @shield.text(f, "severity") != "warning" { continue }
    let grant = @shield.text(f, "grant_path")
    let base = @path.Path(@shield.text(f, "source")).dirname()
    let path = base.join(@path.Path(grant)).resolve().to_string()
    let status = try {
      match @fs.kind(path, follow_symlink=false) {
        Regular => if comparable_path(@fs.realpath(path)) == comparable_path(path) { "REGULAR_EXACT_MATCH" } else { "CANONICAL_MISMATCH" }
        Directory => "DIRECTORY"
        SymLink => "SYMLINK"
        _ => "OTHER_KIND"
      }
    } catch { _ => "UNAVAILABLE" }
    observations.push({ "finding_index": index, "source": @shield.text(f, "source"), "grant_path": grant,
      "resolved_path": path, "status": status, "content_read": false })
  }
  @shield.with_path_context(report, observations)
}
async fn collect(dir : String, root : String, found : Array[String], skipped : Array[String], visited : Map[String, Bool], depth : Int) -> Unit {
  if depth > 32 || found.length() > 1000 { fail("Scan limit reached; no complete result") }
  let real = @fs.realpath(dir).replace_all(old="\\", new="/").to_lower()
  if real != root && !real.has_prefix(root + "/") { skipped.push(dir); return }
  if visited.contains(real) { skipped.push(dir); return }
  visited[real] = true
  for name in @fs.readdir(dir, include_hidden=true, sort=true) {
    if [".git", "vendor", "work", "_build", "node_modules"].contains(name.to_lower()) { continue }
    let path = dir + "/" + name
    match @fs.kind(path, follow_symlink=false) {
      Regular => if name.to_lower().has_suffix(".mbtx") {
        if found.length() >= 1000 { fail("Scan limit reached; no complete result") }
        let canonical = @fs.realpath(path).replace_all(old="\\", new="/").to_lower()
        if canonical.has_prefix(root + "/") { found.push(path) } else { skipped.push(path) }
      }
      Directory => collect(path, root, found, skipped, visited, depth + 1)
      _ => skipped.push(path)
    }
  }
}

async fn output(result : Json, args : Array[String]) -> Unit {
  let format = option(args, "--format", fallback="json")
  let rendered = @shield.render(result, format, lang=option(args, "--lang", fallback="zh"))
  let out = option(args, "--out")
  if out == "" { println(rendered) } else {
    let file = absolute(out)
    let parent = @path.Path(file).dirname().to_string()
    @fs.mkdir(parent, recursive=true, allow_existing=true)
    @fs.write_text(file, rendered + "\n")
    println("Report: " + file)
  }
}

fn help() -> Unit {
  println("MoonShield " + @shield.version() + " — MoonBit Script Permission Policy Auditor & Runtime Conformance Tester")
  println("\n  moonshield audit FILE [--policy FILE] [--inherit FILE] [--format json|text|md|sarif] [--lang zh|en] [--out FILE] [--fail-on warning|high|error]")
  println("  moonshield scan DIRECTORY [same report options; scans .mbtx, skips links/out-of-root targets]")
  println("  Optional: --path-context static|inspect (default static; inspect reads file metadata only)")
  println("  moonshield verify [--repeat N>=3] [--out DIRECTORY]")
  println("  moonshield doctor\n  moonshield --version\n\nAudit reads configuration only. It never compiles or runs the candidate script.\nverify executes only bundled synthetic probes through the pinned MoonBit/Moonrun toolchain.\nSupported policy formats: .mbtx, strict JSON. TOML and legacy YAML are explicitly unsupported.\nExit: 0=no findings / checks pass, 1=review or NO-GO, 2=usage/infrastructure error.")
}

async fn run() -> Int {
  let all = @env.args()
  let args = all[1:].to_owned()
  if args.is_empty() || ["help", "--help", "-h"].contains(args[0]) { help(); return 0 }
  if args[0] == "--version" { println("MoonShield " + @shield.version()); return 0 }
  if args[0] == "doctor" { return doctor() }
  if args[0] == "verify" {
    validate_options(args, ["--repeat", "--out"])
    return verify(args)
  }
  if !["audit", "scan"].contains(args[0]) || args.length() < 2 || args[1].has_prefix("--") {
    help(); return 2
  }
  validate_options(args[1:].to_owned(), ["--policy", "--inherit", "--format", "--lang", "--out", "--fail-on", "--path-context"])
  let format = option(args, "--format", fallback="json")
  let lang = option(args, "--lang", fallback="zh")
  let threshold = option(args, "--fail-on", fallback="warning")
  if !["json", "text", "md", "sarif"].contains(format) || !["warning", "high", "error"].contains(threshold) || !["zh", "en"].contains(lang) { fail("Invalid format, lang or fail-on value") }
  if !["static", "inspect"].contains(option(args, "--path-context", fallback="static")) { fail("Invalid path-context value") }
  if args[0] == "audit" {
    let result = inspect(args[1], args)
    output(result, args)
    return @shield.exit_code(result, fail_on=threshold)
  }
  let dir = absolute(args[1])
  let real = @fs.realpath(dir).replace_all(old="\\", new="/").to_lower()
  let found = []
  let skipped = []
  collect(dir, real, found, skipped, Map([]), 0)
  let reports = []
  let findings = []
  let mut code = 0
  for path in found {
    let report = inspect(path, args)
    reports.push(report)
    for f in @shield.get_array(report, "findings") { findings.push(f) }
    code = Int::max(code, @shield.exit_code(report, fail_on=threshold))
  }
  if !skipped.is_empty() || found.is_empty() {
    code = 1
    findings.push({ "code": "SCAN_INCOMPLETE", "severity": "warning", "category": "risk", "message": "Some paths were skipped or no .mbtx inputs were found", "source": dir, "range": Json::null() })
  }
  let result = @shield.refresh({ "version": @shield.version(), "schema_version": 2,
    "reports": reports, "findings": findings, "files": found.length(), "skipped": skipped,
    "default_exclusions": [".git", "vendor", "work", "_build", "node_modules"], "source_executed": false })
  output(result, args)
  code
}

fn validate_options(args : Array[String], supported : Array[String]) -> Unit raise {
  let seen : Map[String, Bool] = Map([])
  let mut i = 1
  while i < args.length() {
    let key = args[i]
    if !supported.contains(key) || i + 1 >= args.length() { fail("Unknown or incomplete option: " + key) }
    if key != "--inherit" && seen.contains(key) { fail("Repeated option: " + key) }
    seen[key] = true
    i += 2
  }
}

async fn main {
  let code = try run() catch {
    err => {
      let detail = err.to_string()
      println(({ "status": "ERROR", "message": if detail.contains("Malformed") { "Input must be valid UTF-8; content omitted" } else { detail }, "version": @shield.version() } : Json).stringify())
      2
    }
  }
  @env.exit(code)
}
