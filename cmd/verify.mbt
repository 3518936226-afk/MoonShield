async fn doctor() -> Int {
  let tc = @env.get_env_var("MOONSHIELD_TOOLCHAIN").unwrap_or("")
  if tc == "" { fail("Use the launcher or set MOONSHIELD_TOOLCHAIN to the pinned toolchain") }
  let p = @process.run(tc + "/bin/moon.exe", ["version", "--all"], stdout=Collect, stderr=Collect, no_console_window=true)
  println(({ "version": @shield.version(), "status": if p.exit_code == 0 { "READY" } else { "ERROR" },
    "toolchain": tc, "toolchain_versions": p.stdout_text(), "host": "Windows x64 (validated configuration)",
    "mode": "MoonBit Wasm CLI; runtime probes always use Moonrun", "python_required": false,
    "safety_scope": "Static audit is not a proof of safety; arbitrary script execution is not offered" } : Json).stringify(indent=2))
  if p.exit_code == 0 { 0 } else { 2 }
}

async fn wasm_in(dir : String) -> String {
  let found : Array[String] = []
  @fs.walk(dir, fn(path, names) {
    for name in names { if name.has_suffix(".wasm") { found.push(path + "/" + name) } }
  }, max_concurrency=1)
  if found.length() != 1 { fail("Missing or ambiguous trusted probe artifact") }
  found[0]
}

async fn invoke(program : String, argv : Array[String], cwd : String, log : String, guest~ : Bool = false) -> Json {
  let extra : Map[String, String] = Map([])
  if guest {
    extra["MOONSHIELD_PROBE"] = "SYNTHETIC_HOST"
    if @env.get_env_var("SystemRoot") is Some(root) { extra["SystemRoot"] = root }
    // Windows process helpers require a writable temp location even with an empty guest policy.
    // Never fall back to an ambient C-drive temporary directory.
    extra["TEMP"] = cwd
    extra["TMP"] = cwd
    extra["TMPDIR"] = cwd
  }
  let p = @process.run(program, argv, cwd~, extra_env=extra, inherit_env=!guest,
    stdout=Collect, stderr=Collect, no_console_window=true)
  let stdout = p.stdout_binary()
  let stderr = p.stderr_binary()
  @fs.write_binary(log + ".stdout.bin", stdout)
  @fs.write_binary(log + ".stderr.bin", stderr)
  let row : Json = { "program": program, "argv": argv, "cwd": cwd, "exit_code": p.exit_code,
    "stdout": @utf8.decode_lossy(stdout), "stderr": @utf8.decode_lossy(stderr),
    "environment": if guest { "Minimal synthetic environment; no ambient host secrets inherited" } else { "Trusted compiler uses the configured host toolchain environment" } }
  @fs.write_text(log + ".json", row.stringify(indent=2))
  row
}

async fn verify(args : Array[String]) -> Int {
  let repeats = try Some(@string.parse_int(option(args, "--repeat", fallback="3"))) catch { _ => None }
  guard repeats is Some(repeat) && repeat >= 3 && repeat <= 10 else { fail("repeat must be between 3 and 10") }
  let tc = @env.get_env_var("MOONSHIELD_TOOLCHAIN").unwrap_or("")
  let root = @env.get_env_var("MOONSHIELD_ROOT").unwrap_or("")
  if tc == "" || root == "" { fail("verify requires the validated launcher environment") }
  let stamp = @env.now().to_string()
  let work = root + "/work/verify-" + stamp
  let base = option(args, "--out", fallback=root + "/evidence")
  let logs = absolute(base) + "/verify-" + stamp
  @fs.mkdir(work, recursive=true, allow_existing=false)
  @fs.mkdir(logs, recursive=true, allow_existing=false)
  // Do not let an enclosing repository/workspace supply guest build configuration.
  @fs.write_text(work + "/moon.mod", "name = \"moonshield-probes\"\nversion = \"0.0.0\"\n")
  @fs.write_text(work + "/moon.work", "members = [\".\"]\n")
  @fs.write_text(logs + "/trusted-moon.mod", "name = \"moonshield-probes\"\nversion = \"0.0.0\"\n")
  @fs.write_text(logs + "/trusted-moon.work", "members = [\".\"]\n")
  @fs.write_text(work + "/allowed.txt", "ALLOWED_SYNTHETIC")
  let runner = tc.replace_all(old="\\", new="/") + "/bin/moonrun.exe"
  let compiler = tc.replace_all(old="\\", new="/") + "/bin/moon.exe"
  let bodies : Array[(String, String, String)] = [
    ("file", "\"moonbitlang/core/async/fs\"", "async fn main { println(@fs.read_text(\"allowed.txt\")) }"),
    ("env", "\"moonbitlang/core/env\"", "fn main { println(@env.get_env_var(\"MOONSHIELD_PROBE\")) }"),
    ("write", "\"moonbitlang/core/async/fs\"", "async fn main { @fs.write_text(\"created.txt\", \"SYNTHETIC_WRITE\"); println(\"WRITTEN\") }"),
    ("process", "\"moonbitlang/core/async/process\"", "async fn main { let r = @process.run(" + Json::string(runner).stringify() + ", [\"--version\"], stdout=Collect, stderr=Collect, no_console_window=true); println(\"CHILD_EXIT=\\{r.exit_code}\"); println(r.stdout_text()) }"),
    ("noop", "", "fn main { println(\"TRUSTED_NOOP\") }"),
  ]
  let artifacts : Map[String, String] = Map([])
  let records : Array[Json] = []
  for (name, imports, body) in bodies {
    let source = "---\n" + (if imports == "" { "" } else { "import { " + imports + " }\n" }) + "---\n" + body + "\n"
    let path = work + "/" + name + ".mbtx"
    @fs.write_text(path, source)
    @fs.write_text(logs + "/probe-" + name + ".mbtx", source)
    let target = work + "/build-" + name
    let row = invoke(compiler, ["build", "--target", "wasm", "--frozen", "--target-dir", target, path], work, logs + "/compile-" + name)
    records.push(row)
    if @shield.get(row, "exit_code") != 0 { fail("Trusted probe compilation failed; evidence: " + logs) }
    artifacts[name] = wasm_in(target)
  }
  let process_policy : Json = { "env": { "from_host": ["SystemRoot"] }, "process": { "allow": [{ "program": runner, "args_prefix": ["--version"] }] } }
  let cases : Array[(String, String, String, String, String)] = [
    ("file-deny", "file", ".json", "{}", "deny:file read"),
    ("file-allow", "file", ".json", "{\"fs\":{\"read\":[\"allowed.txt\"]}}", "ALLOWED_SYNTHETIC"),
    ("env-deny", "env", ".json", "{}", "None"),
    ("env-allow", "env", ".json", "{\"env\":{\"from_host\":[\"MOONSHIELD_PROBE\"]}}", "Some(SYNTHETIC_HOST)"),
    ("process-deny", "process", ".json", "{}", "deny:process spawn"),
    ("process-allow", "process", ".json", process_policy.stringify(), "CHILD_EXIT=0"),
    ("write-deny", "write", ".json", "{}", "deny:file write"),
    ("write-allow", "write", ".json", "{\"fs\":{\"write\":[\".\"]}}", "WRITTEN"),
    ("escape-wildcard", "file", ".mbtx", "---\npermission(fs:{\"read\":[\"\\u002a\"]})\n---\nfn main { abort(\"POLICY_BODY_MUST_NOT_RUN\") }", "ALLOWED_SYNTHETIC"),
    ("escape-key", "env", ".mbtx", "---\npermission(env:{\"\\u0066rom_host\":[\"MOONSHIELD_PROBE\"]})\n---\nfn main {}", "Some(SYNTHETIC_HOST)"),
    ("invalid-braces", "noop", ".mbtx", "---\npermission(env:{\"from_host\":[\"\\u{002a}\"]})\n---", "invalid"),
    ("invalid-surrogate", "noop", ".mbtx", "---\npermission(env:{\"set\":{\"X\":\"\\ud83d\\ude00\"}})\n---", "invalid"),
    ("json-surrogate", "env", ".json", "{\"env\":{\"set\":{\"MOONSHIELD_PROBE\":\"\\ud83d\\ude00\"}}}", "Some(\u{1f600})"),
  ]
  let checks : Array[Json] = []
  for (name, probe, suffix, policy, expectation) in cases {
    let path = work + "/policy-" + name + suffix
    @fs.write_text(path, policy)
    @fs.write_text(logs + "/policy-" + name + suffix, policy)
    let analysis = @shield.audit(policy, path~, kind=if suffix == ".json" { "json" } else { "mbtx" })
    for n = 1; n <= repeat; n = n + 1 {
      let row = invoke(runner, ["--policy", path, artifacts[probe]], work, logs + "/" + name + "-" + n.to_string(), guest=true)
      let stdout = @shield.text(row, "stdout").trim().to_owned()
      let stderr = @shield.text(row, "stderr")
      let code = @shield.get(row, "exit_code")
      let mut passed = if expectation.has_prefix("deny:") {
        code == 1 && stderr.contains("Sandbox policy blocked " + expectation[5:].to_owned())
      } else if expectation == "invalid" {
        code != 0 && !stderr.contains("Sandbox policy blocked") && (stderr.contains("policy") || stderr.contains("front matter")) && @shield.text(analysis, "status") == "INVALID"
      } else if expectation == "CHILD_EXIT=0" {
        code == 0 && stdout.has_prefix("CHILD_EXIT=0\nmoonrun ")
      } else { code == 0 && stdout == expectation }
      if expectation != "invalid" { passed = passed && !["INVALID", "UNSUPPORTED"].contains(@shield.text(analysis, "status")) }
      if name == "write-deny" { passed = passed && !@fs.exists(work + "/created.txt") }
      if name == "write-allow" { passed = passed && @fs.read_text(work + "/created.txt") == "SYNTHETIC_WRITE" }
      let check : Json = { "case": name, "repetition": n, "passed": passed, "expected": expectation,
        "runtime": row, "static_status": @shield.get(analysis, "status"), "static_findings": @shield.get(analysis, "findings") }
      checks.push(check)
    }
  }
  let passed = checks.filter(x => @shield.get(x, "passed") == Json::boolean(true)).length()
  let go = passed == cases.length() * repeat && checks.length() == cases.length() * repeat
  let result : Json = { "version": @shield.version(), "verdict": if go { "GO" } else { "NO-GO" }, "tests": checks.length(), "passed": passed,
    "backend": "Real Moonrun Wasm only", "candidate_execution": "Bundled synthetic probes only", "records": records, "checks": checks, "evidence": logs }
  @fs.write_text(logs + "/results.json", result.stringify(indent=2))
  println(({ "verdict": if go { "GO" } else { "NO-GO" }, "tests": checks.length(), "passed": passed, "evidence": logs } : Json).stringify(indent=2))
  if go { 0 } else { 1 }
}
