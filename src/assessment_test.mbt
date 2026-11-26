fn policy(value : String, path : String) -> Json {
  @src.audit(value, path~, kind="json")
}

test "classification separates risk invalid unsupported and missing" {
  for (input, kind, status) in [
    ("{", "json", "INVALID"), ("[]", "json", "INVALID"),
    ("{\"fs\":null}", "json", "UNSUPPORTED"), ("x", "toml", "UNSUPPORTED"),
    ("fn main {}", "mbtx", "REVIEW_REQUIRED"),
    ("---\npermission()", "mbtx", "INVALID"),
    ("// policy:\n// fs: []\nfn main {}", "mbtx", "UNSUPPORTED"),
  ] {
    let a = @src.audit(input, path="x", kind~)
    let r = @src.combine(a, a, [])
    assert_eq(@src.text(r, "status"), status)
    assert_eq(@src.exit_code(r, fail_on="error"), if status == "REVIEW_REQUIRED" { 0 } else { 1 })
  }
}

test "selected deny removes broad ancestor actionable risk without losing original" {
  let a = policy("{}", "a.json")
  let b = policy("{\"fs\":{\"read\":[\"*\"]},\"net\":{\"connect\":[\"*:*\"]},\"process\":{\"spawn\":true}}", "b.json")
  let before = b.stringify()
  let r = @src.combine(a, a, [b])
  assert_eq(@src.text(r, "status"), "NO_FINDINGS")
  assert_eq(@src.exit_code(r), 0)
  assert_true(@src.get_array(r, "findings").all(f => @src.text(f, "assessment") == "direct_operation_denied_by_policy"))
  assert_true(@src.get_array(r, "configuration_findings").all(f => @src.text(f, "severity") == "high"))
  assert_eq(before, b.stringify())
}

test "explicit inherited deny is conditional and original groups remain" {
  let a = policy("{\"fs\":{\"read\":[\"*\"]}}", "a.json")
  let b = policy("{}", "b.json")
  let r = @src.combine(a, a, [b])
  assert_eq(@src.text(r, "status"), "NO_FINDINGS")
  let f = @src.get_array(r, "findings")[0]
  assert_eq(@src.text(f, "proof_basis"), "declared_inherited_ceiling")
  assert_eq(@src.text(f, "blocking_source"), "b.json")
  assert_eq(@src.get_array(r, "inherited"), [b])
}

test "read deny cannot suppress write or native child capability" {
  let a = policy("{\"fs\":{\"read\":[\"*\"],\"write\":[\"*\"]},\"process\":{\"spawn\":true}}", "a.json")
  let b = policy("{\"fs\":{\"write\":[\"*\"]},\"process\":{\"spawn\":true}}", "b.json")
  let r = @src.combine(a, a, [b])
  assert_eq(@src.text(r, "status"), "REVIEW_REQUIRED")
  let fs = @src.get_array(r, "findings").filter(f => @src.text(f, "domain") == "fs" && @src.text(f, "role") == "selected")
  assert_eq(@src.text(fs[0], "severity"), "info")
  assert_eq(@src.text(fs[1], "severity"), "high")
  assert_true(@src.get_array(r, "findings").any(f => @src.text(f, "domain") == "process" && @src.text(f, "severity") == "high"))
}

test "nonempty disjoint globs are never guessed to deny" {
  let a = policy("{\"fs\":{\"read\":[{\"glob\":\"a/**\"}]}}", "a.json")
  let b = policy("{\"fs\":{\"read\":[{\"glob\":\"b/**\"}]}}", "b.json")
  let r = @src.combine(a, a, [b])
  assert_eq(@src.text(r, "status"), "REVIEW_REQUIRED")
  assert_true(@src.get_array(r, "findings").all(f => @src.text(f, "severity") == "warning"))
}

test "empty dns alone cannot suppress network risks" {
  let a = policy("{\"net\":{\"connect\":[\"example.invalid:443\"]}}", "a.json")
  let r = @src.combine(a, a, [])
  assert_eq(@src.text(r, "status"), "REVIEW_REQUIRED")
}

test "configuration error and unsupported are never downgraded" {
  let deny = policy("{}", "deny.json")
  for bad in [policy("{\"fs\":{\"read\":true}}", "a.json"), policy("{\"fs\":null}", "b.json")] {
    let r = @src.combine(bad, bad, [deny])
    assert_true(["INVALID", "UNSUPPORTED"].contains(@src.text(r, "status")))
    assert_eq(@src.exit_code(r, fail_on="error"), 1)
    assert_false(@src.get_array(r, "findings").any(f => @src.text(f, "severity") == "info"))
  }
}

test "invalid ancestor cannot prove deny of selected wildcard" {
  let a = policy("{\"fs\":{\"read\":[\"*\"]}}", "a.json")
  let b = policy("{\"fs\":{\"read\":false}}", "b.json")
  let r = @src.combine(a, a, [b])
  assert_true(@src.get_array(r, "findings").any(f => @src.text(f, "severity") == "high"))
  assert_eq(@src.text(r, "status"), "INVALID")
}

test "ancestor environment is context while selected remains actionable" {
  let a = policy("{\"env\":{\"from_host\":[\"*\"]}}", "a.json")
  let b = policy("{\"env\":{\"from_host\":[\"*\"]}}", "b.json")
  let r = @src.combine(a, a, [b])
  let f = @src.get_array(r, "findings")
  assert_eq(@src.text(f[0], "severity"), "high")
  assert_eq(@src.text(f[1], "severity"), "info")
  assert_eq(@src.text(r, "status"), "REVIEW_REQUIRED")
}

test "path context only exact regular files can downgrade" {
  let a = policy("{\"fs\":{\"read\":[\"data.csv\"]}}", "a.json")
  let r = @src.combine(a, a, [])
  let before = r.stringify()
  for status in ["REGULAR_EXACT_MATCH", "DIRECTORY", "SYMLINK", "CANONICAL_MISMATCH", "UNAVAILABLE"] {
    let out = @src.with_path_context(r, [{ "finding_index": 0, "source": "a.json", "grant_path": "data.csv", "status": status }])
    assert_eq(@src.text(out, "status"), if status == "REGULAR_EXACT_MATCH" { "NO_FINDINGS" } else { "REVIEW_REQUIRED" })
    assert_eq(@src.text(@src.get_array(out, "configuration_findings")[0], "severity"), "warning")
  }
  assert_eq(r.stringify(), before)
}

test "unmatched path observations cannot suppress finding" {
  let a = policy("{\"fs\":{\"read\":[\"data.csv\"]}}", "a.json")
  let r = @src.combine(a, a, [])
  let observations : Array[Json] = [
    { "finding_index": 3, "source": "a.json", "grant_path": "data.csv", "status": "REGULAR_EXACT_MATCH" },
    { "finding_index": 0, "source": "wrong.json", "grant_path": "data.csv", "status": "REGULAR_EXACT_MATCH" },
  ]
  for observation in observations {
    assert_eq(@src.text(@src.with_path_context(r, [observation]), "status"), "REVIEW_REQUIRED")
  }
}

test "informational findings produce SARIF notes and human context" {
  let a = policy("{}", "a.json")
  let b = policy("{\"fs\":{\"read\":[\"*\"]}}", "b.json")
  let r = @src.combine(a, a, [b])
  let sarif = @src.render(r, "sarif")
  assert_true(sarif.contains("\"level\": \"note\""))
  assert_true(@src.render(r, "text", lang="zh").contains("提示 1"))
}
