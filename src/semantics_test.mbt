test "empty policy does not execute abort body" {
  let r = @src.audit("---\npermission()\n---\nfn main { abort(\"body\") }", path="x.mbtx")
  assert_eq(@src.text(r, "policy_state"), "EMPTY")
  assert_eq(@src.text(r, "status"), "NO_FINDINGS")
}
test "runtime unicode escape decodes wildcard and keys" {
  let r = @src.audit("---\npermission(fs:{\"\\u0072ead\":[\"\\u002a\"]})\n---", path="x.mbtx")
  assert_true(@src.get_array(r, "findings").any(f => @src.text(f, "code") == "FS_BROAD_SCOPE"))
}
test "MoonBit braced unicode is not runtime configuration unicode" {
  let r = @src.audit("---\npermission(env:{\"from_host\":[\"\\u{002a}\"]})\n---", path="x.mbtx")
  assert_eq(@src.text(r, "status"), "INVALID")
}
test "decoded duplicate keys are retained" {
  let r = @src.audit("---\npermission(fs:{\"read\":[],\"\\u0072ead\":[]})\n---", path="x.mbtx")
  assert_true(@src.get_array(r, "findings").any(f => @src.text(f, "code") == "DUPLICATE_KEY"))
}
test "false spawn and scoped allow are not mutually exclusive" {
  let r = @src.audit("---\npermission(process:{\"spawn\":false,\"allow\":[]})\n---", path="x.mbtx")
  assert_eq(@src.text(r, "status"), "NO_FINDINGS")
}
test "JSON duplicate keys fail closed" {
  assert_eq(@src.text(@src.audit("{\"fs\":{},\"fs\":{}}", path="x.json", kind="json"), "status"), "INVALID")
}
test "JSON policy and selected override" {
  let a = @src.audit("---\npermission(process:{\"spawn\":true})\n---", path="x.mbtx")
  let b = @src.audit("{}", path="empty.json", kind="json")
  let r = @src.combine(a, b, [])
  assert_eq(@src.text(r, "status"), "NO_FINDINGS")
}
test "redaction and SARIF" {
  let a = @src.audit("---\npermission(env:{\"set\":{\"DEMO\":\"DO_NOT_ECHO\"}})\n---", path="x.mbtx")
  assert_false(a.stringify().contains("DO_NOT_ECHO"))
  assert_true(@src.render(@src.combine(a, a, []), "sarif").contains("2.1.0"))
}
test "mixed fence lengths and BOM shebang" {
  assert_eq(@src.text(@src.audit("\u{feff}#!/usr/bin/env moonx\r\n ---\r\npermission()\r\n----\r\n", path="x"), "status"), "NO_FINDINGS")
}
