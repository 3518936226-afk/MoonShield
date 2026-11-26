test "policy schema and risk matrix" {
  let cases : Array[(String, String)] = [
    ("permission(fs:{\"read\":[\"*\"]})", "FS_BROAD_SCOPE"),
    ("permission(fs:{\"write\":[\"../\"]})", "FS_BROAD_SCOPE"),
    ("permission(fs:{\"read\":[\"data.txt\"]})", "FS_LITERAL_SCOPE"),
    ("permission(fs:{\"read\":true})", "INVALID_TYPE"),
    ("permission(fs:{\"typo\":[]})", "UNKNOWN_FIELD"),
    ("permission(env:{\"from_host\":[\"*\"]})", "ENV_HOST_ALL"),
    ("permission(env:{\"from_host\":[\"PATH\"]})", "ENV_PATH"),
    ("permission(env:{\"set\":{\"X\":true}})", "INVALID_TYPE"),
    ("permission(process:{\"spawn\":true})", "PROCESS_ALLOW_ALL"),
    ("permission(process:{\"allow\":[{\"program\":\"cmd.exe\"}]})", "PROCESS_INTERPRETER"),
    ("permission(process:{\"allow\":[{\"program\":\"D:\\\\bin\\\\cmd.exe\"}]})", "PROCESS_INTERPRETER"),
    ("permission(process:{\"spawn\":true,\"allow\":[{\"program\":\"x\"}]})", "PROCESS_CONFLICT"),
    ("permission(process:{\"virtualize\":true,\"ipc\":true})", "PROCESS_MODE_CONFLICT"),
    ("permission(net:{\"connect\":[\"*:*\"]})", "NETWORK_WILDCARD"),
    ("permission(net:{\"bind\":true})", "INVALID_TYPE"),
    ("permission(magic:{})", "UNKNOWN_FIELD"),
    ("permission()\npermission()", "DUPLICATE_PERMISSION"),
    ("permission(fs:{\"read\":[],\"\\u0072ead\":[]})", "DUPLICATE_KEY"),
  ]
  for (policy, code) in cases {
    let result = @src.audit("---\n" + policy + "\n---\nfn main {}", path="fixture.mbtx")
    assert_true(@src.get_array(result, "findings").any(f => @src.text(f, "code") == code), msg=code)
  }
}
test "runtime string grammar invalid escapes and surrogate" {
  for raw in ["\\q", "\\x2a", "\\u{002a}", "\\ud800", "\\ud83d\\ude00"] {
    let r = @src.audit("---\npermission(env:{\"from_host\":[\"" + raw + "\"]})\n---", path="x.mbtx")
    assert_eq(@src.text(r, "status"), "INVALID")
  }
}
test "JSON uses JSON surrogate-pair semantics" {
  let r = @src.audit("{\"env\":{\"from_host\":[\"\\ud83d\\ude00\"]}}", path="x.json", kind="json")
  assert_eq(@src.get_array(@src.get(@src.get(r, "policy"), "env"), "from_host"), [Json::string("\u{1f600}")])
}
test "JSON decoded duplicate rejection" {
  let r = @src.audit("{\"fs\":{},\"\\u0066s\":{}}", path="x.json", kind="json")
  assert_eq(@src.text(r, "status"), "INVALID")
}
test "inherited groups are not flattened or widened" {
  let a = @src.audit("---\npermission()\n---", path="a.mbtx")
  let b = @src.audit("{\"process\":{\"spawn\":true}}", path="b.json", kind="json")
  let r = @src.combine(a, a, [b])
  assert_eq(@src.get_array(r, "inherited").length(), 1)
  assert_eq(@src.text(r, "status"), "NO_FINDINGS")
  assert_true(@src.get_array(r, "findings").all(f => @src.text(f, "severity") == "info"))
  assert_true(@src.get_array(r, "configuration_findings").any(f => @src.text(f, "severity") == "high"))
}
test "JSON source range includes leading whitespace" {
  let r = @src.audit(" \n{\"fs\":{\"read\":[\"*\"]}}", path="x.json", kind="json")
  let p = @src.get(@src.get(@src.get_array(r, "findings")[0], "range"), "start")
  assert_eq(@src.get(p, "line"), 2)
  assert_eq(@src.get(p, "column"), 16)
}
test "unicode source positions count codepoints" {
  let r = @src.audit("#!\u{1f600}\n---\npermission(env:{\"set\":{\"X\":\"\u{1f600}\"}},fs:{\"read\":[\"*\"]})\n---", path="u.mbtx")
  let f = @src.get_array(r, "findings").filter(x => @src.text(x, "code") == "FS_BROAD_SCOPE")[0]
  assert_eq(@src.get(@src.get(@src.get(f, "range"), "start"), "line"), 3)
}
test "unsupported formats fail closed and report partial coverage" {
  let r = @src.audit("[fs]\nread=[]", path="x.toml", kind="toml")
  assert_eq(@src.text(r, "status"), "UNSUPPORTED")
  assert_eq(@src.text(r, "coverage"), "INCOMPLETE")
}
test "override does not suppress malformed header syntax" {
  let a = @src.audit("---\npermission(fs: [)\n---", path="x.mbtx")
  let b = @src.audit("{}", path="deny.json", kind="json")
  assert_eq(@src.text(@src.combine(a, b, []), "status"), "INVALID")
}
test "source URI encoding and no shell interpolation" {
  let a = @src.audit("---\npermission(process:{\"spawn\":true})\n---", path="D:/中文 & %/$().mbtx")
  let s = @src.render(@src.combine(a, a, []), "sarif")
  assert_true(s.contains("file:///D:/%E4%B8%AD%E6%96%87%20%26%20%25/"))
}
