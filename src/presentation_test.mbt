test "Chinese human report explains findings without leaking literal values" {
  let a = @src.audit("---\npermission(env:{\"set\":{\"KEY\":\"SYNTHETIC_SECRET_110\"}},fs:{\"read\":[\"*\"]})\n---", path="x.mbtx")
  let report = @src.combine(a, a, [])
  let output = @src.render(report, "text", lang="zh")
  assert_true(output.contains("需要人工复核"))
  assert_true(output.contains("建议："))
  assert_true(output.contains("FS_BROAD_SCOPE"))
  assert_false(output.contains("SYNTHETIC_SECRET_110"))
}
test "English human report has actionable scope" {
  let a = @src.audit("---\npermission(process:{\"spawn\":true})\n---", path="x.mbtx")
  let output = @src.render(@src.combine(a, a, []), "text", lang="en")
  assert_true(output.contains("Status: REVIEW_REQUIRED"))
  assert_true(output.contains("Action:"))
  assert_true(output.contains("not a proof of safety"))
}
test "missing source ranges never become null null" {
  let a = @src.audit("fn main {}", path="D:/[name]<tag>.mbtx")
  let output = @src.render(@src.combine(a, a, []), "md", lang="zh")
  assert_false(output.contains(":null:null"))
  assert_true(output.contains("&lt;tag&gt;"))
  assert_true(output.contains("\\[name\\]"))
}
test "human language does not alter machine formats" {
  let a = @src.audit("---\npermission()\n---", path="x.mbtx")
  let report = @src.combine(a, a, [])
  assert_eq(@src.render(report, "json", lang="zh"), @src.render(report, "json", lang="en"))
  assert_eq(@src.render(report, "sarif", lang="zh"), @src.render(report, "sarif", lang="en"))
}
test "empty result keeps no-safety-proof caveat" {
  let a = @src.audit("---\npermission()\n---", path="x.mbtx")
  let output = @src.render(@src.combine(a, a, []), "text", lang="zh")
  assert_true(output.contains("当前上下文内无待处理风险"))
  assert_true(output.contains("无发现不等于脚本安全"))
}
