/// Schema v2 separates tool coverage, malformed configuration and policy risks.
fn clone_object(j : Json) -> Map[String, Json] {
  let copy : Map[String, Json] = Map([])
  if j is Object(o) { for k, v in o { copy[k] = v } }
  copy
}

fn classify(f : Json) -> Json {
  let o = clone_object(f)
  let code = text(f, "code")
  o["category"] = Json::string(if code.contains("UNSUPPORTED") { "unsupported" }
    else if text(f, "severity") == "error" { "configuration_error" }
    else if text(f, "severity") == "info" { "information" } else { "risk" })
  if code.contains("UNSUPPORTED") { o["severity"] = "warning" }
  Json::object(o)
}

pub fn assessment_status(findings : Array[Json]) -> String {
  if findings.any(f => text(f, "category") == "configuration_error") { "INVALID" }
  else if findings.any(f => text(f, "category") == "unsupported") { "UNSUPPORTED" }
  else if findings.any(f => ["high", "warning", "error"].contains(text(f, "severity"))) { "REVIEW_REQUIRED" }
  else { "NO_FINDINGS" }
}

fn usable(group : Json) -> Bool {
  ["NO_FINDINGS", "REVIEW_REQUIRED"].contains(text(group, "status")) && get(group, "policy") is Object(_)
}

/// Only prove the trivial empty-rule cases. Never approximate a glob/path intersection.
fn denies(group : Json, domain : String, operation : String) -> Bool {
  if !usable(group) { return false }
  let p = get(get(group, "policy"), domain)
  if domain == "fs" { return get_array(p, operation).is_empty() }
  if domain == "net" { return ["dns", "connect", "bind"].all(k => get_array(p, k).is_empty()) }
  if domain == "process" { return get(p, "spawn") != Json::boolean(true) && get_array(p, "allow").is_empty() }
  false
}

fn projection(f : Json, groups : Array[Json]) -> Json {
  let o = clone_object(f)
  if text(f, "category") != "risk" { return Json::object(o) }
  if text(f, "domain") == "env" && text(f, "role") == "inherited" {
    o["original_severity"] = get(f, "severity")
    o["severity"] = "info"
    o["category"] = "information"
    o["assessment"] = "ancestor_environment_context"
    o["assessment_note"] = "Ancestor provisioning is retained as context; it is not the selected guest environment. Actual inherited host values are not discovered."
    return Json::object(o)
  }
  for i, group in groups {
    if denies(group, text(f, "domain"), text(f, "operation")) {
      o["original_severity"] = get(f, "severity")
      o["severity"] = "info"
      o["category"] = "information"
      o["assessment"] = "direct_operation_denied_by_policy"
      o["blocking_source"] = get(group, "source")
      o["proof_basis"] = if i == 0 { "selected_policy" } else { "declared_inherited_ceiling" }
      o["assessment_note"] = "Only direct runtime operations in the stated context are denied. Native child access, bound resources and actual session inheritance are not proven."
      return Json::object(o)
    }
  }
  o["assessment"] = "configuration_risk_unresolved"
  Json::object(o)
}

pub fn refresh(report : Json) -> Json {
  let o = clone_object(report)
  let findings = get_array(report, "findings")
  o["status"] = Json::string(assessment_status(findings))
  o["summary"] = {
    "configuration_errors": findings.filter(f => text(f, "category") == "configuration_error").length(),
    "unsupported": findings.filter(f => text(f, "category") == "unsupported").length(),
    "risks": findings.filter(f => text(f, "category") == "risk").length(),
    "information": findings.filter(f => text(f, "category") == "information").length(),
  }
  Json::object(o)
}

/// Observations are trusted adapter snapshots, not a proof of necessity or race-free identity.
pub fn with_path_context(report : Json, observations : Array[Json]) -> Json {
  let o = clone_object(report)
  let findings = get_array(report, "findings").map(f => Json::object(clone_object(f)))
  for observation in observations {
    guard get(observation, "finding_index") is Number(n, ..) else { continue }
    let index = n.to_int()
    if index < 0 || index >= findings.length() { continue }
    let f = findings[index]
    if text(f, "code") == "FS_LITERAL_SCOPE" && text(f, "severity") == "warning" &&
      text(observation, "source") == text(f, "source") && text(observation, "grant_path") == text(f, "grant_path") {
      let item = clone_object(f)
      item["path_observation"] = observation
      if text(observation, "status") == "REGULAR_EXACT_MATCH" {
        item["original_severity"] = get(f, "severity")
        item["severity"] = "info"
        item["category"] = "information"
        item["assessment"] = "observed_regular_file"
        item["assessment_note"] = "Read-only metadata snapshot, not business-necessity, content, hardlink or race-free identity proof."
      }
      findings[index] = Json::object(item)
    }
  }
  o["findings"] = Json::array(findings)
  o["path_context"] = { "mode": "inspect", "observations": observations, "content_read": false }
  refresh(Json::object(o))
}
