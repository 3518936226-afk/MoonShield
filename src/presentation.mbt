pub fn version() -> String { "1.2.0" }

fn label(status : String, zh : Bool) -> String {
  if !zh { return status }
  match status {
    "NO_FINDINGS" => "当前上下文内无待处理风险"
    "REVIEW_REQUIRED" => "需要人工复核"
    "INVALID" => "配置错误"
    "UNSUPPORTED" => "暂不支持，审计未完成"
    "ERROR" => "工具运行错误"
    _ => status
  }
}

fn severity_label(severity : String, zh : Bool) -> String {
  if !zh { return severity }
  match severity { "error" => "错误"; "high" => "高风险"; "warning" => "警告"; _ => "提示" }
}

fn explain(code : String, fallback : String, zh : Bool) -> String {
  if !zh { return fallback }
  match code {
    "FS_BROAD_SCOPE" => "文件权限覆盖所有路径、根目录或当前/父级范围。"
    "FS_LITERAL_SCOPE" => "字面路径也可能指向目录子树或别名，实际范围尚未证明。"
    "FS_ABSOLUTE_SCOPE" => "授权包含宿主绝对路径，需要核查实际范围。"
    "FS_GLOB_SCOPE" => "glob 模式及排除规则需要结合真实文件系统复核。"
    "ENV_HOST_ALL" => "脚本请求导入全部宿主环境变量。"
    "ENV_PATH" => "宿主 PATH 会影响子进程的可执行文件查找。"
    "ENV_LITERAL" => "策略直接写入环境变量值；报告已隐藏该值。"
    "PROCESS_ALLOW_ALL" => "允许创建任意宿主进程。"
    "PROCESS_UNBOUNDED_ARGS" => "允许的程序没有非空参数前缀约束。"
    "PROCESS_INTERPRETER" => "允许 shell 或解释器可能带来任意指令执行能力。"
    "PROCESS_LOOKUP" => "仅凭程序名称查找可执行文件，结果依赖宿主环境。"
    "PROCESS_HOST_CAPABILITY" => "被允许的原生子进程仍有宿主账户能力。"
    "NETWORK_WILDCARD" => "网络授权包含通配范围。"
    "NETWORK_ACCESS" => "网络授权存在；未验证实际 DNS、地址及连接行为。"
    "DUPLICATE_KEY" => "存在重复的解码后权限键，解释可能有歧义。"
    "DUPLICATE_PERMISSION" => "存在多个 permission 声明。"
    "NO_PERMISSION" | "NO_PERMISSION_HEADER" => "没有确立显式权限策略，不能假定默认拒绝。"
    "CONFIG_SYNTAX" => "官方配置解析器报告语法错误。"
    "INVALID_LITERAL" => "字符串转义不符合当前锁定运行时的配置语法。"
    "INVALID_TYPE" => "权限字段的值类型不符合要求。"
    "INVALID_FS_RULE" => "路径规则对象必须只有一个 glob 字符串字段。"
    "JSON_SYNTAX" => "JSON 语法错误或存在重复键。"
    "UNTERMINATED_HEADER" => "配置头缺少结束分隔线。"
    "LEGACY_POLICY_UNSUPPORTED" => "旧式 YAML 权限策略暂未支持。"
    "POLICY_FORMAT_UNSUPPORTED" => "权限文件格式暂未支持；不能完成审计。"
    "JSON_NULL_UNSUPPORTED" => "JSON 可选域的 null 写法暂未支持；不能完成审计。"
    "UNKNOWN_FIELD" => "出现锁定权限 schema 中未知的字段。"
    "PROCESS_CONFLICT" => "spawn=true 与非空 allow 列表不能同时使用。"
    "PROCESS_MODE_CONFLICT" => "IPC 与虚拟进程模式不能同时启用。"
    "PROCESS_EXECUTION_MODE" => "进程执行模式需要结合实际运行时复核。"
    "FRONT_MATTER_INVALID_OR_LEGACY" => "配置头不完整，或包含本版本不支持的旧式策略。"
    "POLICY_FORMAT_INVALID_OR_UNSUPPORTED" => "权限文件格式无效或尚未支持，不能乐观放行。"
    "SCAN_INCOMPLETE" => "有路径被跳过，或没有找到可审计脚本，扫描不完整。"
    _ => fallback
  }
}

fn advice(code : String, zh : Bool) -> String {
  if !zh {
    match code {
      "FS_BROAD_SCOPE" => "Narrow roots to required files/directories; verify aliases and subtrees."
      "ENV_HOST_ALL" => "List only required variables in from_host."
      "PROCESS_ALLOW_ALL" | "PROCESS_INTERPRETER" => "Use explicit programs/prefixes; native children retain host capabilities."
      "DUPLICATE_KEY" | "DUPLICATE_PERMISSION" => "Keep one unambiguous declaration/key."
      _ => "Review the finding and effective policy, then repeat audit and runtime verification."
    }
  } else {
    match code {
      "FS_BROAD_SCOPE" => "收窄到实际需要的文件或目录，并核查目录子树与别名。"
      "ENV_HOST_ALL" => "使用 from_host 明确列出所需变量，不导入全部宿主环境。"
      "ENV_LITERAL" => "确认不是密钥；敏感值改为按名称由宿主提供，避免写入策略。"
      "PROCESS_ALLOW_ALL" | "PROCESS_INTERPRETER" | "PROCESS_UNBOUNDED_ARGS" => "使用明确程序与参数前缀；不要将其误当作原生子进程沙箱。"
      "DUPLICATE_KEY" | "DUPLICATE_PERMISSION" => "保留单一明确声明及唯一键，再重新审计。"
      "INVALID_LITERAL" => "按运行时配置语法修正转义；不要混用源码字符串语法。"
      "SCAN_INCOMPLETE" => "核查跳过路径及链接，确认审计范围完整。"
      _ => "结合生效策略复核此项，修改后重新审计与运行验证。"
    }
  }
}

fn location(f : Json) -> String {
  let path = text(f, "source")
  let start = get(get(f, "range"), "start")
  if get(start, "line") is Number(_, ..) && get(start, "column") is Number(_, ..) {
    path + ":" + get(start, "line").stringify() + ":" + get(start, "column").stringify()
  } else { if path == "" { "(location unavailable)" } else { path } }
}

fn markdown_escape(value : String) -> String {
  value.replace_all(old="\\", new="\\\\").replace_all(old="&", new="&amp;").replace_all(old="<", new="&lt;").replace_all(old=">", new="&gt;")
    .replace_all(old="`", new="\\`").replace_all(old="[", new="\\[").replace_all(old="]", new="\\]")
    .replace_all(old="\r", new=" ").replace_all(old="\n", new=" ")
}

fn human(report : Json, markdown : Bool, lang : String) -> String {
  let zh = lang == "zh"
  let findings = get_array(report, "findings")
  let count = fn(level) { findings.filter(f => text(f, "severity") == level).length().to_string() }
  let b = StringBuilder()
  b.write_string((if markdown { "# " } else { "" }) + "MoonShield " + version() + "\n\n")
  b.write_string((if zh { "结论：" } else { "Status: " }) + label(text(report, "status"), zh) + "\n")
  b.write_string((if zh { "发现：错误 " } else { "Findings: error " }) + count("error") + (if zh { " · 高风险 " } else { " | high " }) + count("high") + (if zh { " · 警告 " } else { " | warning " }) + count("warning") + (if zh { " · 提示 " } else { " | information " }) + count("info") + "\n")
  let display = fn(value) { if markdown { markdown_escape(value) } else { value.replace_all(old="\r", new=" ").replace_all(old="\n", new=" ") } }
  let selected = text(get(report, "selected"), "source")
  if selected != "" {
    b.write_string((if zh { "生效策略：" } else { "Selected policy: " }) + display(selected) + "\n")
    if text(get(report, "embedded"), "source") != selected {
      b.write_string(if zh { "已选择外部策略；嵌入策略记录保留，头部语法错误仍会报告。\n" } else { "External override selected; embedded record retained and header syntax errors still reported.\n" })
    }
    b.write_string((if zh { "显式父级限制：" } else { "Explicit inherited ceilings: " }) + get_array(report, "inherited").length().to_string() + "\n")
  }
  if get(report, "files") is Number(_, ..) {
    b.write_string((if zh { "已扫描脚本：" } else { "Scanned scripts: " }) + get(report, "files").stringify() + "\n")
  }
  b.write_string("\n")
  for i, f in findings {
    let code = text(f, "code")
    b.write_string((if markdown { "## " } else { "" }) + (i + 1).to_string() + ". [" + severity_label(text(f, "severity"), zh) + "] " + code + "\n")
    b.write_string("   " + display(location(f)) + "\n")
    b.write_string("   " + explain(code, text(f, "message"), zh) + "\n")
    let assessment = text(f, "assessment")
    if assessment != "" {
      b.write_string((if zh { "   上下文：" } else { "   Context: " }) + (if zh {
        match assessment {
          "direct_operation_denied_by_policy" => "所提供策略中存在明确拒绝；保留原始授权提示。仅证明直接操作，未发现真实会话继承。"
          "ancestor_environment_context" => "父级环境设置仅作上下文记录，不当作选定脚本的环境授权。"
          "observed_regular_file" => "只读元数据表明当前是普通文件；未读内容，未证明业务必要性，也不能消除竞态。"
          _ => "配置授权范围仍需复核。"
        }
      } else { text(f, "assessment_note") }) + "\n")
    }
    b.write_string((if zh { "   建议：" } else { "   Action: " }) + (if text(f, "severity") == "info" {
      if zh { "保留此记录；策略、路径或运行上下文变化后重新审计。" } else { "Retain this context; audit again after policy, path or session changes." }
    } else { advice(code, zh) }) + "\n\n")
  }
  if findings.is_empty() { b.write_string(if zh { "支持的审计规则内没有发现需复核项。\n\n" } else { "No findings in the supported audit rules.\n\n" }) }
  if get(report, "path_context") is Object(_) {
    b.write_string((if zh { "路径检查模式：" } else { "Path context mode: " }) + text(get(report, "path_context"), "mode") + "\n")
  }
  b.write_string(if zh { "范围说明：未执行候选脚本正文；未自动发现会话继承。无发现不等于脚本安全。\n" } else { "Scope: candidate body not executed; ambient inheritance not discovered. No findings is not a proof of safety.\n" })
  b.to_string()
}
