# MoonShield 1.2.0

**MoonBit Script Permission Policy Auditor & Runtime Conformance Tester**

在运行 AI 生成或第三方 `.mbtx` 脚本前审查宿主权限；用真实 Moonrun 探针检查升级后的权限行为。解析、转义语义、策略模型、规则、报告与验证均用 **MoonBit** 实现。日常 CLI 不需要 Python。EXE 只负责保留参数并启动 MoonBit Wasm，不是 Native 权限隔离实现。

这是完成本地验收的 v1.2 CLI，不是任意脚本的安全证明或容器。`audit` 不编译、不运行候选脚本正文；`verify` 只运行内置合成探针。

## 五分钟体验

在 D 盘克隆或解压项目，先按下文“工具链准备”配置锁定版本，再运行以下命令。仓库包含启动器和 Wasm，不包含大型工具链：

```powershell
.\MoonShield.exe doctor
.\MoonShield.exe audit .\examples\empty.mbtx
.\MoonShield.exe audit .\examples\risky.mbtx --format text
.\MoonShield.exe audit .\examples\escaped.mbtx --format sarif --out .\work\escaped.sarif
.\MoonShield.exe audit .\examples\risky.mbtx --policy .\examples\policies\deny.json
.\MoonShield.exe verify
```

预期：empty 无发现；risky 和 escaped 返回复核状态及退出码 1；deny.json 覆盖嵌入风险策略后，顶层无权限发现，embedded 记录仍保留；verify 的 13 个场景各重复三次，39/39 时返回 GO。

人工阅读建议使用 `--format text`：默认中文，先看结论、风险数量与生效策略，再看定位和建议。可加 `--lang en` 切换英文。默认不指定 format 时仍输出 JSON，已有自动化命令不变；Markdown 同样支持语言选项，JSON/SARIF 不因语言而改变。

也可使用纯 PowerShell 入口：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\MoonShield.ps1 audit .\examples\empty.mbtx
```

## 工具链准备

锁定 MoonBit v0.10.22+124d61d05，Moon/Moonrun 0.1.20261119 (738607b)。Windows x64 已完成本机验收。精简发布包不含大型工具链。

```powershell
# 使用现有的相同版本独立工具链
$env:MOONSHIELD_TOOLCHAIN = 'D:/path/to/toolchain'
# 或使用原始离线包，在本项目 work/toolchain 中准备
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1 -ArchiveDir 'D:/archives'
# 下载必须显式选择，仅接受锁定版本和校验值
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1 -Download
```

离线包名为 moonbit-windows-x86_64.zip、core.zip，也可分别用 -BinaryArchive / -CoreArchive 指定文件。默认不下载、不修改全局 PATH、不写个人配置。完整工具链约 315 MiB；现有目录不自动删除或覆盖。历史下载源可能失效，应使用原始离线包，不能偷换成最新版。

## 命令

| 命令 | 功能 |
|---|---|
| audit FILE | 审计 .mbtx 或严格 JSON 策略 |
| --policy FILE | 选择外部策略，保留被覆盖记录；头部语法错误仍不能忽略 |
| --inherit FILE | 可重复；保留显式父级 ceiling，不并成更宽的 union |
| scan DIRECTORY | 扫描 .mbtx；跳过链接/越界路径，跳过或空扫描会要求复核 |
| --format json/text/md/sarif | JSON、中文/英文终端、Markdown、SARIF 2.1.0 输出 |
| --lang zh/en | 人工报告语言，CLI 默认中文；不改变机器格式 |
| --path-context static/inspect | 默认 static；inspect 只读路径元数据，不读取授权文件内容 |
| --out FILE | 保存报告；audit 默认只输出终端，不保存源码副本 |
| --fail-on warning/high/error | 退出阈值，默认 warning；改变阈值不会抹去风险 |
| verify --repeat N | 仅执行内置探针，N 为 3–10；--out 指定证据父目录 |
| doctor | 工具链与运行模式 |

退出码：0 为当前阈值下无发现/测试通过；1 为复核、配置错误、暂不支持或 NO-GO；2 为参数、I/O、工具链或可信探针故障。**退出 0 不代表脚本安全。**

## v1.2 如何减少误报

JSON schema 升为 2，消费者需适配。`configuration_findings` 保留原始配置风险；`findings` 表示结合当前明确提供的策略后的待处理风险或提示，不删除原始记录。

- `INVALID` 只表示已知配置错误，`UNSUPPORTED` 表示工具尚未覆盖；两者不能被 --fail-on error 放过。
- 当前策略明确拒绝直接操作时，宽泛授权保留为 info 提示；仅证明空规则的简单情形，不推测 glob 的交集。--inherit 只是用户声明的上下文，不代表发现了真实会话。
- `--path-context inspect` 对普通文件作只读元数据观察，规范路径完全一致时才将对应字面路径警告降为提示。目录、别名、缺失或访问失败继续警告；不证明权限必要性、不消除竞态或硬链接问题。

```powershell
.\MoonShield.exe audit .\examples\empty.mbtx --inherit .\examples\policies\parent.json --format text
.\MoonShield.exe audit .\examples\orders\orders.mbtx --path-context inspect --format text
```

订单示例只用虚构 CSV。读取范围可识别为当前普通文件，但 summary.txt 的 glob 写权限仍需复核，因此第二条仍可退出 1。完整解释见 docs/AUDIT_SEMANTICS.md。

## 规则与范围

识别缺失/空策略、重复声明与解码后重复键、字段类型、宽泛文件根、glob、环境全量导入、PATH、字面值、任意进程、解释器、可执行查找、参数前缀、进程模式冲突和网络授权。

- 文件根可能是目录/别名；默认不访问授权目标，只做保守提示。显式 inspect 可读取元数据快照，仍不读取文件内容。
- .mbtx 转义按固定 Moonrun 官方实现转换，JSON 使用官方 core/json；四位十六进制与花括号转义不混用，surrogate-pair 差异有实际运行时测试。
- 显式策略替换嵌入策略；父级 fs/net/process ceiling 按 AND 保留。环境 provisioning 不是可合并权限列表；没有声称求出任意 glob/网络集合的精确交集。
- 不自动发现会话继承，须明确提供 --inherit。没有正文/数据流审计或权限最小化证明。
- **不支持 TOML、旧 YAML、JSON 顶层可选域为 null 的特殊写法**；拒绝乐观放行。网络端点/DNS/实际连接还需运行时验证。
- 原生子进程仍有宿主账户权限，fs/net 不会自动隔离它们。本工具不提供任意不可信脚本执行命令。
- 不是防竞态、资源配额或恶意编译输入沙箱。扫描限深度 32、1,000 文件、单输入 1 MiB；链接检查不能消除 TOCTOU。
- env.set 值默认隐藏；报告仍含路径、变量名、程序和参数。日志不是通用密钥脱敏器。

## 开发与验证

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test.ps1
# 开发者 CLI 验收需要已有 Python 3，不会自动安装
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\test.ps1 -Integration
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\demo.ps1
```

公开验收说明与摘要见 docs/VALIDATION.md 和 docs/validation-summary.json；原始日志在本地保留，不随仓库上传。所有脚本使用项目内 work/evidence，不自动清理历史。build 使用 --frozen，只编译本项目与固定依赖，绝不编译候选脚本。编译器、运行时及 core 源码/接口共锁定 1,850 项输入；可重建缓存不作为信任根，验证后并发替换仍是限制。

演示脚本默认包含十步与真实运行验证，保存逐步命令、结果、SARIF 和文本实录；`-Fast` 明确跳过运行验证，不声明 GO。三分钟讲解稿见 docs/DEMO_SCRIPT_ZH.md，项目说明见 docs/PROJECT_BRIEF_ZH.md。这些是操作/说明材料，未冒充已录制视频。

## 目录与许可

src 为可复用 MoonBit 模块，cmd 为 MoonBit CLI/验证，scripts 为平台适配/构建，vendor 为未修改的官方解析器，docs 为设计与威胁模型，examples 为合成示例，dist 为预编译 Wasm。

自有代码采用 Apache-2.0，见 LICENSE；来源和移植说明见 THIRD_PARTY_NOTICES.md。构建副本仅停用必要的 token 生成步骤，使用固定提交附带的 tokens.mbt；官方 .mbt 未修改。

GitHub 仓库：https://github.com/3518936226-afk/MoonShield 。本次按用户授权公开当前源码，提交记录从实际上传开始，不补造历史。GitHub Actions 结果见仓库 Actions 页面；赛事报名及资格核实未代用户执行。

## 源码打包

开发者可运行 `python scripts/package.py` 生成不含原始日志、工作目录与工具链的独立源码/运行产物包。已存在同名包时停止，不覆盖历史。打包不会上传文件或创建 GitHub Release。
