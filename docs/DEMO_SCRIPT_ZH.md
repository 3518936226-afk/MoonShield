# MoonShield 三分钟真实演示

这是操作脚本，不是录制完成的视频。全部结果须来自当前 CLI，不能用伪造字幕或 Native 结果替代 Moonrun。

## 0:00–0:25：问题

“AI 生成的脚本能运行，不代表它该拿到所有宿主权限。MoonShield 审查 MoonBit 脚本的权限声明，并用真实 Moonrun 检查隔离行为。”

显示 `MoonShield.exe doctor`。解释核心、CLI、审计和验证由 MoonBit/Wasm 实现，日常无需 Python。

## 0:25–1:15：看得懂的风险

执行 `MoonShield.exe audit examples/risky.mbtx --format text`。

先看结论和错误/高风险/警告数量，再选择文件星号、全宿主环境与 shell 三项，指出源码行列和建议。退出 1 表示成功发现风险，不是程序崩溃。

## 1:15–1:45：语义与生效策略

执行 `MoonShield.exe audit examples/escaped.mbtx --format text`，说明不能只搜索星号文本，必须根据官方 AST 和运行时转义语义识别授权。

再执行 `MoonShield.exe audit examples/risky.mbtx --policy examples/policies/deny.json --format text`。展示选定策略，说明嵌入记录仍保留，头部语法错误不能被忽略。无发现不代表正文安全。

## 1:45–2:15：进入开发流程

导出 SARIF：`MoonShield.exe audit examples/risky.mbtx --format sarif --out work/demo.sarif`。JSON/SARIF 用于脚本和代码审查，中文 text/Markdown 用于人工阅读。

## 2:15–3:00：实际证据与边界

执行 `MoonShield.exe verify`。只有本次真实 39/39 才展示 GO；若录制时失稳，保留失败，不套用旧字幕。

说明 13 个场景各三次，只执行内置合成探针。TOML、自动继承发现、正文分析及通用原生子进程沙箱尚未支持。

## 一键操作

`powershell -NoProfile -ExecutionPolicy Bypass -File scripts/demo.ps1`

实际 argv、cwd、退出码、文本记录、SARIF 和验证原始证据保存在新的 evidence/demo-v1.2-*。`-Fast` 明确跳过运行验证，不给出运行时 GO。

## v1.2 新增演示

一键演示新增：选定 deny-all 下父级宽授权降为上下文提示、订单示例的元数据观察、官方旧式策略明确显示暂不支持。共十步，其中一步真实运行验证；Fast 为九步且明确跳过运行验证。
