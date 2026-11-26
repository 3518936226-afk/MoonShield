# v1.2 审计语义与兼容边界

本版减少误报的办法是保留事实，再解释上下文；没有把静态结果当作安全保证。

## 状态与 JSON schema 2

| 状态 | 含义 | 退出行为 |
|---|---|---|
| INVALID | 已知的配置语法、类型或字段错误 | 始终 1 |
| UNSUPPORTED | 格式或声明超出当前实现覆盖 | 始终 1 |
| REVIEW_REQUIRED | 存在需复核的授权风险 | 按 --fail-on 阈值 |
| NO_FINDINGS | 当前明确上下文内没有待处理风险，可有 info 提示 | 0 |
| ERROR | 参数、I/O、固定工具链或可信探针故障 | CLI 2 |

状态优先级为配置错误、覆盖不足、风险、无待处理风险。混合输入的全部条目仍保留；不会只保留最高优先级类别。

`configuration_findings` 是选定策略与显式父级配置的原始问题列表；被覆盖的嵌入策略另在 embedded 中保留，头部语法、转义与覆盖不足也不能被悄悄忽略。`findings` 是当前上下文投影，包含 category、assessment、original_severity 等解释。旧 schema 1 的使用者需适配，不能只按 findings 数量判断风险。

类别为 risk、configuration_error、unsupported、information。SARIF 的 info 对应 note；原始配置风险不会因提示降级而删除。summary 分类别计数。

缺少显式权限是风险，未必是配置语法错误。TOML、旧 YAML、JSON 可选域的 null 写法是覆盖不足。本机真实 Moonrun 已证明 `{"fs":null}` 可以执行受控 noop，因此工具显示 UNSUPPORTED，不能错误称为非法 JSON。未知 glob 对象字段则是已知 schema 错误，运行时反例保留。

## 只证明明确的简单拒绝

选定配置替换嵌入权限；每个明确提供的 fs/net/process ceiling 还需授权。同一个操作必须满足所有组。我们只识别：

- 文件 read 或 write 列表为空/域缺省，分别拒绝该类直接操作。
- net 的 dns、connect、bind 全部为空/缺省，拒绝直接网络操作；不会仅因 dns 为空就推断不能解析 connect 授权的域名。
- process 的 spawn 不为 true 且 allow 为空/缺省，拒绝直接创建进程。

只有已成功分析的组能用于拒绝证明。配置错误、覆盖不足不会降级；read 的拒绝不能抹去 write 或创建原生子进程的风险。两个非空 glob 即使看起来不相交，也不猜测交集。

父级环境 provisioning 只作上下文信息，当前客体环境以选定配置为准。该模型依据固定官方实现，不代表自动发现了真实父会话；`proof_basis=declared_inherited_ceiling` 是以用户提供的上下文成立为条件的结论。不会证明 Native 子进程、已绑定 stdio、继承资源或宿主账户被隔离。

## 可选路径元数据观察

默认 `--path-context static` 不访问授权目标。显式 `inspect` 只对仍为 warning 的相对字面路径调用文件类型与规范路径查询，不打开或读取目标数据内容。

以对应策略文件目录解析授权路径。只有末端为普通文件且规范路径与词法绝对路径一致，才降为 info。中间 junction 导致的规范路径差异、末端链接、目录、缺失或不可访问路径保持 warning。实际 Windows junction 对照各重复三次。

这是时间点上的观察，不证明业务必要性，不防止随后替换、硬链接或所有别名。报告会包含观察路径；在分享私人项目报告前仍须复核。核心模块的 with_path_context 接受可信适配器观察，不是用于验证任意外部 JSON 证据的接口。

## 真实样本和环境

- 官方 corpus：moonbitlang/moon 固定提交的六份原始脚本，仅静态解析，不下载 imports，不运行正文。来源、许可和 SHA-256 见 examples/official-corpus/provenance.json。
- 订单场景：MoonShield 自有、虚构三笔订单；真实 Wasm 读 CSV、计算 4990 分、写 summary.txt。成功、缺读、缺写、授权其他文件各三次。
- JSON null/错误 glob 对象：自有 noop 的真实 Moonrun 正反例，各三次。
- 干净目录：同一台 Windows 机器、最小宿主环境、无 PATH/PATHEXT/Python 搜索路径；不是另一台电脑。日常命令无需 Python；Python 仅为开发验收依赖，未安装新包。
- Linux、macOS、其他 MoonBit 版本：NOT_TESTED。锁不匹配的拒绝只证明完整性检查，不等于测过其他版本的权限行为。

最小环境暴露了 PowerShell 在 PATHEXT 缺少 .EXE 时可能空输出却退出 0 的问题。启动器现明确补充 .EXE 并校验实际退出码；原失败与修正后的三次结果保留。此设置属于可信启动器自身环境，不会放宽客体权限。

## 官方依据

[官方脚本模式文档](https://docs.moonbitlang.com/en/latest/toolchain/moon/script-mode.html) 是解释入口。行为比较固定在已验收的 Moon/Moonrun 738607b，不能拿 nightly 文档更新当成当前二进制的新功能：

- [front_matter.rs](https://github.com/moonbitlang/moon/blob/738607b3e4005a0343f09b744dbde641b38de64c/crates/moonutil/src/front_matter.rs)
- [policy/config.rs](https://github.com/moonbitlang/moon/blob/738607b3e4005a0343f09b744dbde641b38de64c/crates/moonrun/src/policy/config.rs)
- docs/runtime-reference 保留的策略与进程参考实现；官方 parser 原始字节由 upstream.lock.json 校验。
