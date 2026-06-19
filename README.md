# PersistGuard

PersistGuard 是一个面向 macOS 的只读自启动持久化检测与可解释风险评分工具。它自主完成点位采集、配置解析、签名与文件证据校验、规则评分、审计日志和报告生成，不创建、加载、修改或删除任何自启动项。

## 功能

- 覆盖用户/全局 `LaunchAgents`、`LaunchDaemons` 和 `/System/Library` 系统基线。
- 检查传统登录项、BTM/`SMAppService` 后台项、cron、periodic、Shell 启动脚本、登录/注销钩子和配置描述文件。
- 使用 9 条透明规则生成 0-100 风险分，显示每条规则的权重、原因和证据。
- 通过 `codesign` 校验 Apple/Developer ID 签名，采集 SHA-256、属主、权限、大小和修改时间。
- 单个采集器、单个文件或系统命令失败不会中断扫描；权限不足会被明确记录。
- 输出美观的单文件 HTML 仪表盘、JSON、CSV 和追加式 JSONL 审计日志。
- 支持搜索、风险/来源筛选、发现详情、客户端 JSON/CSV 导出、打印和窄屏布局。
- 支持保存扫描基线并比较新增、删除、签名/哈希/分值等变化。
- 核心运行时仅使用 Python 标准库，无第三方检测工具或服务依赖。

![PersistGuard 扫描报告界面](/assets/report-preview.png)

## 环境

- macOS 12 或更新版本
- Python 3.9 或更新版本
- 普通用户可完成用户级扫描；部分系统点位无权限时会降级并记录

`codesign`、`system_profiler`、`sfltool` 和 `profiles` 均为 macOS 系统命令。命令缺失或超时时，相应来源会标记为不可用，其他扫描继续执行。

## 安装与扫描

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .

persistguard scan --out reports
```

扫描会生成：

```text
reports/
├── persistguard-report.html
├── persistguard-report.json
├── persistguard-report.csv
└── persistguard-report-audit.jsonl
```

HTML 是离线单文件，不加载 CDN、字体或外部脚本。可直接双击打开，也可使用本地服务：

```bash
persistguard serve reports/persistguard-report.html
```

若发现高危项目，`scan` 返回退出码 `2`，便于 CI 或定时任务告警；无高危项目返回 `0`。PersistGuard 不会自动处置发现项。

## 安全演示

仓库内置无害夹具，不写入真实 `~/Library/LaunchAgents`，也不执行 `launchctl`：

```bash
persistguard scan \
  --root tests/fixtures/demo_root \
  --home tests/fixtures/demo_root/Users/fixture \
  --no-system-baseline \
  --out reports/demo
```

`test.demo.persist` 指向夹具根目录中的 `/tmp/benign.sh`，预期命中：

- R01 未签名或签名无效：+30
- R02 临时/隐藏路径：+25
- R04 `RunAtLoad + KeepAlive`：+10
- R05 最近 7 天修改：+10

总分 75，等级 HIGH。这个脚本在扫描中不会被执行。

也可以在任意目录创建新的隔离夹具：

```bash
python examples/create_demo_fixture.py /tmp/persistguard-fixture
```

## 扫描范围与规则配置

只扫描指定类别：

```bash
persistguard scan --sources launchd,scheduled,shell --no-system-baseline
```

可用类别：`launchd`、`scheduled`、`shell`、`system`。

复制并调整 [`config/rules.example.json`](config/rules.example.json)，然后运行：

```bash
persistguard scan --rules config/rules.example.json
```

规则权重和高/中危阈值会写入 JSON/HTML 报告，确保结果可复现。默认规则如下：

| ID | 检测点 | 权重 |
|---|---|---:|
| R01 | 可执行文件未签名、无效或缺失 | +30 |
| R02 | 程序位于临时或隐藏目录 | +25 |
| R03 | 参数包含下载执行、解码、反连等命令链 | +25 |
| R04 | `RunAtLoad` 与 `KeepAlive` 同时开启 | +10 |
| R05 | 文件在最近 7 天修改 | +10 |
| R06 | 高权限任务的属主或写权限异常 | +15 |
| R07 | 非 Apple 程序使用 `com.apple.*` 标签 | +15 |
| R08 | 解释器执行内联脚本 | +10 |
| W01 | Apple 或有效 Developer ID 签名 | -40 |

默认高危分数为 `>= 60`，中危为 `30-59`，低危为 `< 30`。分数最终截断到 `[0, 100]`。

## 基线比较

保存当前扫描基线：

```bash
persistguard scan --baseline-out baselines/clean.json
```

完成后再次扫描，并比较：

```bash
persistguard scan --format json --out reports/current
persistguard compare baselines/clean.json reports/current/persistguard-report.json \
  --out reports/baseline-diff.json
```

差异会列出新增、移除和字段变化项。发现新增或变化时 `compare` 返回退出码 `1`。

## 测试

```bash
python -m unittest discover -s tests -v
```

测试覆盖数据模型、plist/cron/Shell 解析、全部评分规则、异常降级、报告导出、基线比较和无害夹具端到端扫描。

## 项目结构

```text
persistguard/
├── collectors/        # 各持久化点位的只读采集器
├── templates/         # 自包含 HTML 报告模板
├── scanner.py         # 五级扫描流水线与故障隔离
├── verifier.py        # codesign、哈希与文件元数据
├── engine.py          # 可解释规则评分
├── reporters.py       # HTML / JSON / CSV / 终端报告
├── auditlog.py        # JSONL 审计日志
├── baseline.py        # 基线保存与差异比较
└── cli.py             # 命令行入口
```

## 只读边界

PersistGuard 仅对用户指定的报告、日志和基线路径进行写入。对系统自启动点位只执行枚举和读取；不会运行发现的命令，不会调用 `launchctl load/bootstrap`，不会停用或删除任何项目。确认恶意项目后的处置应由管理员独立完成并保留证据。

## 许可证

[MIT](LICENSE)
