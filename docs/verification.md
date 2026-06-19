# 实现与验收矩阵

本文档将技术架构说明书的要求映射到代码与可复现验证证据。

| 要求 | 实现位置 | 验证方式 |
|---|---|---|
| 只读扫描，不创建/修改/删除自启动项 | `persistguard/scanner.py`、各 collector | 代码审计；扫描只调用读取命令，写入仅限用户指定报告/日志路径 |
| LaunchAgents / LaunchDaemons / 系统基线 | `collectors/launchd.py` | `tests/test_collectors.py`；实机基线扫描覆盖 5 个目录 |
| 登录项与 BTM / SMAppService | `collectors/system.py` | `tests/test_system_collector.py`；实机 `sfltool dumpbtm` 采集并过滤非启动类型 |
| cron 与 periodic | `collectors/cron.py` | `test_cron_parser_handles_system_and_reboot` |
| Shell 启动脚本 | `collectors/shell.py` | 普通赋值、命令替换、内联命令回归测试 |
| 登录/注销钩子与描述文件 | `collectors/system.py` | 实机空状态/权限降级检查 |
| 统一数据模型 | `models.py` | `tests/test_models.py` |
| codesign / spctl、SHA-256、属主、权限、时间 | `verifier.py` | Apple 系统二进制、未签名夹具和 `.app` 主程序哈希测试 |
| R01-R08、W01 可解释规则 | `engine.py`、`config.py` | `tests/test_engine.py` |
| 权重和阈值可配置 | `config/rules.example.json`、CLI `--rules` | 规则配置写入 JSON/HTML 的 `policy` 字段 |
| 0-100 分与高/中/低阈值 | `engine.py` | 阈值、截断、可信签名测试 |
| 权限/解析/命令超时不中断扫描 | collector 边界与 `ScanError` | 损坏 plist、Expat fallback、权限不足实机证据 |
| HTML / JSON / CSV 报告 | `reporters.py`、`templates/report.html` | 可解析性、自包含、XSS/CSV 注入测试 |
| 美观、可筛选、可查看证据的界面 | `templates/report.html` | 浏览器桌面/390px 移动端、搜索、筛选、详情抽屉检查 |
| 可审计日志 | `auditlog.py` | JSONL 追加与解析测试 |
| 基线差异 | `baseline.py`、CLI `compare` | 新增/移除/变化测试 |
| 无害高危演示 | `tests/fixtures/demo_root` | 端到端得到 R01+R02+R04+R05、75 分 HIGH |

## 验证命令

```bash
python -m unittest discover -s tests -v

python -m persistguard scan \
  --root tests/fixtures/demo_root \
  --home tests/fixtures/demo_root/Users/fixture \
  --no-system-baseline \
  --out reports/demo

python -m persistguard scan --sources launchd --no-signature --out reports/system-baseline
```

夹具扫描出现 HIGH 时返回退出码 2，这是预期的检测结果，不是运行失败。
