"""Configuration and rule definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    title: str
    weight: int
    rationale: str


RULES: Dict[str, RuleDefinition] = {
    "R01": RuleDefinition("R01", "签名缺失或无效", 30, "恶意或被篡改程序通常缺少可信代码签名。"),
    "R02": RuleDefinition("R02", "临时或隐藏路径", 25, "临时目录和隐藏目录不适合作为长期自启动程序位置。"),
    "R03": RuleDefinition("R03", "可疑命令链", 25, "下载执行、解码或反连命令常用于恶意载荷启动。"),
    "R04": RuleDefinition("R04", "强驻留配置", 10, "RunAtLoad 与 KeepAlive 同时开启会形成被杀重拉。"),
    "R05": RuleDefinition("R05", "近期新增或修改", 10, "最近七天发生变更的启动项值得优先核查。"),
    "R06": RuleDefinition("R06", "属主或权限异常", 15, "高权限任务的程序可被低权限用户修改时存在劫持风险。"),
    "R07": RuleDefinition("R07", "仿冒 Apple 命名", 15, "非 Apple 签名项目使用 com.apple.* 标签具有伪装嫌疑。"),
    "R08": RuleDefinition("R08", "解释器内联执行", 10, "内联脚本减少落地痕迹并可能规避文件级检测。"),
    "W01": RuleDefinition("W01", "可信签名", -40, "Apple 或有效 Developer ID 签名可显著降低来源风险。"),
}

SUSPICIOUS_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("curl", "curl 下载命令"),
    ("wget", "wget 下载命令"),
    ("bash -c", "bash 内联命令"),
    ("sh -c", "shell 内联命令"),
    ("base64", "Base64 解码"),
    ("osascript -e", "AppleScript 内联命令"),
    ("python -c", "Python 内联命令"),
    ("python3 -c", "Python 内联命令"),
    ("perl -e", "Perl 内联命令"),
    ("ruby -e", "Ruby 内联命令"),
    ("/dev/tcp", "TCP 设备重定向"),
    ("nc -", "netcat 网络命令"),
    ("ncat ", "ncat 网络命令"),
    ("socat ", "socat 网络命令"),
    ("chmod +x", "修改可执行权限"),
    ("xattr -d", "移除扩展属性"),
)

INTERPRETERS = {
    "bash", "sh", "zsh", "dash", "fish", "python", "python3", "perl", "ruby",
    "osascript", "node", "php",
}
INLINE_FLAGS = {"-c", "-e", "--eval", "-Command", "-EncodedCommand"}
TEMP_PREFIXES = ("/tmp", "/private/tmp", "/var/tmp", "/Users/Shared", "/dev/shm")
SHELL_RC_FILES = (
    ".zshrc", ".zprofile", ".zlogin", ".bash_profile", ".bashrc", ".profile",
    ".config/fish/config.fish",
)


@dataclass
class ScanConfig:
    root: Path = Path("/")
    home: Path = field(default_factory=Path.home)
    include_system_baseline: bool = True
    signature_timeout: float = 8.0
    command_timeout: float = 15.0
    recent_days: int = 7
    min_level: str = "LOW"
    rule_weights: Dict[str, int] = field(default_factory=lambda: {rule_id: rule.weight for rule_id, rule in RULES.items()})
    high_threshold: int = 60
    medium_threshold: int = 30

    def rooted(self, absolute_path: str) -> Path:
        path = Path(absolute_path)
        if self.root == Path("/"):
            return path
        return self.root / str(path).lstrip("/")

    def home_path(self, relative: str = "") -> Path:
        return self.home / relative if relative else self.home
