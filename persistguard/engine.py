"""Explainable, deterministic risk-scoring engine."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .config import (
    INLINE_FLAGS,
    INTERPRETERS,
    RULES,
    SUSPICIOUS_PATTERNS,
    TEMP_PREFIXES,
)
from .models import AutoStartItem, RuleHit
from .utils import is_hidden_path


class RuleEngine:
    def __init__(self, recent_days: int = 7, now: Optional[float] = None, weights: Optional[Dict[str, int]] = None, high_threshold: int = 60, medium_threshold: int = 30) -> None:
        self.recent_days = recent_days
        self.now = now
        self.weights = weights or {rule_id: rule.weight for rule_id, rule in RULES.items()}
        self.high_threshold = high_threshold
        self.medium_threshold = medium_threshold

    def _add(self, item: AutoStartItem, rule_id: str, reason: str, evidence: str = "") -> None:
        definition = RULES[rule_id]
        item.hits.append(
            RuleHit(rule_id, self.weights.get(rule_id, definition.weight), definition.title, reason, evidence)
        )

    @staticmethod
    def _permission_risk(item: AutoStartItem) -> str:
        if not item.mode:
            return ""
        try:
            mode = int(item.mode, 8)
        except ValueError:
            return ""
        writable_by_others = bool(mode & stat.S_IWOTH)
        writable_by_group = bool(mode & stat.S_IWGRP)
        privileged = item.scope == "system" or item.source in {"launch_daemon", "login_hook", "periodic"}
        wrong_owner = privileged and item.owner not in {"root", "0", ""}
        if writable_by_others:
            return f"程序权限 {item.mode} 允许任意用户写入"
        if privileged and writable_by_group:
            return f"系统级任务程序权限 {item.mode} 允许组写入"
        if wrong_owner:
            return f"系统级任务程序属主为 {item.owner}，并非 root"
        return ""

    @staticmethod
    def _inline_interpreter(item: AutoStartItem) -> str:
        base = Path(item.program).name.lower()
        if base in INTERPRETERS and any(arg in INLINE_FLAGS for arg in item.arguments[:2]):
            return f"解释器 {base} 使用内联参数 {item.arguments[0] if item.arguments else ''}"
        return ""

    @staticmethod
    def _recommendations(item: AutoStartItem) -> List[str]:
        advice: List[str] = []
        ids = {hit.rule_id for hit in item.hits}
        if "R01" in ids:
            advice.append("核对程序来源；无法确认时不要执行，并用官方安装包重新安装。")
        if "R02" in ids:
            advice.append("将合法程序迁移到受保护的标准应用目录，并核查临时目录中的同名文件。")
        if "R03" in ids or "R08" in ids:
            advice.append("逐项审查命令参数，重点确认下载地址、解码内容和内联脚本的真实用途。")
        if "R04" in ids:
            advice.append("确认持续重启是否为业务所需；非必要时关闭 KeepAlive 或 RunAtLoad。")
        if "R05" in ids:
            advice.append("将修改时间与近期软件安装、升级记录进行比对。")
        if "R06" in ids:
            advice.append("修复文件属主与写权限，确保高权限任务不能被普通用户篡改。")
        if "R07" in ids:
            advice.append("非 Apple 程序不应使用 com.apple.* 标签；核对其来源与签名主体。")
        if not advice:
            advice.append("保留为当前基线，后续扫描关注路径、签名或哈希变化。")
        return advice

    def evaluate(self, item: AutoStartItem) -> AutoStartItem:
        item.hits = []
        if item.sign_status in {"unsigned", "invalid", "missing"}:
            self._add(item, "R01", f"签名状态为 {item.sign_status}", item.program)

        if item.program.startswith(TEMP_PREFIXES) or is_hidden_path(item.program):
            self._add(item, "R02", "程序位于临时目录或隐藏目录", item.program)

        raw_line = str(item.raw.get("line", "")) if item.raw else ""
        command_lower = f"{item.command} {raw_line}".lower()
        matched = [label for pattern, label in SUSPICIOUS_PATTERNS if pattern.lower() in command_lower]
        if matched:
            self._add(item, "R03", "命令中发现高风险执行模式", "、".join(matched))

        if item.run_at_load and item.keep_alive:
            self._add(item, "R04", "RunAtLoad 与 KeepAlive 同时启用", "RunAtLoad=true; KeepAlive=true")

        reference_time = self.now if self.now is not None else time.time()
        if item.mtime and 0 <= reference_time - item.mtime < self.recent_days * 86400:
            self._add(item, "R05", f"文件在最近 {self.recent_days} 天内修改", str(item.mtime))

        permission_reason = self._permission_risk(item)
        if permission_reason:
            self._add(item, "R06", permission_reason, f"owner={item.owner}; mode={item.mode}")

        if item.label.startswith("com.apple.") and item.sign_status != "apple":
            self._add(item, "R07", "使用 Apple 命名空间但程序不具备 Apple 签名", item.label)

        inline_reason = self._inline_interpreter(item)
        if inline_reason:
            self._add(item, "R08", inline_reason, item.command)

        if item.sign_status in {"apple", "valid"}:
            self._add(item, "W01", "程序具有可信代码签名", item.signer or item.sign_status)

        item.score = max(0, min(100, sum(hit.weight for hit in item.hits)))
        item.level = "HIGH" if item.score >= self.high_threshold else "MEDIUM" if item.score >= self.medium_threshold else "LOW"
        item.recommendations = self._recommendations(item)
        return item

    def evaluate_all(self, items: Iterable[AutoStartItem]) -> List[AutoStartItem]:
        return sorted((self.evaluate(item) for item in items), key=lambda item: (-item.score, item.label, item.config_path))
