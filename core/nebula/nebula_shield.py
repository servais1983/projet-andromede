#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Projet Andromède — Nebula Shield
Surveillance réelle des processus et connexions réseau via psutil.
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import psutil

logger = logging.getLogger(__name__)


@dataclass
class ProcessSnapshot:
    pid: int
    name: str
    status: str
    cpu_percent: float
    memory_rss_mb: float
    open_connections: int
    suspicious: bool
    reason: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class NetworkConnection:
    local_addr: str
    remote_addr: str
    status: str
    pid: int
    process_name: str
    suspicious: bool
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class SecurityBubble:
    def __init__(self):
        self._allowed_pids: Set[int] = set()
        self._blocked_pids: Set[int] = set()

    def allow(self, pid: int) -> None:
        self._allowed_pids.add(pid)

    def block(self, pid: int) -> None:
        self._blocked_pids.add(pid)
        self._allowed_pids.discard(pid)

    def is_allowed(self, pid: int) -> bool:
        return pid in self._allowed_pids

    def is_blocked(self, pid: int) -> bool:
        return pid in self._blocked_pids

    def status(self) -> Dict[str, Any]:
        return {"allowed": list(self._allowed_pids),
                "blocked": list(self._blocked_pids)}


class NebulaShield:
    """Surveillance réseau et processus temps réel via psutil."""

    SUSPICIOUS_REMOTE_PORTS = {4444, 5555, 31337, 1337, 6667, 6697, 9001, 9030}
    SUSPICIOUS_PROCESS_NAMES = {
        "nc", "ncat", "netcat", "nmap", "masscan",
        "msfconsole", "msfvenom", "sqlmap",
        "hydra", "john", "hashcat",
    }

    def __init__(self, cpu_alert_threshold: float = 90.0,
                 memory_alert_threshold_mb: float = 500.0):
        self.cpu_threshold = cpu_alert_threshold
        self.mem_threshold_mb = memory_alert_threshold_mb
        self.bubble = SecurityBubble()
        self.alerts: List[Dict[str, Any]] = []
        self.stats = {"scans": 0, "processes_inspected": 0,
                      "suspicious_processes": 0, "suspicious_connections": 0,
                      "alerts_raised": 0}
        logger.info("Nebula Shield init — cpu=%.0f%% mem=%.0fMB",
                    cpu_alert_threshold, memory_alert_threshold_mb)

    def scan_processes(self) -> List[ProcessSnapshot]:
        snapshots: List[ProcessSnapshot] = []
        self.stats["scans"] += 1

        for proc in psutil.process_iter(attrs=["pid", "name", "status",
                                               "cpu_percent", "memory_info"]):
            try:
                info = proc.info
                pid = info["pid"]
                name = info["name"] or "unknown"
                status = info["status"] or "unknown"
                cpu = info.get("cpu_percent") or 0.0
                mem_info = info.get("memory_info")
                mem_rss = (mem_info.rss / 1024 / 1024) if mem_info else 0.0

                # Connexions réseau — appel séparé (pas dispo via attrs)
                try:
                    conns = proc.net_connections() if hasattr(proc, 'net_connections') else proc.connections()
                except (psutil.AccessDenied, AttributeError, psutil.NoSuchProcess):
                    conns = []

                suspicious = False
                reason = ""

                if name.lower() in self.SUSPICIOUS_PROCESS_NAMES:
                    suspicious = True
                    reason = f"nom suspect: {name}"
                elif cpu > self.cpu_threshold:
                    suspicious = True
                    reason = f"CPU excessif: {cpu:.0f}%"
                elif mem_rss > self.mem_threshold_mb:
                    suspicious = True
                    reason = f"mémoire excessive: {mem_rss:.0f} MB"

                snap = ProcessSnapshot(
                    pid=pid, name=name, status=status,
                    cpu_percent=cpu, memory_rss_mb=round(mem_rss, 2),
                    open_connections=len(conns),
                    suspicious=suspicious, reason=reason,
                )
                snapshots.append(snap)
                self.stats["processes_inspected"] += 1

                if suspicious:
                    self.stats["suspicious_processes"] += 1
                    self._raise_alert("process", pid, name, reason)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return snapshots

    def scan_network(self) -> List[NetworkConnection]:
        connections: List[NetworkConnection] = []
        try:
            net_conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, AttributeError):
            return connections

        for conn in net_conns:
            try:
                local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                pid = conn.pid or 0
                proc_name = "unknown"
                if pid:
                    try:
                        proc_name = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                suspicious = False
                if conn.raddr and conn.raddr.port in self.SUSPICIOUS_REMOTE_PORTS:
                    suspicious = True
                    self.stats["suspicious_connections"] += 1
                    self._raise_alert("network", pid, proc_name,
                                      f"connexion port suspect {conn.raddr.port}")

                connections.append(NetworkConnection(
                    local_addr=local, remote_addr=remote,
                    status=conn.status, pid=pid,
                    process_name=proc_name, suspicious=suspicious,
                ))
            except Exception:
                continue

        return connections

    def _raise_alert(self, category: str, pid: int, name: str, reason: str) -> None:
        alert = {"category": category, "pid": pid, "process": name,
                 "reason": reason, "severity": "high" if self.bubble.is_blocked(pid) else "medium",
                 "timestamp": datetime.utcnow().isoformat()}
        self.alerts.append(alert)
        self.stats["alerts_raised"] += 1
        logger.warning("ALERTE Nebula [%s] pid=%d %s: %s", category, pid, name, reason)

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(reversed(self.alerts[-limit:]))

    def clear_alerts(self) -> int:
        n = len(self.alerts)
        self.alerts.clear()
        return n

    def system_snapshot(self) -> Dict[str, Any]:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net_io = psutil.net_io_counters()
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "cpu": {"percent": cpu, "count": psutil.cpu_count()},
            "memory": {"total_mb": round(mem.total/1024/1024, 1),
                       "used_mb": round(mem.used/1024/1024, 1),
                       "percent": mem.percent},
            "disk": {"total_gb": round(disk.total/1024**3, 1),
                     "used_gb": round(disk.used/1024**3, 1),
                     "percent": disk.percent},
            "network_io": {"bytes_sent": net_io.bytes_sent,
                           "bytes_recv": net_io.bytes_recv},
        }

    def get_status(self) -> Dict[str, Any]:
        return {"status": "operational",
                "thresholds": {"cpu_percent": self.cpu_threshold,
                               "memory_mb": self.mem_threshold_mb},
                "bubble": self.bubble.status(),
                "stats": self.stats,
                "pending_alerts": len(self.alerts)}
