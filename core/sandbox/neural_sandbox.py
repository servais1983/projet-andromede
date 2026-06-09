#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Projet Andromède — Neural Sandbox
Isolation réelle des processus via resource.setrlimit + psutil.
"""

import logging
import os
import resource
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import psutil

logger = logging.getLogger(__name__)


@dataclass
class SandboxProfile:
    max_cpu_seconds: int = 5
    max_memory_bytes: int = 64 * 1024 * 1024
    max_file_size_bytes: int = 1 * 1024 * 1024
    max_open_files: int = 20
    max_processes: int = 1
    wall_timeout_seconds: float = 10.0


@dataclass
class SandboxResult:
    success: bool
    stdout: str
    stderr: str
    exit_code: Optional[int]
    cpu_time_ms: float
    peak_memory_bytes: int
    wall_time_ms: float
    killed_reason: Optional[str]
    pid: Optional[int]
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class NeuralSandbox:
    """Bac à sable système réel avec isolation au niveau noyau."""

    def __init__(self, profile: Optional[SandboxProfile] = None):
        self.profile = profile or SandboxProfile()
        self.stats = {"executions": 0, "killed_timeout": 0,
                      "killed_memory": 0, "successful": 0}
        logger.info("Neural Sandbox init — cpu=%ds mem=%dMB",
                    self.profile.max_cpu_seconds,
                    self.profile.max_memory_bytes // 1024 // 1024)

    def _make_preexec_fn(self):
        p = self.profile
        def preexec():
            resource.setrlimit(resource.RLIMIT_CPU,
                               (p.max_cpu_seconds, p.max_cpu_seconds))
            resource.setrlimit(resource.RLIMIT_AS,
                               (p.max_memory_bytes, p.max_memory_bytes))
            resource.setrlimit(resource.RLIMIT_FSIZE,
                               (p.max_file_size_bytes, p.max_file_size_bytes))
            resource.setrlimit(resource.RLIMIT_NOFILE,
                               (p.max_open_files, p.max_open_files))
            try:
                resource.setrlimit(resource.RLIMIT_NPROC,
                                   (p.max_processes, p.max_processes))
            except (ValueError, resource.error):
                pass
            os.setsid()
        return preexec

    def run_command(self, cmd: List[str], stdin_data: bytes = b"",
                    env: Optional[Dict[str, str]] = None) -> SandboxResult:
        self.stats["executions"] += 1
        start_wall = time.monotonic()
        peak_memory = 0
        killed_reason: Optional[str] = None
        proc = None
        psutil_proc = None
        safe_env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp"}

        # stdin : PIPE si on a des données, DEVNULL sinon
        stdin_mode = subprocess.PIPE if stdin_data else subprocess.DEVNULL

        try:
            proc = subprocess.Popen(
                cmd, stdin=stdin_mode, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=safe_env,
                preexec_fn=self._make_preexec_fn(), close_fds=True,
            )
            psutil_proc = psutil.Process(proc.pid)

            # Envoyer stdin_data si nécessaire (non bloquant)
            if stdin_data:
                try:
                    proc.stdin.write(stdin_data)
                    proc.stdin.close()
                except BrokenPipeError:
                    pass

            # Boucle de surveillance
            while proc.poll() is None:
                elapsed = time.monotonic() - start_wall
                if elapsed > self.profile.wall_timeout_seconds:
                    killed_reason = "timeout"
                    self.stats["killed_timeout"] += 1
                    break
                try:
                    mem = psutil_proc.memory_info().rss
                    if mem > peak_memory:
                        peak_memory = mem
                    if mem > self.profile.max_memory_bytes:
                        killed_reason = "memory"
                        self.stats["killed_memory"] += 1
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break
                time.sleep(0.05)

            if killed_reason or proc.poll() is None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    try:
                        proc.kill()
                    except Exception:
                        pass

            out, err = b"", b""
            try:
                out, err = proc.communicate(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
            except ValueError:
                # stdin déjà fermé
                if proc.stdout:
                    out = proc.stdout.read()
                if proc.stderr:
                    err = proc.stderr.read()

            exit_code = proc.returncode
            wall_ms = (time.monotonic() - start_wall) * 1000
            cpu_ms = 0.0
            try:
                if psutil_proc:
                    t = psutil_proc.cpu_times()
                    cpu_ms = (t.user + t.system) * 1000
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            success = (exit_code == 0 and killed_reason is None)
            if success:
                self.stats["successful"] += 1

            return SandboxResult(
                success=success,
                stdout=out.decode("utf-8", errors="replace")[:16384],
                stderr=err.decode("utf-8", errors="replace")[:4096],
                exit_code=exit_code, cpu_time_ms=cpu_ms,
                peak_memory_bytes=peak_memory, wall_time_ms=wall_ms,
                killed_reason=killed_reason, pid=proc.pid if proc else None,
            )
        except FileNotFoundError as e:
            return SandboxResult(
                success=False, stdout="", stderr=f"Commande introuvable: {e}",
                exit_code=-1, cpu_time_ms=0, peak_memory_bytes=0,
                wall_time_ms=(time.monotonic() - start_wall) * 1000,
                killed_reason=None, pid=None,
            )
        except Exception as e:
            logger.exception("Erreur sandbox: %s", e)
            return SandboxResult(
                success=False, stdout="", stderr=str(e), exit_code=-1,
                cpu_time_ms=0, peak_memory_bytes=0,
                wall_time_ms=(time.monotonic() - start_wall) * 1000,
                killed_reason=None, pid=None,
            )

    def run_python_snippet(self, code: str) -> SandboxResult:
        restricted = SandboxProfile(max_cpu_seconds=3, max_memory_bytes=32*1024*1024,
                                    wall_timeout_seconds=5.0)
        sandbox = NeuralSandbox(restricted)
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False,
                                         prefix="andromede_sbx_") as f:
            f.write(code)
            tmp = f.name
        try:
            return sandbox.run_command(["python3", "-I", tmp])
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass

    def analyze_file_safely(self, filepath: str) -> SandboxResult:
        return self.run_command(["file", "--mime-type", "-b", filepath])

    def get_status(self) -> Dict[str, Any]:
        return {
            "status": "operational",
            "profile": {"max_cpu_seconds": self.profile.max_cpu_seconds,
                        "max_memory_mb": self.profile.max_memory_bytes // 1024 // 1024,
                        "wall_timeout_seconds": self.profile.wall_timeout_seconds},
            "stats": self.stats,
            "isolation_mechanisms": [
                "resource.setrlimit (RLIMIT_CPU, RLIMIT_AS, RLIMIT_FSIZE, RLIMIT_NPROC)",
                "os.setsid — nouveau groupe de processus",
                "os.killpg — kill récursif du groupe",
                "psutil — surveillance mémoire temps réel",
                "env minimal — PATH=/usr/bin:/bin",
            ],
        }
