"""
Gunicorn configuration — Projet Andromède
Usage: gunicorn -c gunicorn.conf.py "src.app:app"
"""
import os
import multiprocessing

# ── Binding ───────────────────────────────────────────────────────────────────
host = os.environ.get("HOST", "0.0.0.0")
port = os.environ.get("PORT", "5625")
bind = f"{host}:{port}"

# ── Workers ───────────────────────────────────────────────────────────────────
workers = int(os.environ.get("GUNICORN_WORKERS", multiprocessing.cpu_count() * 2 + 1))
worker_class = "sync"
worker_connections = 1000
timeout = int(os.environ.get("GUNICORN_TIMEOUT", 120))
keepalive = 5

# ── Logging ───────────────────────────────────────────────────────────────────
loglevel = os.environ.get("LOG_LEVEL", "info")
accesslog = "-"   # stdout
errorlog  = "-"   # stderr
access_log_format = '%(h)s "%(r)s" %(s)s %(b)s %(D)sµs'

# ── Security ─────────────────────────────────────────────────────────────────
limit_request_line   = 4096
limit_request_fields = 100
forwarded_allow_ips  = os.environ.get("FORWARDED_IPS", "127.0.0.1")

# ── Process naming ────────────────────────────────────────────────────────────
proc_name = "andromede"

# ── Hooks ─────────────────────────────────────────────────────────────────────
def on_starting(server):
    server.log.info("🌌 Andromède starting — workers=%s bind=%s", workers, bind)

def worker_exit(server, worker):
    server.log.info("Worker %s exited", worker.pid)
