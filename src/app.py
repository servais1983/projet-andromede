#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Projet Andromède - Interface Web (production-ready)
"""

import os
import sys
import tempfile
import json
import time
import logging
from pathlib import Path
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename
import pandas as pd

# ── Path setup ──────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIR))
from src.main import CSVScanner

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Optional AI modules ───────────────────────────────────────────────────────
try:
    from core.ai.astra_assistant import AstraAssistant
    from core.ai.orion_core import OrionCore
    from ui.starmap_visualizer import StarMapVisualizer
    AI_MODULES_AVAILABLE = True
except ImportError:
    AI_MODULES_AVAILABLE = False
    logger.info("AI modules unavailable — running in basic mode")

# ── App factory ───────────────────────────────────────────────────────────────
def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(ROOT_DIR / "templates"),
        static_folder=str(ROOT_DIR / "static"),
    )

    # Configuration (env vars with safe defaults for dev)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or _require_secret(),
        UPLOAD_FOLDER=os.environ.get("UPLOAD_FOLDER", tempfile.mkdtemp(prefix="andromede_")),
        MAX_CONTENT_LENGTH=int(os.environ.get("MAX_UPLOAD_MB", 16)) * 1024 * 1024,
        ENV=os.environ.get("FLASK_ENV", "production"),
        DEBUG=os.environ.get("FLASK_DEBUG", "false").lower() == "true",
    )

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # ── AI init ───────────────────────────────────────────────────────────────
    astra = orion = starmap = None
    if AI_MODULES_AVAILABLE:
        try:
            astra = AstraAssistant()
            orion = OrionCore()
            starmap = StarMapVisualizer()
            logger.info("AI modules initialised")
        except Exception as exc:
            logger.warning("AI init failed: %s", exc)

    # ── Simple in-memory rate limiter ─────────────────────────────────────────
    _rate_store: dict = {}

    def rate_limit(max_per_minute: int = 30):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                ip = request.remote_addr or "unknown"
                now = time.time()
                window = _rate_store.setdefault(ip, [])
                # purge old entries
                _rate_store[ip] = [t for t in window if now - t < 60]
                if len(_rate_store[ip]) >= max_per_minute:
                    return jsonify(error="Too many requests"), 429
                _rate_store[ip].append(now)
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    # ── Helpers ───────────────────────────────────────────────────────────────
    def allowed_file(filename: str) -> bool:
        return "." in filename and filename.rsplit(".", 1)[1].lower() == "csv"

    def _ai_status():
        return {
            "astra": astra.get_stats() if astra else {"status": "unavailable"},
            "orion": orion.get_status() if orion else {"status": "unavailable"},
            "starmap": {"status": "available" if starmap else "unavailable"},
        }

    def _categorise(threats):
        cats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for t in threats:
            cats[t.get("severity", "info").lower()] = cats.get(t.get("severity", "info").lower(), 0) + 1
        return cats

    def _top_threats(threats, n=5):
        return [
            {
                "name": t.get("rule_name", "Unknown"),
                "description": t.get("description", ""),
                "severity": t.get("severity", "info"),
                "score": t.get("score", 0),
                "location": t.get("location", ""),
            }
            for t in sorted(threats, key=lambda x: x.get("score", 0), reverse=True)[:n]
        ]

    # ── Routes ────────────────────────────────────────────────────────────────
    @app.get("/")
    def index():
        return render_template("index.html", astra_available=astra is not None,
                               ai_modules_status=_ai_status())

    @app.get("/chat")
    def chat():
        return render_template("chat.html", astra_available=astra is not None,
                               project_name="Projet Andromède")

    @app.get("/healthz")
    def health():
        """Kubernetes / load-balancer health check."""
        return jsonify(status="ok", timestamp=datetime.utcnow().isoformat()), 200

    @app.get("/status")
    def system_status():
        return jsonify(system="operational", ai_modules=_ai_status(),
                       scanner="available", timestamp=datetime.utcnow().isoformat())

    @app.post("/upload")
    @rate_limit(max_per_minute=20)
    def upload_file():
        if "file" not in request.files:
            return jsonify(success=False, error="No file part"), 400
        f = request.files["file"]
        if not f.filename:
            return jsonify(success=False, error="No file selected"), 400
        if not allowed_file(f.filename):
            return jsonify(success=False, error="Only CSV files are accepted"), 400

        filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secure_filename(f.filename)}"
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        f.save(file_path)

        try:
            t0 = time.time()
            scanner = CSVScanner()
            results = scanner.scan_file(file_path)

            # Optional AI enrichment (first 5 threats only)
            ai_insights = []
            if orion and results.get("results"):
                for r in results["results"][:5]:
                    if r.get("match"):
                        try:
                            ai_insights.append({
                                "threat": r["match"],
                                "ai_analysis": orion.analyze_threat(r["match"]),
                            })
                        except Exception:
                            pass

            # HTML report
            report_url = None
            try:
                rp = scanner.generate_html_report(results)
                report_url = f"/report/{Path(rp).name}"
            except Exception as exc:
                logger.warning("Report generation failed: %s", exc)

            return jsonify(
                success=True,
                filename=f.filename,
                threats_detected=len(results.get("results", [])),
                risk_score=results.get("total_score", 0),
                risk_level=results.get("risk_level", "Unknown"),
                processing_time=round(time.time() - t0, 2),
                report_url=report_url,
                ai_insights=ai_insights,
                summary={
                    "total_rows_analyzed": results.get("rows_analyzed", 0),
                    "threats_by_severity": _categorise(results.get("results", [])),
                    "top_threats": _top_threats(results.get("results", [])),
                },
            )
        finally:
            try:
                os.remove(file_path)
            except OSError:
                pass

    @app.post("/ai-analysis")
    @rate_limit(max_per_minute=30)
    def ai_analysis():
        if not astra:
            return jsonify(success=False, error="AI assistant not available"), 503
        data = request.get_json(silent=True) or {}
        message = (data.get("message") or "").strip()
        if not message:
            return jsonify(success=False, error="Empty message"), 400
        try:
            response = astra.chat(message, data.get("session_id", "web_default"))
            return jsonify(success=True, response=response,
                           session_id=data.get("session_id", "web_default"),
                           timestamp=datetime.utcnow().isoformat())
        except Exception as exc:
            logger.error("AI error: %s", exc)
            return jsonify(success=False, error="AI processing error"), 500

    @app.get("/report/<path:filename>")
    def serve_report(filename):
        # Security: restrict to basename, no path traversal
        safe = Path(filename).name
        for search_dir in [Path.cwd(), Path(tempfile.gettempdir())]:
            candidate = search_dir / safe
            if candidate.exists():
                return send_file(str(candidate), as_attachment=False)
        return jsonify(error="Report not found"), 404

    # ── Error handlers ────────────────────────────────────────────────────────
    @app.errorhandler(413)
    def too_large(_e):
        return jsonify(success=False,
                       error=f"File too large. Max: {app.config['MAX_CONTENT_LENGTH']//1024//1024} MB"), 413

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify(success=False, error="Not found"), 404

    @app.errorhandler(500)
    def internal(_e):
        logger.exception("Internal server error")
        return jsonify(success=False, error="Internal server error"), 500

    return app


def _require_secret() -> str:
    """Warn loudly in dev if SECRET_KEY is not set; refuse to start in production."""
    env = os.environ.get("FLASK_ENV", "production")
    if env == "production":
        raise RuntimeError(
            "SECRET_KEY environment variable must be set in production. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    logger.warning("SECRET_KEY not set — using insecure dev default")
    return "dev-insecure-key-do-not-use-in-production"


# ── Entrypoint (dev only) ─────────────────────────────────────────────────────
app = create_app()

if __name__ == "__main__":
    logger.info("Starting Andromède dev server on http://localhost:5625")
    logger.warning("Use Gunicorn for production: gunicorn 'src.app:app'")
    app.run(host="127.0.0.1", port=5625, debug=app.config["DEBUG"])
