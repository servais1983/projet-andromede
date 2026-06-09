# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Security: non-root user
RUN groupadd --gid 1001 andromede \
 && useradd  --uid 1001 --gid 1001 --no-create-home andromede

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application
COPY --chown=andromede:andromede . .

# Remove dev / test artefacts
RUN rm -rf tests/ *.test.py test_*.py *_test.py \
           starmap_*.html real_*.csv \
           .git .github requirements-dev.txt

# Upload temp dir owned by app user
RUN mkdir -p /tmp/andromede_uploads \
 && chown andromede:andromede /tmp/andromede_uploads

USER andromede

EXPOSE 5625

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5625/healthz')"

CMD ["gunicorn", "-c", "gunicorn.conf.py", "src.app:app"]
