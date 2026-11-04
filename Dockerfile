# GroundTrace — one image, two roles (see docker-compose.yml):
#   api      python -m groundtrace serve --host 0.0.0.0   (REST API + dashboard)
#   watcher  python -m groundtrace watch                  (scheduled collection + alerts)
#
# The core is standard-library only. Build with --build-arg WITH_CRAWLER=1 to
# add the optional Tor/.onion crawler dependencies (requests[socks], bs4).
FROM python:3.13-slim

ARG WITH_CRAWLER=0
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    GROUNDTRACE_DB_PATH=/data/groundtrace.db \
    DARKFEEDS_DB_PATH=/data/darkfeeds.db

WORKDIR /app
# certifi is optional for the tool (it falls back to the system trust store),
# but the image ships it: some threat-intel APIs are signed by CAs a slim
# image does not carry, and without it those lookups fail. A failed lookup is
# reported as an error rather than a clean result, so the effect is lost
# coverage rather than a wrong answer -- but lost coverage is worth avoiding.
RUN pip install --no-cache-dir certifi
COPY requirements-crawler.txt .
RUN if [ "$WITH_CRAWLER" = "1" ]; then pip install --no-cache-dir -r requirements-crawler.txt; fi

COPY groundtrace/ groundtrace/
COPY darkfeeds/ darkfeeds/

# Run unprivileged; /data is the only writable path (mount a volume there).
RUN useradd --create-home --uid 10001 groundtrace \
 && mkdir -p /data && chown groundtrace:groundtrace /data
USER groundtrace
VOLUME ["/data"]

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4).status == 200 else 1)"

# Refuses to start on 0.0.0.0 unless GROUNDTRACE_API_KEY is set — by design.
CMD ["python", "-m", "groundtrace", "serve", "--host", "0.0.0.0", "--port", "8080"]
