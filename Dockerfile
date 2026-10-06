FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /app

COPY app/dnsreplay ./dnsreplay
COPY tests ./tests

# Build-time sanity: everything must byte-compile before the image ships.
RUN python -m compileall -q dnsreplay tests \
    && useradd --system --uid 10001 --no-create-home appuser

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=12 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8080')+'/healthz',timeout=3)" || exit 1

CMD ["python", "-m", "dnsreplay.server"]
