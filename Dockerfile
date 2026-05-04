# Listener-only container. The listener is pure stdlib + optional
# boto3 (for --s3-bucket); cryptography and maxminddb live in the
# generators / replay tool, not in this image.
FROM python:3.11-slim

RUN useradd --system --create-home --uid 1000 canary
USER canary
WORKDIR /home/canary

COPY --chown=canary:canary canary_listener.py ./

# Install boto3 only -- the listener will exit cleanly with a clear
# message if --s3-bucket is set without it.
RUN pip install --no-cache-dir --user boto3

ENV PATH=/home/canary/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

# TCP-level healthcheck rather than an HTTP route. Adding /healthz
# would be a tell that this is a canary listener; opening the port
# is enough to confirm the process is alive.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import socket,sys; s=socket.socket(); s.settimeout(3); sys.exit(0 if s.connect_ex(('127.0.0.1',8080))==0 else 1)"

ENTRYPOINT ["python", "canary_listener.py"]
CMD ["--bind=0.0.0.0", "--port=8080"]
