FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:555.0.0-slim

RUN apt-get update && \
    apt-get install -y python3-venv && \
    rm -rf /var/lib/apt/lists/*

COPY . /app
RUN python3 -m venv /app/.venv
RUN /app/.venv/bin/pip3 install --no-cache-dir /app

WORKDIR /app
ENTRYPOINT ["/bin/bash", "./entrypoint.sh"]
