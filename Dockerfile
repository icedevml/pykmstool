FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:531.0.0-slim

RUN apt-get update && \
    apt-get install -y python3-venv && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /tmp/.venv

COPY requirements.txt /tmp/requirements.txt
RUN /tmp/.venv/bin/pip3 install --no-cache-dir -r /tmp/requirements.txt

COPY . /app
RUN cp -r /tmp/.venv /app/.venv

WORKDIR /app
ENTRYPOINT ["/bin/bash", "./entrypoint.sh"]
