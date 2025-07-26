FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:531.0.0-slim

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt

COPY . /app
WORKDIR /app
VOLUME ["/root/.config/gcloud"]
ENTRYPOINT ["/bin/bash", "./entrypoint.sh"]
