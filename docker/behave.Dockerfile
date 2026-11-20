# Behavioural inspector image. Build context is this directory:
#   docker build -f docker/behave.Dockerfile -t hashvault-behave:local docker
# The host scanner does not build or run this image. Tests do not need it.
# torch and transformers are installed here, not in the scanner environment.

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    HF_HOME=/work/hf

RUN useradd --create-home --uid 10001 behave \
    && mkdir -p /opt/hashvault /work \
    && chown behave:behave /work

RUN pip install --no-cache-dir "torch" "transformers" "safetensors" "numpy"

COPY behave.py /opt/hashvault/behave.py

USER behave
WORKDIR /work
ENTRYPOINT ["python", "/opt/hashvault/behave.py"]
