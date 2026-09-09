FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . /src
RUN python3 -m venv /opt/fts && /opt/fts/bin/pip install --no-cache-dir .
CMD ["/bin/bash", "-lc", "/opt/fts/bin/python -m unittest discover -s tests -v && cd /tmp && /opt/fts/bin/fts --config /tmp/missing.toml catalog && /opt/fts/bin/fuzz-pipeline --config /tmp/missing.toml doctor"]
