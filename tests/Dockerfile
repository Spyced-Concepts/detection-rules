# Copyright 2026 Spyced Concepts Ltd. (company number 16978283)
# SPDX-License-Identifier: Apache-2.0
FROM ubuntu:24.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends yara python3 python3-pip python3-venv \
    && python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir sigma-cli \
    && rm -rf /var/lib/apt/lists/*
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /rules
