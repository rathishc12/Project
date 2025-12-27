FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    auditd \
    audispd-plugins \
    curl \
    tcpdump \
    procps \
    net-tools \
    python3 \
    python3-pip \
    yara \
    clamav \
    clamav-daemon \
    iptables \
    jq \
    diffutils \
    file \
    binutils \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install jinja2 requests

# Preload ClamAV DB (best effort)
RUN freshclam || true

COPY sandbox/entrypoint.sh /entrypoint.sh

COPY vt /vt

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
