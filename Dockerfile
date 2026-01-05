FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    git \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    pkg-config \
    autoconf \
    automake \
    libtool \
    wget \
    curl \
    util-linux \
    iproute2 \
    libcap2-bin \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    MALLOC_ARENA_MAX=2

WORKDIR /app
COPY . /app

RUN cd openssl-3.6.0 && \
    ./Configure && \
    make -j"$(nproc)"

RUN cd openssl-3.6.0/demos/quic/server && \
    make -j"$(nproc)"

RUN test -d /app/oqs-provider || (echo "ERROR: oqs-provider directory not found in build context"; exit 1); \
    cd /app/oqs-provider && \
    OPENSSL_INSTALL=/app/openssl-3.6.0 ./scripts/fullbuild.sh

ENV OPENSSL_CONF=/app/config/openssl-oqs.cnf \
    LD_LIBRARY_PATH=/app/openssl-3.6.0:/app/oqs-provider/_build/lib \
    OPENSSL_MODULES=/app/oqs-provider/_build/lib

RUN chmod +x /app/scripts/docker_entrypoint.sh

ENTRYPOINT ["/app/scripts/docker_entrypoint.sh"]

