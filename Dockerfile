FROM python:3.12-slim

# liboqs build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build libssl-dev git \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs from source (required for ML-DSA-65)
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cd /tmp/liboqs \
    && mkdir build && cd build \
    && cmake -GNinja -DBUILD_SHARED_LIBS=ON .. \
    && ninja && ninja install \
    && ldconfig \
    && rm -rf /tmp/liboqs

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY lattice_keeper.py .

# PQC key storage
VOLUME ["/data/pqc_keys"]

EXPOSE 8765 9090

CMD ["python", "lattice_keeper.py"]
