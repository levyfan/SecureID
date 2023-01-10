FROM ubuntu:latest
ENV GIT_SSL_NO_VERIFY=1

WORKDIR /usr/src/SecureID
COPY . .

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        make \
        cmake \
        gcc \
        g++ \
        clang \
        libgmp-dev \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/herumi/mcl.git --depth 1 --branch v1.76 && cd mcl && \
    mkdir build && cd build && \
    cmake -DCMAKE_CXX_COMPILER=clang++ .. && make install

RUN mkdir build && cd build && \
    cmake .. && make && make test