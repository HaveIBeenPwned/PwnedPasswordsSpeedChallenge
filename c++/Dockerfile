# Building and installing
FROM ubuntu:21.10 as buildenv

RUN apt update
RUN apt -y install g++ cmake libboost-coroutine-dev libboost-program-options-dev libboost-system-dev libfmt-dev libssl-dev

COPY . /src
WORKDIR /src
RUN cmake -B /tmp/build . -DCMAKE_BUILD_TYPE=Release
RUN cmake --bulid /tmp/build
RUN cmake --build /tmp/build --target install

# The real deal
FROM ubuntu:21.10
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libboost-coroutine1.74.0 \
    libboost-program-options1.74.0 \
    libfmt7 \
    libssl1.1 \
   && rm -rf /var/lib/apt/lists/*
COPY --from=buildenv /usr/local /usr/local
