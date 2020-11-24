FROM ubuntu:16.04


RUN apt-get update
RUN apt-get install -y --no-install-recommends \
            build-essential \
            ca-certificates \
            cmake \
            curl \
            jq \
            libclang-dev \
            pkg-config \
            protobuf-compiler \
            libssl-dev

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > ./rust.sh
RUN chmod +x ./rust.sh
RUN ./rust.sh -y
ENV PATH="/root/.cargo/bin:$PATH"

RUN rustup toolchain add nightly
RUN rustup default nightly
RUN rustup target add x86_64-fortanix-unknown-sgx --toolchain nightly
RUN rustup update
RUN cargo install fortanix-sgx-tools sgxs-tools

RUN echo '[target.x86_64-fortanix-unknown-sgx]\nrunner = "ftxsgx-runner-cargo"' > ~/.cargo/config
RUN cat ~/.cargo/config

RUN apt-get update
RUN apt-get install -y --no-install-recommends git clang

COPY . /build/
WORKDIR /build/
RUN rm -rf ./target

RUN cargo build --target=x86_64-fortanix-unknown-sgx --features=sgx

WORKDIR /build/target/x86_64-fortanix-unknown-sgx/debug/
RUN openssl genrsa -3 3072 > private.pem
RUN ftxsgx-elf2sgxs ./https-json-server --heap-size 409600 --stack-size 409600 --threads 20 --debug > /dev/null
RUN sgxs-sign ./https-json-server.sgxs ./sigstruct.bin --key ./private.pem -p 0 -v 0 > /dev/null

FROM ubuntu:16.04
WORKDIR /root/
COPY --from=0 /build/target/x86_64-fortanix-unknown-sgx/debug/https-json-server.sgxs .
COPY --from=0 /root/.cargo/bin/ftxsgx-runner .

RUN apt-get update
RUN apt-get install -y --no-install-recommends libssl-dev

CMD /root/ftxsgx-runner /root/https-json-server.sgxs