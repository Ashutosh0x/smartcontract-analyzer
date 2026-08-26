# Stage 1: Build the Rust binary
FROM rust:1.80-alpine AS builder

RUN apk add --no-cache musl-dev pkgconfig openssl-dev build-base

WORKDIR /usr/src/sentinel
COPY . .

RUN cargo build --release

# Stage 2: Minimal runner image
FROM alpine:3.19

RUN apk add --no-cache libgcc ca-certificates wget

# Install solc (example for downloading a static solc binary)
RUN wget https://github.com/ethereum/solidity/releases/download/v0.8.26/solc-static-linux -O /usr/local/bin/solc \
    && chmod +x /usr/local/bin/solc

COPY --from=builder /usr/src/sentinel/target/release/sentinel /usr/local/bin/sentinel

WORKDIR /app

ENTRYPOINT ["sentinel"]
CMD ["--help"]
