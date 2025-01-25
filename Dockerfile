ARG ALPINE=alpine:3.21

FROM $ALPINE AS builder
WORKDIR /build

COPY ./src ./src
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

RUN apk add --no-cache rust cargo
RUN cargo build --release && cp target/release/udp-broadcast-relay-rs ./udp-broadcast-relay-rs

FROM $ALPINE
WORKDIR /runtime
COPY --from=builder /build/udp-broadcast-relay-rs .
ENTRYPOINT ["./udp-broadcast-relay-rs"]
