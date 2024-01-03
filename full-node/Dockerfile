FROM rust:1 AS builder
LABEL maintainer "Pierre Krieger <pierre.krieger1708@gmail.com>"

ARG TARGET

COPY ./.. /build
WORKDIR /build

RUN apt-get update && apt-get install -y musl-tools
RUN rustup target add $TARGET
RUN cargo build --target $TARGET --package smoldot-full-node --release --verbose
RUN mv ./target/$TARGET/release/full-node ./full-node


FROM alpine:latest
LABEL maintainer "Pierre Krieger <pierre.krieger1708@gmail.com>"

COPY --from=builder /build/full-node /usr/local/bin

EXPOSE 30333
ENTRYPOINT ["/usr/local/bin/full-node"]
