# syntax=docker/dockerfile:1.7

FROM golang:1.26-bookworm AS builder
RUN apt-get update && apt-get install -y llvm-15 clang-15 git make
ENV CLANG=clang-15
WORKDIR /build/
ADD go.mod go.sum ./
RUN go mod download
ADD . .
RUN git submodule update --init
RUN --mount=type=secret,id=oixcloud_dns_auth_private_key,required=true \
    --mount=type=secret,id=oixcloud_subscription_hmac_key,required=true \
    OIXCLOUD_DNS_AUTH_PRIVATE_KEY="$(cat /run/secrets/oixcloud_dns_auth_private_key)" \
    OIXCLOUD_DNS_AUTH_REQUIRE_PRIVATE_KEY=1 \
    OIXCLOUD_SUBSCRIPTION_HMAC_KEY="$(cat /run/secrets/oixcloud_subscription_hmac_key)" \
    OIXCLOUD_SUBSCRIPTION_REQUIRE_HMAC_KEY=1 \
    make OUTPUT=dae GOFLAGS="-buildvcs=false" CC=clang CGO_ENABLED=0

FROM alpine
RUN mkdir -p /usr/local/share/dae/
RUN mkdir -p /etc/dae/
RUN wget -O /usr/local/share/dae/geoip.dat https://github.com/v2fly/geoip/releases/latest/download/geoip.dat
RUN wget -O /usr/local/share/dae/geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
COPY --from=builder /build/dae /usr/local/bin
COPY --from=builder /build/install/empty.dae /etc/dae/config.dae
RUN chmod 0600 /etc/dae/config.dae

CMD ["dae"]
ENTRYPOINT ["dae", "run", "-c", "/etc/dae/config.dae"]
