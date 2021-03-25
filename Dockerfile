#############      builder       #############
FROM golang:1.15.4 AS builder

ARG TARGETS=dev

WORKDIR /go/src/github.com/mandelsoft/kubelink
COPY . .

RUN make $TARGETS

############# base
FROM alpine:3.11.3 AS base

#############      kubelink     #############
FROM base AS kubelink

RUN apk add iptables  wireguard-tools iputils  tcpdump  curl
COPY --from=builder /go/bin/kubelink /kubelink

WORKDIR /

ENTRYPOINT ["/kubelink"]
