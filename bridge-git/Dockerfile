FROM alpine:3.22.4

RUN apk add socat

ENTRYPOINT socat TCP-LISTEN:22,fork TCP:git-server:22
