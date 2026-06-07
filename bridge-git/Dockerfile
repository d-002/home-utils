FROM alpine:3.22.4

RUN apk add --no-cache socat

ENTRYPOINT socat TCP-LISTEN:22,fork TCP:git-server:22
