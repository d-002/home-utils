FROM alpine:3.22.4

RUN apk add --no-cache socat

ENTRYPOINT socat TCP-LISTEN:80,fork TCP:password-mgr:8080
