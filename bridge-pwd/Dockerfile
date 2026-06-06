FROM alpine:3.22.4

RUN apk add socat

ENTRYPOINT socat TCP-LISTEN:80,fork TCP:password-mgr:80
