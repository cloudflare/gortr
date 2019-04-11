ARG src_uri=github.com/cloudflare/gortr/cmd/gortr

FROM golang:alpine as builder
ARG src_uri

RUN apk --update --no-cache add git && \
    go get -u $src_uri

FROM alpine:latest as keygen

RUN apk --update --no-cache add openssl
RUN openssl ecparam -genkey -name prime256v1 -noout -outform pem > private.pem

FROM alpine:latest
ARG src_uri

RUN apk --update --no-cache add ca-certificates && \
    adduser -S -D -H -h / rtr
USER rtr

COPY --from=builder /go/bin/gortr /
COPY cmd/gortr/cf.pub /
COPY --from=keygen /private.pem /private.pem
ENTRYPOINT ["./gortr"]
