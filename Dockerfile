FROM library/ubuntu

RUN apt-get update && \
  apt-get install -y ca-certificates

COPY gortr /
ENTRYPOINT ["./gortr"]
