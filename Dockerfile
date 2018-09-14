FROM library/ubuntu

RUN apt-get update && \
  apt-get install -y ca-certificates

COPY gortr /
COPY cf.pub /
ENTRYPOINT ["./gortr"]
