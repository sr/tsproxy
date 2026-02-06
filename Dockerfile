FROM debian:bookworm
ARG TARGETARCH

WORKDIR /app

RUN apt-get update && \
    apt-get install -y ca-certificates

COPY tsproxy-$TARGETARCH /usr/bin/tsproxy

CMD ["/usr/bin/tsproxy"]
