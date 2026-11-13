FROM debian:stable-slim
RUN apt-get update && apt-get install -y openssl curl tcpdump && rm -rf /var/lib/apt/lists/*
COPY ca.crt /etc/ssl/lab/ca.crt
