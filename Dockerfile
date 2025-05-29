FROM rust:1.87 as builder
WORKDIR /usr/src/myapp
COPY . .
RUN cargo install --path .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/fsync /usr/local/bin/fsync
WORKDIR /app
CMD ["fsync"]
