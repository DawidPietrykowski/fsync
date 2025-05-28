FROM rust:1.87 as builder
WORKDIR /usr/src/myapp
COPY . .
RUN cargo install --path .

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/fsync /usr/local/bin/fsync
WORKDIR /app
CMD ["fsync"]
