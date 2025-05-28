### Run client
```
cargo install --path .
FILE_DIR=notes CONNECT_ADDR='https://example.com' fsync c
```

### Run server
```
docker buildx build -t fsync .
docker compose up -d
```
