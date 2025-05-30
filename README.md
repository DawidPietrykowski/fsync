## `fsync`

A blazingly fast :fire::fire::fire: note sync server and client.

When running the client it will first download the latest versions of note files. Next it will keep periodically (every 5s) sending the updated files to the server.

###### Text editor?
Bring your own
###### Note manager?
`ls` ?
###### Collaboration?
The app is very secure. If you run 2 clients at once you lose data because the app was designed for a single client. Any additional connection means someone is trying to get your data.
###### Directories?
And why would you need that

## client

#### Install
```
cargo install --git https://github.com/DawidPietrykowski/fsync.git
```
#### Run
```
FILE_DIR=notes CONNECT_ADDR='https://example.com' fsync c
```

## server
#### Docker compose
```
docker buildx build -t fsync .
docker compose up -d
```
#### cli
```
cargo install --git https://github.com/DawidPietrykowski/fsync.git
FILE_DIR=notes BIND_ADDR='0.0.0.0:80' fsync s
```
