## `fsync`

A blazingly fast :fire::fire::fire: note sync server and client.

When running the client it will first download the latest versions of note files. Next it will keep periodically (every 5s) sending the updated files to the server.

#### Text editor?
Bring your own
#### File manager?
`ls` ? `mv` ?
#### Collaboration?
The app is very secure. If you run 2 clients at once you lose data because the app was designed for a single client. Any additional connection means someone is trying to get your data.
#### Authorization?
Very low prio. Might come at some point.
#### Directories?
I don't know what that is

## client

### Install
```
cargo install --git https://github.com/DawidPietrykowski/fsync.git
```
### Run
```
FILE_DIR=notes CONNECT_ADDR='example.com:443' fsync c
```

## server
### Docker compose
The image is on Docker Hub so you can just run the compose up command:
```
docker compose up -d
```
### cli
```
cargo install --git https://github.com/DawidPietrykowski/fsync.git
FILE_DIR=notes BIND_ADDR='0.0.0.0:80' fsync s
```
