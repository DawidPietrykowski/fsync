use std::time::Duration;
use std::{env, fs, thread};

use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

const DEFAULT_FILE_DIR: &str = "data";
const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9876";

struct HttpHeader {
    name: String,
    data: String,
}

struct HttpRequest {
    protocol: String,
    path: String,
    request_type: RequestType,
    headers: Vec<HttpHeader>,
    data: Vec<u8>,
}

struct HttpResponse {
    protocol: String,
    code: HttpCode,
    headers: Vec<HttpHeader>,
    data: Vec<u8>,
}

impl HttpResponse {
    pub fn from_stream(stream: &mut TcpStream) -> HttpResponse {
        let mut http_buffer = [0; 1024];
        let received = stream.read(&mut http_buffer).unwrap();
        let request = str::from_utf8(&http_buffer[0..received]).unwrap();
        let mut lines = request.lines();
        let first_line = lines.next().unwrap();
        let mut request_elements = first_line.split_whitespace();
        let protocol = request_elements.next().unwrap().to_string();
        let code: HttpCode = request_elements.next().unwrap().into();
        let mut headers = vec![];
        for header in &mut lines {
            if header.is_empty() {
                break;
            }
            if let Some((name, data)) = header.split_once(' ') {
                headers.push(HttpHeader {
                    name: name.to_string(),
                    data: data.to_string(),
                });
            }
        }
        let data = lines.map(|line| line.as_bytes()).fold(
            Vec::<u8>::new(),
            |mut acc: Vec<u8>, n: &[u8]| {
                acc.append(&mut n.to_vec());
                acc.push('\n' as u8);
                acc
            },
        );

        HttpResponse {
            protocol,
            headers,
            data,
            code,
        }
    }
    pub fn encode(self) -> Vec<u8> {
        let mut res = vec![];
        res.append(&mut self.protocol.into_bytes());
        res.push(' ' as u8);
        res.append(&mut self.code.to_string().into_bytes());
        res.push('\n' as u8);
        for header in self.headers {
            res.append(&mut header.name.to_string().into_bytes());
            res.push(':' as u8);
            res.push(' ' as u8);
            res.append(&mut header.data.to_string().into_bytes());
            res.push('\n' as u8);
        }
        res.push('\n' as u8);
        res.append(&mut self.data.clone());
        res
    }
}

#[derive(PartialEq, Debug)]
enum HttpCode {
    NotFound,
    Ok,
}

impl HttpCode {
    pub fn to_string(self) -> String {
        let code = match self {
            HttpCode::NotFound => 404,
            HttpCode::Ok => 200,
        };
        let string = match self {
            HttpCode::NotFound => "Not found",
            HttpCode::Ok => "Ok",
        };
        format!("{} {}", code, string)
    }
}

impl From<u32> for HttpCode {
    fn from(value: u32) -> Self {
        match value {
            200 => HttpCode::Ok,
            404 => HttpCode::NotFound,
            _ => unimplemented!(),
        }
    }
}

impl From<&str> for HttpCode {
    fn from(value: &str) -> Self {
        HttpCode::from(value.parse::<u32>().unwrap())
    }
}

enum RequestType {
    Get,
    Post,
    Unknown,
}

impl RequestType {
    fn to_string(self) -> String {
        match self {
            RequestType::Get => "GET".to_owned(),
            RequestType::Post => "POST".to_owned(),
            RequestType::Unknown => panic!(),
        }
    }
}

impl From<&str> for RequestType {
    fn from(value: &str) -> Self {
        match value {
            "GET" => RequestType::Get,
            "POST" => RequestType::Post,
            _ => RequestType::Unknown,
        }
    }
}

impl HttpRequest {
    pub fn from_stream(stream: &mut TcpStream) -> HttpRequest {
        let mut http_buffer = [0; 1024];
        let received = stream.read(&mut http_buffer).unwrap();
        let request = str::from_utf8(&http_buffer[0..received]).unwrap();
        let mut lines = request.lines();
        let first_line = lines.next().unwrap();
        let mut request_elements = first_line.split_whitespace();
        let request_type = RequestType::from(request_elements.next().unwrap());
        let path = request_elements
            .next()
            .unwrap()
            .strip_prefix("/")
            .unwrap()
            .to_string();
        let protocol = request_elements.next().unwrap().to_string();
        let mut headers = vec![];
        for header in &mut lines {
            if header.is_empty() {
                break;
            }
            if let Some((name, data)) = header.split_once(' ') {
                headers.push(HttpHeader {
                    name: name.to_string(),
                    data: data.to_string(),
                });
            }
        }
        let data = lines.map(|line| line.as_bytes()).fold(
            Vec::<u8>::new(),
            |mut acc: Vec<u8>, n: &[u8]| {
                acc.append(&mut n.to_vec());
                acc.push('\n' as u8);
                acc
            },
        );

        HttpRequest {
            protocol,
            path,
            request_type,
            headers,
            data,
        }
    }

    fn encode(self) -> Vec<u8> {
        let mut res = vec![];
        res.append(&mut self.request_type.to_string().into_bytes());
        res.push(' ' as u8);
        res.append(&mut self.path.to_string().into_bytes());
        res.push(' ' as u8);
        res.append(&mut self.protocol.into_bytes());
        res.push('\n' as u8);
        for header in self.headers {
            res.append(&mut header.name.to_string().into_bytes());
            res.push(':' as u8);
            res.push(' ' as u8);
            res.append(&mut header.data.to_string().into_bytes());
            res.push('\n' as u8);
        }
        res.push('\n' as u8);
        res.append(&mut self.data.clone());
        res
    }
}

fn handle_client(mut stream: TcpStream, file_directory_path: String) {
    let request = HttpRequest::from_stream(&mut stream);

    let file_dir = Path::new(&file_directory_path);
    let file_path = file_dir.join(Path::new(&request.path));

    match request.request_type {
        RequestType::Get => {
            if request.path.is_empty() {
                println!("Received request for file list");
                // list all files
                let data = fs::read_dir(file_dir)
                    .unwrap()
                    .filter(|f| f.is_ok())
                    .map(|f| f.unwrap())
                    .filter(|f| f.path().is_file())
                    .map(|f| f.path())
                    .fold(Vec::<u8>::new(), |mut acc: Vec<u8>, n: PathBuf| {
                        let relative_path = n.strip_prefix(file_dir).unwrap();
                        let mut bytes = relative_path.to_str().unwrap().as_bytes().to_vec();
                        println!("returning: {:?}", bytes);
                        acc.append(&mut bytes);
                        acc.push('\n' as u8);
                        acc
                    });
                let response = HttpResponse {
                    protocol: request.protocol,
                    code: HttpCode::Ok,
                    headers: vec![HttpHeader {
                        name: "Content-Type".to_string(),
                        data: "text/plain".to_string(),
                    }],
                    data,
                };
                stream.write(&response.encode()).unwrap();
            } else {
                println!("Received GET request for file: {}", request.path);
                let response = if let Ok(file_contents) = fs::read(file_path) {
                    HttpResponse {
                        protocol: request.protocol,
                        code: HttpCode::Ok,
                        headers: vec![HttpHeader {
                            name: "Content-Type".to_string(),
                            data: "text/plain".to_string(),
                        }],
                        data: file_contents,
                    }
                } else {
                    HttpResponse {
                        protocol: request.protocol,
                        code: HttpCode::NotFound,
                        headers: vec![],
                        data: vec![],
                    }
                };
                stream.write(&response.encode()).unwrap();
            }
        }
        RequestType::Post => {
            println!("Received POST request for file: {}", request.path);
            fs::write(file_path, request.data).unwrap();
            let response = HttpResponse {
                protocol: request.protocol,
                code: HttpCode::Ok,
                headers: vec![],
                data: vec![],
            };
            stream.write(&response.encode()).unwrap();
        }
        _ => {}
    }

    stream.flush().unwrap();
}

enum Mode {
    Server,
    Client,
}

fn send_http_request(addr: &str, request: HttpRequest) -> HttpResponse {
    let mut socket = TcpStream::connect(addr).unwrap();
    let sent = socket.write(&request.encode()).unwrap();
    println!("sent {} bytes", sent);
    socket.flush().unwrap();
    HttpResponse::from_stream(&mut socket)
}

fn main() {
    // get cli arguments
    let mut args_iter = env::args().skip(1);
    let mode = args_iter.next().map_or(Mode::Server, |m| match m.as_str() {
        "s" => Mode::Server,
        "c" => Mode::Client,
        value => panic!("Unexpected mode: {}", value),
    });
    let path = args_iter.next();

    // fill missing config from env vars and defaults
    let file_directory_path =
        path.unwrap_or(env::var("FILE_DIR").unwrap_or(DEFAULT_FILE_DIR.to_owned()));
    let bind_addr = env::var("BIND_ADDR").unwrap_or(DEFAULT_BIND_ADDR.to_owned());

    match mode {
        Mode::Server => {
            let listener = TcpListener::bind(bind_addr.clone()).unwrap();

            println!("Started listening at: {}", bind_addr);

            for stream in listener.incoming() {
                handle_client(stream.unwrap(), file_directory_path.clone());
            }
        }
        Mode::Client => {
            let list_request = HttpRequest {
                protocol: "HTTP/1.1".to_owned(),
                path: "/".to_owned(),
                request_type: RequestType::Get,
                headers: vec![],
                data: vec![],
            };
            let addr = "127.0.0.1:9876";
            let response = send_http_request(addr, list_request);
            let mut files: Vec<String> = vec![];
            println!("bytes: {:?}", response.data.clone());
            let mut data_iter = response.data.iter();
            loop {
                let line_bytes: Vec<u8> = (&mut data_iter)
                    .take_while(|c| **c != ('\n' as u8))
                    .map(|c| *c)
                    .collect();
                if line_bytes.is_empty() {
                    break;
                }
                files.push(String::from_utf8(line_bytes).unwrap());
            }
            for file in &files {
                println!("Downloading file: {}", file);
                let contents_request = HttpRequest {
                    protocol: "HTTP/1.1".to_owned(),
                    path: "/".to_owned() + &file,
                    request_type: RequestType::Get,
                    headers: vec![],
                    data: vec![],
                };
                let response = send_http_request(addr, contents_request);
                let file_path = PathBuf::from(&file_directory_path).join(file);
                fs::write(&file_path, response.data).unwrap();
                println!("Written file: {:?}", file_path);
            }

            // sync indefinietly
            loop {
                thread::sleep(Duration::from_secs(1));
                println!("Syncing files to server");
                for file in &files {
                    println!("Sending file to server: {}", file);
                    let file_path = PathBuf::from(&file_directory_path).join(file);
                    let data = fs::read(&file_path).unwrap();
                    let contents_request = HttpRequest {
                        protocol: "HTTP/1.1".to_owned(),
                        path: "/".to_owned() + &file,
                        request_type: RequestType::Post,
                        headers: vec![],
                        data,
                    };
                    let response = send_http_request(addr, contents_request);
                    assert_eq!(response.code, HttpCode::Ok);
                    println!("File update successfull");
                }
            }
        }
    }
}
