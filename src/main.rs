use std::time::Duration;
use std::{env, fs, io, thread};

use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};

use native_tls::TlsConnector;

const DEFAULT_FILE_DIR: &str = "data";
const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9876";
const DEFAULT_CONNECT_ADDR: &str = "127.0.0.1:9876";
const BUFFER_LEN: usize = 1024;
const CRLF: [u8; 2] = *b"\r\n";
const CRLF_CRLF: [u8; 4] = *b"\r\n\r\n";
const HTTP_PROTOCOL: &str = "HTTP/1.0";

#[derive(Clone, Debug)]
struct HttpHeader {
    name: String,
    data: String,
}

impl HttpHeader {
    fn new(name: &str, data: &str) -> HttpHeader {
        HttpHeader {
            name: name.to_owned(),
            data: data.to_owned(),
        }
    }

    fn to_string(&self) -> String {
        format!("{}: {}", self.name, self.data)
    }
}

#[derive(Clone)]
struct HttpMessage<T> {
    protocol: String,
    headers: Vec<HttpHeader>,
    data: Vec<u8>,
    message_data: T,
}

#[derive(Clone)]
struct RequestData {
    path: String,
    request_type: RequestType,
}

#[derive(Clone)]
struct ResponseData {
    code: HttpCode,
}

type HttpRequest = HttpMessage<RequestData>;
type HttpResponse = HttpMessage<ResponseData>;

trait Encodable {
    fn encode_first_line(&self, protocol: &str) -> Vec<u8>;
}

impl Encodable for RequestData {
    fn encode_first_line(&self, protocol: &str) -> Vec<u8> {
        let line = format!(
            "{} {} {}",
            self.request_type.to_string(),
            self.path,
            protocol
        );
        line.as_bytes().to_vec()
    }
}

impl Encodable for ResponseData {
    fn encode_first_line(&self, protocol: &str) -> Vec<u8> {
        let line = format!("{} {}", protocol, self.code.to_string(),);
        line.as_bytes().to_vec()
    }
}

impl<T: Encodable> HttpMessage<T> {
    fn encode(self) -> Vec<u8> {
        let mut res = vec![];
        res.append(&mut self.message_data.encode_first_line(&self.protocol).clone());
        res.extend_from_slice(&CRLF);
        for header in self.headers {
            res.append(&mut header.to_string().into_bytes());
            res.extend_from_slice(&CRLF);
        }
        res.extend_from_slice(&CRLF);
        res.append(&mut self.data.clone());
        res
    }
}

impl HttpResponse {
    pub fn from_stream<S>(mut stream: &mut S) -> HttpResponse
    where
        S: io::Read + io::Write,
    {
        let (request_line, headers, data) = decode_http_packet(&mut stream);
        let mut request_elements = request_line.split_whitespace();
        let protocol = request_elements.next().unwrap().to_string();
        let code: HttpCode = request_elements.next().unwrap().into();

        HttpResponse {
            protocol,
            headers,
            data,
            message_data: ResponseData { code },
        }
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
enum HttpCode {
    Ok = 200,
    Unauthorized = 400,
    NotFound = 404,
}

impl HttpCode {
    pub fn to_string(self) -> String {
        let code = match self {
            HttpCode::NotFound => 404,
            HttpCode::Ok => 200,
            HttpCode::Unauthorized => 400,
        };
        let string = match self {
            HttpCode::NotFound => "Not found",
            HttpCode::Ok => "Ok",
            HttpCode::Unauthorized => "Unauthorized",
        };
        format!("{} {}", code, string)
    }
}

impl From<u32> for HttpCode {
    fn from(value: u32) -> Self {
        match value {
            200 => HttpCode::Ok,
            404 => HttpCode::NotFound,
            400 => HttpCode::Unauthorized,
            _ => HttpCode::NotFound,
        }
    }
}

impl From<&str> for HttpCode {
    fn from(value: &str) -> Self {
        HttpCode::from(value.parse::<u32>().unwrap())
    }
}

#[derive(Clone, Copy)]
enum RequestType {
    Get,
    Post,
    Delete,
    Unknown,
}

impl RequestType {
    fn to_string(self) -> String {
        match self {
            RequestType::Get => "GET".to_owned(),
            RequestType::Post => "POST".to_owned(),
            RequestType::Unknown => "DELETE".to_owned(),
            RequestType::Delete => todo!(),
        }
    }
}

impl From<&str> for RequestType {
    fn from(value: &str) -> Self {
        match value {
            "GET" => RequestType::Get,
            "POST" => RequestType::Post,
            "DELETE" => RequestType::Delete,
            _ => RequestType::Unknown,
        }
    }
}

fn decode_http_packet<S>(stream: &mut S) -> (String, Vec<HttpHeader>, Vec<u8>)
where
    S: io::Read + io::Write,
{
    let mut http_buffer = vec![];
    let mut received = 0;
    loop {
        let mut tmp_buf = [0u8; BUFFER_LEN];
        let tmp_received = stream.read(&mut tmp_buf).unwrap();
        http_buffer.extend_from_slice(&tmp_buf[0..tmp_received]);
        received += tmp_received;
        let header_end_pos = http_buffer.windows(4).position(|w| w == b"\r\n\r\n");
        if header_end_pos.is_some() {
            break;
        }
    }
    let response_bytes = &http_buffer[0..received];

    let header_end_pos = response_bytes.windows(4).position(|w| w == b"\r\n\r\n");
    let header_end = header_end_pos.unwrap_or(received);
    let header_data = str::from_utf8(&response_bytes[0..header_end]).unwrap();

    let mut lines = header_data
        .lines()
        .map(|l| l.strip_suffix('\r').unwrap_or(l));

    let first_line = lines.next().unwrap();

    let headers: Vec<HttpHeader>;
    if header_end_pos.is_some() {
        headers = lines
            .filter_map(|line| {
                if let Some((name, data)) = line.split_once(": ") {
                    Some(HttpHeader {
                        name: name.to_string(),
                        data: data.to_string(),
                    })
                } else {
                    None
                }
            })
            .collect();
    } else {
        headers = vec![];
    }

    let mut body_data = response_bytes[header_end + 4..].to_vec();
    if let Some(content_length_header) = headers
        .iter()
        .find(|h| h.name.to_lowercase() == "content-length")
    {
        let content_length = content_length_header.data.parse::<usize>().unwrap();
        while body_data.len() < content_length {
            let mut tmp_buf = [0u8; BUFFER_LEN];
            let tmp_received = stream.read(&mut tmp_buf).unwrap();
            body_data.extend_from_slice(&tmp_buf[0..tmp_received]);
            received += tmp_received;
            let header_end_pos = http_buffer.windows(4).position(|w| w == CRLF_CRLF);
            if header_end_pos.is_some() {
                break;
            }
        }
    }
    (first_line.to_string(), headers, body_data)
}

impl HttpRequest {
    pub fn from_stream<S>(mut stream: &mut S) -> HttpRequest
    where
        S: io::Read + io::Write,
    {
        let (request_line, headers, data) = decode_http_packet(&mut stream);
        let mut request_elements = request_line.split_whitespace();
        let request_type = RequestType::from(request_elements.next().unwrap());
        let path_string = request_elements.next().unwrap();
        let path = path_string
            .strip_prefix("/")
            .unwrap_or(path_string)
            .to_string();
        let protocol = request_elements.next().unwrap().to_string();

        HttpRequest {
            protocol,
            headers,
            data,
            message_data: RequestData { path, request_type },
        }
    }
}

fn handle_client(mut stream: TcpStream, file_directory_path: String) {
    let request = HttpRequest::from_stream(&mut stream);

    let file_dir = Path::new(&file_directory_path);
    let file_path = file_dir.join(Path::new(&request.message_data.path));

    match request.message_data.request_type {
        RequestType::Get => {
            if request.message_data.path.is_empty() {
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
                        acc.append(&mut bytes);
                        acc.push('\n' as u8);
                        acc
                    });
                let response = HttpResponse {
                    protocol: request.protocol,
                    headers: vec![HttpHeader {
                        name: "Content-Type".to_string(),
                        data: "text/plain".to_string(),
                    }],
                    data,
                    message_data: ResponseData { code: HttpCode::Ok },
                };
                stream.write_all(&response.encode()).unwrap();
            } else {
                println!(
                    "Received GET request for file: {}",
                    request.message_data.path
                );
                let response = if let Ok(file_contents) = fs::read(file_path) {
                    HttpResponse {
                        protocol: request.protocol,
                        message_data: ResponseData { code: HttpCode::Ok },
                        headers: vec![HttpHeader {
                            name: "Content-Type".to_string(),
                            data: "text/plain".to_string(),
                        }],
                        data: file_contents,
                    }
                } else {
                    HttpResponse {
                        protocol: request.protocol,
                        message_data: ResponseData {
                            code: HttpCode::NotFound,
                        },
                        headers: vec![],
                        data: vec![],
                    }
                };
                stream.write_all(&response.encode()).unwrap();
            }
        }
        RequestType::Post => {
            println!(
                "Received POST request for file: {}",
                request.message_data.path
            );

            let mut headers = vec![];
            headers.push(HttpHeader::new("Connection", "close"));
            headers.push(HttpHeader::new("Access-Control-Allow-Origin", "*"));

            let response = if request.message_data.path.contains('/')
                || fs::write(file_path, request.data).is_err()
            {
                HttpResponse {
                    protocol: request.protocol,
                    message_data: ResponseData {
                        code: HttpCode::NotFound,
                    },
                    headers,
                    data: vec![],
                }
            } else {
                HttpResponse {
                    protocol: request.protocol,
                    message_data: ResponseData { code: HttpCode::Ok },
                    headers,
                    data: vec![],
                }
            };

            stream.write_all(&response.encode()).unwrap();
        }
        RequestType::Delete => {
            println!(
                "Received DELETE request for file: {}",
                request.message_data.path
            );

            let mut headers = vec![];
            headers.push(HttpHeader::new("Connection", "close"));
            headers.push(HttpHeader::new("Access-Control-Allow-Origin", "*"));

            let response =
                if request.message_data.path.contains('/') || fs::remove_file(file_path).is_err() {
                    HttpResponse {
                        protocol: request.protocol,
                        message_data: ResponseData {
                            code: HttpCode::NotFound,
                        },
                        headers,
                        data: vec![],
                    }
                } else {
                    HttpResponse {
                        protocol: request.protocol,
                        message_data: ResponseData { code: HttpCode::Ok },
                        headers,
                        data: vec![],
                    }
                };

            stream.write_all(&response.encode()).unwrap();
        }
        _ => {}
    }
}

enum Mode {
    Server,
    Client,
}

fn send_http_request(addr: &str, mut request: HttpRequest) -> HttpResponse {
    request.headers.push(HttpHeader::new("Connection", "close"));
    request.headers.push(HttpHeader::new("Host", addr));

    let https = addr.chars().any(|c| c.is_ascii_alphabetic());

    let mut socket = TcpStream::connect(addr).unwrap();
    if https {
        let connector = TlsConnector::new().unwrap();
        let host = addr.split(':').next().unwrap();
        let mut stream = connector.connect(host, socket).unwrap();
        stream.write_all(&request.encode()).unwrap();
        HttpResponse::from_stream(&mut stream)
    } else {
        socket.write_all(&request.encode()).unwrap();
        HttpResponse::from_stream(&mut socket)
    }
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
    let connect_addr = &env::var("CONNECT_ADDR").unwrap_or(DEFAULT_CONNECT_ADDR.to_owned());

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
                protocol: HTTP_PROTOCOL.to_owned(),
                headers: vec![],
                data: vec![],
                message_data: RequestData {
                    path: "/".to_owned(),
                    request_type: RequestType::Get,
                },
            };
            let response = send_http_request(connect_addr, list_request);
            assert_eq!(response.message_data.code, HttpCode::Ok);
            let mut files: Vec<String> = vec![];
            let mut data_iter = response.data.iter();
            loop {
                let line_bytes: Vec<u8> = (&mut data_iter)
                    .take_while(|c| **c != ('\n' as u8))
                    .map(|c| *c)
                    .collect();
                if line_bytes.is_empty() {
                    break;
                }
                let filename = String::from_utf8(line_bytes).unwrap();
                println!("Found file: {}", filename);
                files.push(filename);
            }
            for file in &files {
                println!("Downloading file: {}", file);
                let contents_request = HttpRequest {
                    protocol: HTTP_PROTOCOL.to_owned(),
                    message_data: RequestData {
                        path: format!("/{}", file),
                        request_type: RequestType::Get,
                    },
                    headers: vec![],
                    data: vec![],
                };
                let response = send_http_request(connect_addr, contents_request);
                assert_eq!(response.message_data.code, HttpCode::Ok);
                let file_path = PathBuf::from(&file_directory_path).join(file);
                println!("Writing to file: {:?}", file_path);
                fs::write(&file_path, response.data).unwrap();
            }

            let local_files: Vec<PathBuf> = fs::read_dir(&file_directory_path)
                .unwrap()
                .filter_map(|f| {
                    if let Ok(file) = f {
                        let path = file.path();
                        if path.is_file() { Some(path) } else { None }
                    } else {
                        None
                    }
                })
                .collect();

            // sync indefinietly
            loop {
                thread::sleep(Duration::from_secs(1));
                println!("Syncing files to server");
                for file in &local_files {
                    let data = fs::read(&file).unwrap();
                    let file_str = file
                        .strip_prefix(&file_directory_path)
                        .unwrap()
                        .to_str()
                        .unwrap();
                    println!("Sending file to server: {}", file_str);
                    let contents_request = HttpRequest {
                        protocol: HTTP_PROTOCOL.to_owned(),
                        headers: vec![],
                        data,
                        message_data: RequestData {
                            path: format!("/{}", file_str),
                            request_type: RequestType::Post,
                        },
                    };
                    let response = send_http_request(connect_addr, contents_request);
                    assert_eq!(response.message_data.code, HttpCode::Ok);
                    println!("File update successfull");
                }
            }
        }
    }
}
