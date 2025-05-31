use std::{
    io::{Error, ErrorKind},
    os::raw::{c_int, c_uint, c_void},
    ptr,
};

use constants::*;

#[allow(unused)]
mod constants {
    pub const ALG_SET_KEY: u32 = 1;
    pub const ALG_SET_IV: u32 = 2;
    pub const ALG_SET_OP: u32 = 3;
    pub const ALG_SET_AEAD_ASSOCLEN: u32 = 4;
    pub const ALG_SET_AEAD_AUTHSIZE: u32 = 5;
    pub const ALG_SET_DRBG_ENTROPY: u32 = 6;
    pub const ALG_SET_KEY_BY_KEY_SERIAL: u32 = 7;
    pub const ALG_OP_DECRYPT: u32 = 0;
    pub const ALG_OP_ENCRYPT: u32 = 1;
    pub const SOCK_SEQPACKET: u32 = 5;
    pub const AES_KEY_LEN: u32 = 16;
    pub const AF_ALG: u16 = 38;
    pub const SOL_ALG: u32 = 279;
    pub const SHA256_DIG_LEN: usize = 32;
}

#[allow(unused)]
unsafe extern "C" {
    fn socket(domain: c_int, type_: c_int, protocol: c_int) -> c_int;
    fn bind(sockfd: c_int, addr: *const sockaddr_alg, addrlen: c_uint) -> c_int;
    fn setsockopt(
        fd: c_int,
        level: c_int,
        optname: c_int,
        optval: *const c_void,
        optlen: c_uint,
    ) -> c_int;
    fn accept(fd: c_int, addr: *const sockaddr_alg, addrlen: *const c_uint) -> c_int;
    fn write(fd: c_int, buf: *const c_void, count: usize) -> c_int;
    fn read(fd: c_int, buf: *const c_void, count: usize) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn __errno_location() -> *mut c_int;
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct sockaddr_alg {
    salg_family: u16,
    salg_type: [u8; 14],
    salg_feat: u32,
    salg_mask: u32,
    salg_name: [u8; 64],
}

impl sockaddr_alg {
    fn new(alg_type: &str, alg_name: &str) -> sockaddr_alg {
        let alg_type = alg_type.as_bytes();
        let alg_name = alg_name.as_bytes();

        let mut salg_type = [0u8; 14];
        salg_type[..alg_type.len()].copy_from_slice(alg_type);
        let mut salg_name = [0u8; 64];
        salg_name[..alg_name.len()].copy_from_slice(alg_name);

        sockaddr_alg {
            salg_family: AF_ALG,
            salg_type,
            salg_feat: 0,
            salg_mask: 0,
            salg_name,
        }
    }
}

#[repr(C)]
#[allow(non_camel_case_types, unused)]
struct af_alg_iv {
    ivlen: u32,
    iv: [u8],
}

fn print_err() -> Error {
    let errno = unsafe { *__errno_location() };
    if errno == 0 {
        return Error::new(ErrorKind::Other, "no error");
    }
    Error::from_raw_os_error(errno)
}

enum ErrorType {
    NonZero,
    LessThanZero,
}

fn wrap_error<T: PartialEq<i32> + PartialOrd<i32>>(
    res: T,
    err_type: ErrorType,
) -> Result<T, Error> {
    let is_error = match err_type {
        ErrorType::NonZero => res != 0,
        ErrorType::LessThanZero => res < 0,
    };
    if is_error { Err(print_err()) } else { Ok(res) }
}

fn wrap_error_empty<T: PartialEq<i32> + PartialOrd<i32>>(
    res: T,
    err_type: ErrorType,
) -> Result<(), Error> {
    if let Err(e) = wrap_error(res, err_type) {
        return Err(e);
    } else {
        return Ok(());
    }
}

fn open_socket() -> Result<i32, Error> {
    let socket_fd = unsafe { socket(AF_ALG as c_int, SOCK_SEQPACKET as c_int, 0) };
    wrap_error(socket_fd, ErrorType::LessThanZero)
}

fn bind_socket(socket_fd: i32, alg_type: &str, alg_name: &str) -> Result<(), Error> {
    let sa = sockaddr_alg::new(alg_type, alg_name);
    let sockaddr_ptr: *const sockaddr_alg = &sa;
    let err = unsafe { bind(socket_fd, sockaddr_ptr, size_of::<sockaddr_alg>() as u32) };
    wrap_error_empty(err, ErrorType::NonZero)
}

pub fn run_op() {
    let socket_fd = open_socket().unwrap();
    bind_socket(socket_fd, "hash", "sha256").unwrap();
    // let key = [1u8; AES_KEY_LEN as usize];
    // let err = setsockopt(
    //     socket_fd,
    //     SOL_ALG as c_int,
    //     ALG_SET_KEY as c_int,
    //     key.as_ptr().cast(),
    //     key.len() as c_uint,
    // );

    let data = b"text\n";
    let result = perform_operation(socket_fd, data).unwrap();
    result.iter().for_each(|b| print!("{:x?}", b));
}

fn perform_operation(socket_fd: i32, data: &[u8; 5]) -> Result<[u8; 32], Error> {
    let result = [0u8; SHA256_DIG_LEN];
    let size = 0;

    let accept_fd = unsafe { accept(socket_fd, ptr::null(), &size) };
    if let Err(e) = wrap_error(accept_fd, ErrorType::LessThanZero) {
        return Err(e);
    }

    let write_len = unsafe { write(accept_fd, data.as_ptr().cast(), data.len()) };
    if let Err(e) = wrap_error(write_len, ErrorType::LessThanZero) {
        return Err(e);
    }
    assert_eq!(write_len, data.len() as c_int);

    let read_len = unsafe { read(accept_fd, result.as_ptr().cast(), result.len()) };
    if let Err(e) = wrap_error(read_len, ErrorType::LessThanZero) {
        return Err(e);
    }
    assert_eq!(read_len, SHA256_DIG_LEN as c_int);

    unsafe { close(accept_fd) };
    unsafe { close(socket_fd) };

    Ok(result)
}
