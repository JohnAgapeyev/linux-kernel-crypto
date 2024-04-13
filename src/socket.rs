//use libc::{sockaddr_alg, AF_ALG};
use libc::*;

use std::io;
use std::mem;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

pub fn fill_addr(salg_type: &[u8], salg_name: &[u8]) -> sockaddr_alg {
    sockaddr_alg {
        salg_family: AF_ALG as u16,
        salg_feat: 0u32,
        salg_mask: 0u32,
        salg_type: <[u8; 14]>::try_from(salg_type).unwrap(),
        salg_name: <[u8; 64]>::try_from(salg_name).unwrap(),
    }
}

pub unsafe fn create_socket(salg_type: &[u8], salg_name: &[u8]) -> io::Result<OwnedFd> {
    let sock = match libc::socket(AF_ALG, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) {
        -1 => panic!("{}", io::Error::last_os_error().to_string()),
        fd => OwnedFd::from_raw_fd(fd),
    };

    let addr = fill_addr(salg_type, salg_name);

    match libc::bind(
        sock.as_raw_fd(),
        &addr as *const sockaddr_alg as *const sockaddr,
        mem::size_of_val(&addr).try_into().unwrap(),
    ) {
        -1 => return Err(io::Error::last_os_error()),
        _ => (),
    }

    Ok(sock)
}

pub struct Socket {
    pub fd: OwnedFd,
}
