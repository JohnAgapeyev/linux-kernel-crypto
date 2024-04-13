//use libc::{sockaddr_alg, AF_ALG};
use libc::*;

use std::io;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

pub fn fill_addr_unchecked(salg_type: &[u8], salg_name: &[u8]) -> sockaddr_alg {
    sockaddr_alg {
        salg_family: AF_ALG as u16,
        salg_feat: 0u32,
        salg_mask: 0u32,
        salg_type: <[u8; 14]>::try_from(salg_type).unwrap(),
        salg_name: <[u8; 64]>::try_from(salg_name).unwrap(),
    }
}

pub unsafe fn create_socket() -> io::Result<OwnedFd> {
    let fd = libc::socket(AF_ALG, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    match fd {
        -1 => Err(io::Error::last_os_error()),
        _ => Ok(OwnedFd::from_raw_fd(fd)),
    }
}

pub struct Socket {
    pub fd: OwnedFd,
}
