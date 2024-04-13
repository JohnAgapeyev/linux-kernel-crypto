//use libc::{sockaddr_alg, AF_ALG};
use libc::*;

use std::io;
use std::iter::zip;
use std::mem;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::ptr;

pub unsafe fn fill_addr(salg_type: &[u8], salg_name: &[u8]) -> sockaddr_alg {
    assert!(salg_type.len() <= 14);
    assert!(salg_name.len() <= 64);
    let mut addr = sockaddr_alg {
        salg_family: AF_ALG as u16,
        salg_feat: 0u32,
        salg_mask: 0u32,
        salg_type: [0u8; 14],
        salg_name: [0u8; 64],
    };
    for (dest, src) in zip(addr.salg_type.iter_mut(), salg_type.iter().take(14)) {
        *dest = *src
    }
    for (dest, src) in zip(addr.salg_name.iter_mut(), salg_name.iter().take(64)) {
        *dest = *src
    }
    addr
}

pub unsafe fn create_socket(salg_type: &[u8], salg_name: &[u8]) -> io::Result<OwnedFd> {
    let sock = match libc::socket(AF_ALG, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) {
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

pub unsafe fn create_socket_instance<'fd>(sock: BorrowedFd<'fd>) -> io::Result<OwnedFd> {
    match libc::accept(sock.as_raw_fd(), ptr::null_mut(), ptr::null_mut()) {
        -1 => Err(io::Error::last_os_error()),
        fd => Ok(OwnedFd::from_raw_fd(fd)),
    }
}

pub struct Socket {
    pub fd: OwnedFd,
}

#[cfg(test)]
mod sock_tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn it_works() {
        unsafe {
            let sock = create_socket(b"hash", b"sha256").unwrap();
            let child = create_socket_instance(sock.as_fd()).unwrap();
            assert!(child.as_raw_fd() > 0);
        }
    }
}
