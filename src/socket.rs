use libc::{c_void, sockaddr_alg, AF_ALG, SOCK_CLOEXEC, SOCK_SEQPACKET};
//use libc::*;
use nix::sys::socket::{
    accept, msghdr, send, setsockopt, sockaddr, sockopt::AlgSetKey, AlgAddr, MsgFlags,
    SockProtocol, SockType,
};
use nix::sys::uio::writev;

use std::io::{self, IoSlice, IoSliceMut, Read, Result, Write};
use std::iter::zip;
use std::mem;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::ptr;

pub fn send_msg<'fd>(sock: BorrowedFd<'fd>, bufs: &mut [IoSlice<'_>], flags: i32) -> Result<usize> {
    let mhdr = msghdr {
        msg_name: ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: bufs.as_mut_ptr() as *mut libc::iovec,
        msg_iovlen: bufs.len(),
        msg_control: ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };

    unsafe {
        match libc::sendmsg(sock.as_raw_fd(), ptr::addr_of!(mhdr), flags) {
            -1 => Err(io::Error::last_os_error()),
            sz => Ok(sz as usize),
        }
    }
}

pub fn recv_msg<'fd>(
    sock: BorrowedFd<'fd>,
    bufs: &mut [IoSliceMut<'_>],
    flags: i32,
) -> Result<usize> {
    //TODO: We're not returning this or asking for input data, do we need to care about that?
    let mut mhdr = msghdr {
        msg_name: ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: bufs.as_mut_ptr() as *mut libc::iovec,
        msg_iovlen: bufs.len(),
        msg_control: ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    dbg!(bufs.len());
    dbg!(&bufs);
    dbg!(&flags);

    let ret = unsafe {
        match libc::recvmsg(sock.as_raw_fd(), ptr::addr_of_mut!(mhdr), flags) {
            -1 => Err(io::Error::last_os_error()),
            sz => Ok(sz as usize),
        }
    };

    dbg!(bufs.len());
    dbg!(&bufs);
    dbg!(&flags);
    dbg!(&ret);

    ret
}

pub fn fill_addr(salg_type: &[u8], salg_name: &[u8]) -> sockaddr_alg {
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

#[derive(Debug)]
pub struct Socket {
    fd: OwnedFd,
}

impl Socket {
    pub fn set_key(&self, key: Vec<u8>) -> Result<()> {
        Ok(setsockopt(&self.fd, AlgSetKey::default(), &key)?)
    }
}

impl Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        unsafe {
            match libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0i32,
            ) {
                -1 => Err(io::Error::last_os_error()),
                sz => Ok(sz as usize),
            }
        }
    }
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> Result<usize> {
        unsafe {
            match libc::readv(
                self.fd.as_raw_fd(),
                bufs.as_mut_ptr() as *mut libc::iovec,
                bufs.len().try_into().unwrap(),
            ) {
                -1 => Err(io::Error::last_os_error()),
                sz => Ok(sz as usize),
            }
        }
    }
}
impl Write for Socket {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        Ok(send(self.fd.as_raw_fd(), buf, MsgFlags::empty())?)
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> Result<usize> {
        Ok(writev(&self.fd, bufs)?)
    }
}

#[derive(Debug)]
pub struct SocketGenerator {
    fd: OwnedFd,
}

impl SocketGenerator {
    pub fn new(salg_type: &[u8], salg_name: &[u8]) -> Result<Self> {
        let sock = unsafe {
            match libc::socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0) {
                -1 => return Err(io::Error::last_os_error()),
                fd => OwnedFd::from_raw_fd(fd),
            }
        };

        let addr = fill_addr(salg_type, salg_name);

        if unsafe {
            libc::bind(
                sock.as_raw_fd(),
                &addr as *const sockaddr_alg as *const sockaddr,
                mem::size_of_val(&addr).try_into().unwrap(),
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd: sock })
    }
    pub fn set_key(&self, key: Vec<u8>) -> Result<()> {
        Ok(setsockopt(&self.fd, AlgSetKey::default(), &key)?)
    }
}

impl Iterator for SocketGenerator {
    type Item = Socket;

    fn next(&mut self) -> Option<Self::Item> {
        Some(Socket {
            fd: unsafe { OwnedFd::from_raw_fd(accept(self.fd.as_raw_fd()).ok()?) },
        })
    }
}

#[cfg(test)]
mod sock_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::os::fd::AsFd;

    #[test]
    fn it_works() {
        let mut sg = SocketGenerator::new(b"hash", b"sha256").unwrap();
        let child = sg.next().unwrap();
        assert!(child.fd.as_raw_fd() > 0);
    }

    #[test]
    fn read_write_hash() {
        let hash_input = [0u8; 0];

        let mut sg = SocketGenerator::new(b"hash", b"sha256").unwrap();

        let mut kernel_hasher = sg.next().unwrap();
        assert!(kernel_hasher.fd.as_raw_fd() > 0);

        let mut kernel_hash = [0u8; 32];
        kernel_hasher.write(&hash_input).unwrap();
        kernel_hasher.read(&mut kernel_hash).unwrap();

        let code_hash: [u8; 32] = Sha256::digest(&hash_input).into();

        assert_eq!(kernel_hash, code_hash);
    }

    #[test]
    fn read_write_hash_vectored() {
        let mut inputs = Vec::new();

        for i in 0..100 {
            inputs.push([i; 17]);
        }

        let mut hash_input = Vec::new();
        for i in 0..100 {
            hash_input.push(IoSlice::new(&inputs[i]));
        }

        let mut kernel_hasher: Socket = {
            let mut sg = SocketGenerator::new(b"hash", b"sha256").unwrap();
            let child = sg.next().unwrap();
            assert!(child.fd.as_raw_fd() > 0);
            child
        };

        kernel_hasher.write_vectored(&hash_input).unwrap();

        let mut kernel_hash = [0u8; 32];
        let mut kernel_outputs = Vec::new();

        for chunk in kernel_hash.chunks_exact_mut(1) {
            kernel_outputs.push(IoSliceMut::new(chunk))
        }

        kernel_hasher.read_vectored(&mut kernel_outputs).unwrap();

        let mut code_hasher = Sha256::new();
        for chunk in &hash_input {
            code_hasher.update(&**chunk);
        }
        let code_hash: [u8; 32] = code_hasher.finalize().into();

        assert_eq!(kernel_hash, code_hash);
    }

    #[test]
    fn rng_works() {
        let init_buf = [0u8; 133];
        let mut buf = init_buf.clone();
        let rng_seed = [0u8; 0];

        let mut sg = SocketGenerator::new(b"rng", b"stdrng").unwrap();
        //You have to seed the algorithm, not the instance, even if the seedsize is zero!
        sg.set_key(rng_seed.to_vec()).unwrap();

        let mut kernel_rng = sg.next().unwrap();
        assert!(kernel_rng.fd.as_raw_fd() > 0);

        kernel_rng.read(&mut buf).unwrap();

        assert!(buf != init_buf);
    }
}
