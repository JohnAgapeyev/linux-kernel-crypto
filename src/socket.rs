use nix::sys::socket::{
    accept, bind, recv, send, setsockopt, socket, sockopt::AlgSetKey, AddressFamily, AlgAddr,
    MsgFlags, SockFlag, SockType,
};
use nix::sys::uio::{readv, writev};

use std::io::{IoSlice, IoSliceMut, Read, Result, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

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
        Ok(recv(self.fd.as_raw_fd(), buf, MsgFlags::empty())?)
    }
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> Result<usize> {
        Ok(readv(self.fd.as_fd(), bufs)?)
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
    pub fn new(salg_type: &str, salg_name: &str) -> Result<Self> {
        let fd = socket(
            AddressFamily::Alg,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None,
        )?;

        let addr = AlgAddr::new(salg_type, salg_name);

        bind(fd.as_raw_fd(), &addr)?;

        Ok(Self { fd })
    }
    pub fn set_key(&self, key: Vec<u8>) -> Result<()> {
        Ok(setsockopt(&self.fd, AlgSetKey::default(), &key)?)
    }
}

impl Iterator for SocketGenerator {
    type Item = Socket;

    fn next(&mut self) -> Option<Self::Item> {
        let fd = accept(self.fd.as_raw_fd()).ok()?;
        Some(Self::Item {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
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
        let mut sg = SocketGenerator::new("hash", "sha256").unwrap();
        let child = sg.next().unwrap();
        assert!(child.fd.as_raw_fd() > 0);
    }

    #[test]
    fn read_write_hash() {
        let hash_input = [0u8; 0];

        let mut sg = SocketGenerator::new("hash", "sha256").unwrap();

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
            let mut sg = SocketGenerator::new("hash", "sha256").unwrap();
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

        let mut sg = SocketGenerator::new("rng", "stdrng").unwrap();
        //You have to seed the algorithm, not the instance, even if the seedsize is zero!
        sg.set_key(rng_seed.to_vec()).unwrap();

        let mut kernel_rng = sg.next().unwrap();
        assert!(kernel_rng.fd.as_raw_fd() > 0);

        kernel_rng.read(&mut buf).unwrap();

        assert!(buf != init_buf);
    }
}
