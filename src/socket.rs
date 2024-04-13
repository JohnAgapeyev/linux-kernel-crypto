use libc::{sockaddr_alg, AF_ALG};

pub fn fill_addr_unchecked(salg_type: &[u8], salg_name: &[u8]) -> sockaddr_alg {
    sockaddr_alg {
        salg_family: AF_ALG as u16,
        salg_feat: 0u32,
        salg_mask: 0u32,
        salg_type: <[u8; 14]>::try_from(salg_type).unwrap(),
        salg_name: <[u8; 64]>::try_from(salg_name).unwrap(),
    }
}
