use std::io::{self, Error, ErrorKind, Result};

//TODO: Reduce the amount of public struct/member visibility exported by this module

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum EntryKey {
    Async,
    BlockSize,
    ChunkSize,
    DigestSize,
    Driver,
    GenIv,
    Internal,
    IvSize,
    MaxKeySize,
    MaxAuthSize,
    MinKeySize,
    Module,
    Name,
    Priority,
    RefCnt,
    SeedSize,
    SelfTest,
    StateSize,
    Type,
    WalkSize,
}

impl TryFrom<&str> for EntryKey {
    type Error = std::io::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "async" => Ok(EntryKey::Async),
            "blocksize" => Ok(EntryKey::BlockSize),
            "chunksize" => Ok(EntryKey::ChunkSize),
            "digestsize" => Ok(EntryKey::DigestSize),
            "driver" => Ok(EntryKey::Driver),
            "geniv" => Ok(EntryKey::GenIv),
            "internal" => Ok(EntryKey::Internal),
            "ivsize" => Ok(EntryKey::IvSize),
            "max keysize" => Ok(EntryKey::MaxKeySize),
            "maxauthsize" => Ok(EntryKey::MaxAuthSize),
            "min keysize" => Ok(EntryKey::MinKeySize),
            "module" => Ok(EntryKey::Module),
            "name" => Ok(EntryKey::Name),
            "priority" => Ok(EntryKey::Priority),
            "refcnt" => Ok(EntryKey::RefCnt),
            "seedsize" => Ok(EntryKey::SeedSize),
            "selftest" => Ok(EntryKey::SelfTest),
            "statesize" => Ok(EntryKey::StateSize),
            "type" => Ok(EntryKey::Type),
            "walksize" => Ok(EntryKey::WalkSize),
            _ => Err(Error::from(ErrorKind::InvalidData)),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum TransformType {
    Aead,
    AsyncCompression,
    AsyncHash,
    PublicKeyCipher,
    Cipher,
    Compression,
    KeyAgreementProtocolPrimitive,
    LinearSymmetricKeyCipher,
    Rng,
    SyncCompression,
    SyncHash,
    SymmetricKeyCipher,
}

impl TryFrom<&str> for TransformType {
    type Error = std::io::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "aead" => Ok(TransformType::Aead),
            "acomp" => Ok(TransformType::AsyncCompression),
            "ahash" => Ok(TransformType::AsyncHash),
            "akcipher" => Ok(TransformType::PublicKeyCipher),
            "cipher" => Ok(TransformType::Cipher),
            "compression" => Ok(TransformType::Compression),
            "kpp" => Ok(TransformType::KeyAgreementProtocolPrimitive),
            "lskcipher" => Ok(TransformType::LinearSymmetricKeyCipher),
            "rng" => Ok(TransformType::Rng),
            "scomp" => Ok(TransformType::SyncCompression),
            "shash" => Ok(TransformType::SyncHash),
            "skcipher" => Ok(TransformType::SymmetricKeyCipher),
            _ => Err(Error::from(ErrorKind::InvalidData)),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TransformBase {
    pub name: String,
    pub driver: String,
    pub module: String,
    pub priority: u64,
    pub ref_cnt: u64,
    pub self_test: bool,
    pub internal: bool,
    pub ttype: TransformType,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct AeadTransform {
    pub base: TransformBase,
    pub is_async: bool,
    pub block_size: u64,
    pub iv_size: u64,
    pub max_auth_size: u64,
    pub gen_iv: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct AsyncCompressionTransform {
    pub base: TransformBase,
}
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct AsyncHashTransform {
    pub base: TransformBase,
    pub is_async: bool,
    pub block_size: u64,
    pub digest_size: u64,
}
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct PublicKeyTransform {
    pub base: TransformBase,
}
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CipherTransform {
    pub base: TransformBase,
    pub block_size: u64,
    pub min_key_size: u64,
    pub max_key_size: u64,
}
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CompressionTransform {
    pub base: TransformBase,
}
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct KeyAgreementProtocolPrimitiveTransform {
    pub base: TransformBase,
}
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct LinearSymmetricKeyTransform {
    pub base: TransformBase,
    pub block_size: u64,
    pub min_key_size: u64,
    pub max_key_size: u64,
    pub iv_size: u64,
    pub chunk_size: u64,
    pub state_size: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct RngTransform {
    pub base: TransformBase,
    pub seed_size: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SyncCompressionTransform {
    pub base: TransformBase,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SyncHashTransform {
    pub base: TransformBase,
    pub block_size: u64,
    pub digest_size: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SymmetricKeyCipherTransform {
    pub base: TransformBase,
    pub is_async: bool,
    pub block_size: u64,
    pub min_key_size: u64,
    pub max_key_size: u64,
    pub iv_size: u64,
    pub chunk_size: u64,
    pub walk_size: u64,
    pub state_size: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Transform {
    Aead(AeadTransform),
    AsyncCompression(AsyncCompressionTransform),
    AsyncHash(AsyncHashTransform),
    PublicKeyCipher(PublicKeyTransform),
    Cipher(CipherTransform),
    Compression(CompressionTransform),
    KeyAgreementProtocolPrimitive(KeyAgreementProtocolPrimitiveTransform),
    LinearSymmetricKeyCipher(LinearSymmetricKeyTransform),
    Rng(RngTransform),
    SyncCompression(SyncCompressionTransform),
    SyncHash(SyncHashTransform),
    SymmetricKeyCipher(SymmetricKeyCipherTransform),
}
