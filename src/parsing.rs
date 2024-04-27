use itertools::Itertools;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Error, ErrorKind, Result};

const CRYPTO_FILE_PATH: &str = "/proc/crypto";

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
enum EntryKey {
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
enum TransformType {
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
struct TransformBase {
    name: String,
    driver: String,
    module: String,
    priority: String,
    ref_cnt: u64,
    self_test: bool,
    internal: bool,
    ttype: TransformType,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct AeadTransform {
    base: TransformBase,
    is_async: bool,
    block_size: u64,
    iv_size: u64,
    max_auth_size: u64,
    gen_iv: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct AsyncCompressionTransform(TransformBase);
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct AsyncHashTransform {
    base: TransformBase,
    is_async: bool,
    block_size: u64,
    digest_size: u64,
}
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct PublicKeyTransform(TransformBase);
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct CipherTransform {
    base: TransformBase,
    block_size: u64,
    min_key_size: u64,
    max_key_size: u64,
}
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct CompressionTransform(TransformBase);
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct KeyAgreementProtocolPrimitiveTransform(TransformBase);
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct LinearSymmetricKeyTransform {
    base: TransformBase,
    block_size: u64,
    min_key_size: u64,
    max_key_size: u64,
    iv_size: u64,
    chunk_size: u64,
    state_size: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct RngTransform {
    base: TransformBase,
    seed_size: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct SyncCompressionTransform(TransformBase);

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct SyncHashTransform {
    base: TransformBase,
    block_size: u64,
    digest_size: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct SymmetricKeyCipherTransform {
    base: TransformBase,
    is_async: bool,
    block_size: u64,
    min_key_size: u64,
    max_key_size: u64,
    iv_size: u64,
    chunk_size: u64,
    walk_size: u64,
    state_size: u64,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
enum Transform {
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

fn chunk_entries(contents: impl BufRead) -> Result<Vec<Vec<String>>> {
    contents
        .lines()
        .group_by(|line| line.as_ref().is_ok_and(|l| !l.is_empty()))
        .into_iter()
        .filter_map(|(key, group)| key.then_some(group.collect()))
        .collect()
}

fn trim_line(line: &str) -> Result<(&str, &str)> {
    let tokens: Vec<&str> = line.split(':').collect();

    match tokens.len() {
        2 => Ok((tokens[0].trim(), tokens[1].trim())),
        _ => Err(Error::from(ErrorKind::InvalidData)),
    }
}

fn parse_entries(contents: impl BufRead) -> Result<HashMap<String, HashMap<EntryKey, String>>> {
    let entries = chunk_entries(contents)?;

    let mut entry_lookup: HashMap<String, HashMap<EntryKey, String>> = HashMap::new();

    for entry in entries {
        let mut line_lookup: HashMap<EntryKey, String> = HashMap::new();
        for line in entry {
            let (key, value) = trim_line(&line)?;
            line_lookup.insert(EntryKey::try_from(key)?, value.to_string());
        }

        let entry_name: String = line_lookup
            .get(&EntryKey::Name)
            .ok_or(Error::from(ErrorKind::InvalidData))?
            .to_string();

        entry_lookup.insert(entry_name, line_lookup);
    }

    Ok(entry_lookup)
}

fn build_transform(rows: &HashMap<EntryKey, String>) -> Result<bool> {
    let mut is_async: Option<bool> = None;
    let mut block_size: Option<u64> = None;
    let mut chunk_size: Option<u64> = None;
    let mut digest_size: Option<u64> = None;
    let mut driver: Option<String> = None;
    let mut gen_iv: Option<String> = None;
    let mut internal: Option<bool> = None;
    let mut iv_size: Option<u64> = None;
    let mut max_key_size: Option<u64> = None;
    let mut max_auth_size: Option<u64> = None;
    let mut min_key_size: Option<u64> = None;
    let mut module: Option<String> = None;
    let mut name: Option<String> = None;
    let mut priority: Option<String> = None;
    let mut ref_cnt: Option<u64> = None;
    let mut seed_size: Option<u64> = None;
    let mut self_test: Option<bool> = None;
    let mut state_size: Option<u64> = None;
    let mut ttype: Option<TransformType> = None;
    let mut walk_size: Option<u64> = None;

    for (key, value) in rows {
        match key {
            EntryKey::Async => {
                is_async = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::BlockSize => {
                block_size = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::ChunkSize => {
                chunk_size = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::DigestSize => {
                digest_size = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::Driver => {
                driver = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::GenIv => {
                if value != "<none>" {
                    return Err(Error::from(ErrorKind::InvalidData));
                }
                gen_iv = Some(value.clone());
            }
            EntryKey::Internal => {
                internal = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::IvSize => {
                iv_size = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::MaxKeySize => {
                max_key_size = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::MaxAuthSize => {
                max_auth_size = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::MinKeySize => {
                min_key_size = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::Module => {
                module = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::Name => {
                name = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::Priority => {
                priority = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::RefCnt => {
                ref_cnt = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::SeedSize => {
                seed_size = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::SelfTest => {
                self_test = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::StateSize => {
                state_size = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
            EntryKey::Type => {
                ttype = Some(value.as_str().try_into()?);
            }
            EntryKey::WalkSize => {
                walk_size = Some(
                    value
                        .parse()
                        .map_err(|_| Error::from(ErrorKind::InvalidData))?,
                );
            }
        };
    }

    let base: TransformBase = TransformBase {
        name: name.ok_or(Error::from(ErrorKind::InvalidData))?,
        driver: driver.ok_or(Error::from(ErrorKind::InvalidData))?,
        module: module.ok_or(Error::from(ErrorKind::InvalidData))?,
        priority: priority.ok_or(Error::from(ErrorKind::InvalidData))?,
        ref_cnt: ref_cnt.ok_or(Error::from(ErrorKind::InvalidData))?,
        self_test: self_test.ok_or(Error::from(ErrorKind::InvalidData))?,
        internal: internal.ok_or(Error::from(ErrorKind::InvalidData))?,
        ttype: ttype.ok_or(Error::from(ErrorKind::InvalidData))?,
    };

    //match ttype {
    //    TransformType::Aead => (),
    //    TransformType::AsyncCompression => (),
    //    TransformType::AsyncHash => (),
    //    TransformType::PublicKeyCipher => (),
    //    TransformType::Cipher => (),
    //    TransformType::Compression => (),
    //    TransformType::KeyAgreementProtocolPrimitive => (),
    //    TransformType::LinearSymmetricKeyCipher => (),
    //    TransformType::Rng => (),
    //    TransformType::SyncCompression => (),
    //    TransformType::SyncHash => (),
    //    TransformType::SymmetricKeyCipher => (),
    //};

    Ok(true)
}

#[cfg(test)]
mod parsing_tests {
    use super::*;

    #[test]
    fn entry_chunking() {
        let f = BufReader::new(File::open(CRYPTO_FILE_PATH).unwrap());
        let output = chunk_entries(f).unwrap();
        assert!(!output.is_empty());
    }

    #[test]
    fn line_stripping() {
        let (key, value) = trim_line("driver       : cryptd(__generic-gcm-aesni)").unwrap();
        assert_eq!(key, "driver");
        assert_eq!(value, "cryptd(__generic-gcm-aesni)");
    }

    #[test]
    fn parsing_to_map() {
        let f = BufReader::new(File::open(CRYPTO_FILE_PATH).unwrap());
        let output = parse_entries(f).unwrap();
        assert!(!output.is_empty());

        for (entry_key, entry_map) in output {
            assert!(!entry_key.is_empty());
            assert!(!entry_map.is_empty());

            assert!(entry_map.contains_key(&EntryKey::Name));
            assert!(entry_map.contains_key(&EntryKey::Driver));
            assert!(entry_map.contains_key(&EntryKey::Module));
            assert!(entry_map.contains_key(&EntryKey::Priority));
            assert!(entry_map.contains_key(&EntryKey::RefCnt));
            assert!(entry_map.contains_key(&EntryKey::SelfTest));
            assert!(entry_map.contains_key(&EntryKey::Internal));
            assert!(entry_map.contains_key(&EntryKey::Type));
        }
    }

    #[test]
    fn can_construct_transform() {
        let _ = AeadTransform {
            base: TransformBase {
                name: "".to_string(),
                driver: "".to_string(),
                module: "".to_string(),
                priority: "".to_string(),
                ref_cnt: 0u64,
                self_test: true,
                internal: false,
                ttype: TransformType::Aead,
            },
            is_async: true,
            block_size: 1u64,
            iv_size: 12u64,
            max_auth_size: 16u64,
            gen_iv: None,
        };
    }
}
