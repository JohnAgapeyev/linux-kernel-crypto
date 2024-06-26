use itertools::Itertools;
use std::collections::HashMap;
use std::io::{BufRead, Error, ErrorKind, Result};

use crate::transform::*;

const CRYPTO_FILE_PATH: &str = "/proc/crypto";

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

fn build_transform(rows: &HashMap<EntryKey, String>) -> Result<TransformData> {
    let mut is_async: Option<bool> = None;
    let mut block_size: Option<u64> = None;
    let mut chunk_size: Option<u64> = None;
    let mut digest_size: Option<u64> = None;
    let mut driver: Option<String> = None;
    let mut gen_iv: Option<Option<String>> = None;
    let mut internal: Option<bool> = None;
    let mut iv_size: Option<u64> = None;
    let mut max_key_size: Option<u64> = None;
    let mut max_auth_size: Option<u64> = None;
    let mut min_key_size: Option<u64> = None;
    let mut module: Option<String> = None;
    let mut name: Option<String> = None;
    let mut priority: Option<u64> = None;
    let mut ref_cnt: Option<u64> = None;
    let mut seed_size: Option<u64> = None;
    let mut self_test: Option<bool> = None;
    let mut state_size: Option<u64> = None;
    let mut ttype: Option<TransformType> = None;
    let mut walk_size: Option<u64> = None;

    for (key, value) in rows {
        match key {
            EntryKey::Async => {
                is_async = match value.as_str() {
                    "yes" => Some(true),
                    "no" => Some(false),
                    _ => return Err(Error::from(ErrorKind::InvalidData)),
                };
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
                if value == "<none>" {
                    gen_iv = Some(None);
                } else {
                    gen_iv = Some(Some(value.clone()));
                }
            }
            EntryKey::Internal => {
                internal = match value.as_str() {
                    "yes" => Some(true),
                    "no" => Some(false),
                    _ => return Err(Error::from(ErrorKind::InvalidData)),
                };
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
                self_test = match value.as_str() {
                    "passed" => Some(true),
                    "unknown" => Some(false),
                    _ => return Err(Error::from(ErrorKind::InvalidData)),
                };
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

    Ok(match base.ttype {
        TransformType::Aead => TransformData::Aead(AeadTransform {
            base,
            is_async: is_async.ok_or(Error::from(ErrorKind::InvalidData))?,
            block_size: block_size.ok_or(Error::from(ErrorKind::InvalidData))?,
            iv_size: iv_size.ok_or(Error::from(ErrorKind::InvalidData))?,
            max_auth_size: max_auth_size.ok_or(Error::from(ErrorKind::InvalidData))?,
            gen_iv: gen_iv.ok_or(Error::from(ErrorKind::InvalidData))?,
        }),
        TransformType::AsyncCompression => {
            TransformData::AsyncCompression(AsyncCompressionTransform { base })
        }
        TransformType::AsyncHash => TransformData::AsyncHash(AsyncHashTransform {
            base,
            is_async: is_async.ok_or(Error::from(ErrorKind::InvalidData))?,
            block_size: block_size.ok_or(Error::from(ErrorKind::InvalidData))?,
            digest_size: digest_size.ok_or(Error::from(ErrorKind::InvalidData))?,
        }),
        TransformType::PublicKeyCipher => {
            TransformData::PublicKeyCipher(PublicKeyTransform { base })
        }
        TransformType::Cipher => TransformData::Cipher(CipherTransform {
            base,
            block_size: block_size.ok_or(Error::from(ErrorKind::InvalidData))?,
            min_key_size: min_key_size.ok_or(Error::from(ErrorKind::InvalidData))?,
            max_key_size: max_key_size.ok_or(Error::from(ErrorKind::InvalidData))?,
        }),
        TransformType::Compression => TransformData::Compression(CompressionTransform { base }),
        TransformType::KeyAgreementProtocolPrimitive => {
            TransformData::KeyAgreementProtocolPrimitive(KeyAgreementProtocolPrimitiveTransform {
                base,
            })
        }
        TransformType::LinearSymmetricKeyCipher => {
            TransformData::LinearSymmetricKeyCipher(LinearSymmetricKeyTransform {
                base,
                block_size: block_size.ok_or(Error::from(ErrorKind::InvalidData))?,
                min_key_size: min_key_size.ok_or(Error::from(ErrorKind::InvalidData))?,
                max_key_size: max_key_size.ok_or(Error::from(ErrorKind::InvalidData))?,
                iv_size: iv_size.ok_or(Error::from(ErrorKind::InvalidData))?,
                chunk_size: chunk_size.ok_or(Error::from(ErrorKind::InvalidData))?,
                state_size: state_size.ok_or(Error::from(ErrorKind::InvalidData))?,
            })
        }
        TransformType::Rng => TransformData::Rng(RngTransform {
            base,
            seed_size: seed_size.ok_or(Error::from(ErrorKind::InvalidData))?,
        }),
        TransformType::SyncCompression => {
            TransformData::SyncCompression(SyncCompressionTransform { base })
        }
        TransformType::SyncHash => TransformData::SyncHash(SyncHashTransform {
            base,
            block_size: block_size.ok_or(Error::from(ErrorKind::InvalidData))?,
            digest_size: digest_size.ok_or(Error::from(ErrorKind::InvalidData))?,
        }),
        TransformType::SymmetricKeyCipher => {
            TransformData::SymmetricKeyCipher(SymmetricKeyCipherTransform {
                base,
                is_async: is_async.ok_or(Error::from(ErrorKind::InvalidData))?,
                block_size: block_size.ok_or(Error::from(ErrorKind::InvalidData))?,
                min_key_size: min_key_size.ok_or(Error::from(ErrorKind::InvalidData))?,
                max_key_size: max_key_size.ok_or(Error::from(ErrorKind::InvalidData))?,
                iv_size: iv_size.ok_or(Error::from(ErrorKind::InvalidData))?,
                chunk_size: chunk_size.ok_or(Error::from(ErrorKind::InvalidData))?,
                walk_size: walk_size.ok_or(Error::from(ErrorKind::InvalidData))?,
                state_size: state_size.ok_or(Error::from(ErrorKind::InvalidData))?,
            })
        }
    })
}

fn validate_base_transform(base: &TransformBase) -> Result<()> {
    if base.name.is_empty() {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if base.driver.is_empty() {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if base.module.is_empty() {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    //Not validating priority

    //Not validating ref_cnt

    if !base.self_test {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if base.internal {
        return Err(Error::from(ErrorKind::InvalidData));
    }

    //Not validating ttype

    Ok(())
}

fn validate_aead_transform(tf: &AeadTransform) -> Result<()> {
    //Not validating is_async

    //Not validating block_size

    //Not validating iv_size

    //Not validating max_auth_size

    if tf.gen_iv.is_some() {
        return Err(Error::from(ErrorKind::InvalidData));
    }

    Ok(())
}

fn validate_async_compression_transform(_tf: &AsyncCompressionTransform) -> Result<()> {
    Ok(())
}

fn validate_async_hash_transform(_tf: &AsyncHashTransform) -> Result<()> {
    //Not validating is_async

    //Not validating block_size

    //Not validating digest_size

    Ok(())
}

fn validate_public_key_transform(_tf: &PublicKeyTransform) -> Result<()> {
    Ok(())
}

fn validate_cipher_transform(tf: &CipherTransform) -> Result<()> {
    //Not validating block_size

    if tf.min_key_size == 0 {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if tf.max_key_size == 0 {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if tf.min_key_size > tf.max_key_size {
        return Err(Error::from(ErrorKind::InvalidData));
    }

    Ok(())
}

fn validate_compression_transform(_tf: &CompressionTransform) -> Result<()> {
    Ok(())
}

fn validate_key_agreement_protocol_primitive_transform(
    _tf: &KeyAgreementProtocolPrimitiveTransform,
) -> Result<()> {
    Ok(())
}

fn validate_linear_symmetric_key_transform(tf: &LinearSymmetricKeyTransform) -> Result<()> {
    //Not validating block_size

    if tf.min_key_size == 0 {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if tf.max_key_size == 0 {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if tf.min_key_size > tf.max_key_size {
        return Err(Error::from(ErrorKind::InvalidData));
    }

    if tf.iv_size == 0 {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if tf.chunk_size == 0 {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if tf.state_size == 0 {
        return Err(Error::from(ErrorKind::InvalidData));
    }

    Ok(())
}

fn validate_rng_transform(tf: &RngTransform) -> Result<()> {
    if tf.seed_size == 0 {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    Ok(())
}

fn validate_sync_compression_transform(_tf: &SyncCompressionTransform) -> Result<()> {
    Ok(())
}

fn validate_sync_hash_transform(_tf: &SyncHashTransform) -> Result<()> {
    //Not validating block_size

    //Not validating digest_size

    Ok(())
}

fn validate_symmetric_key_cipher_transform(tf: &SymmetricKeyCipherTransform) -> Result<()> {
    //Not validating is_async

    //Not validating block_size

    //Not validating digest_size

    if tf.min_key_size == 0 {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if tf.max_key_size == 0 {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if tf.min_key_size > tf.max_key_size {
        return Err(Error::from(ErrorKind::InvalidData));
    }

    if tf.iv_size == 0 {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if tf.chunk_size == 0 {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if tf.walk_size == 0 {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    if tf.state_size == 0 {
        return Err(Error::from(ErrorKind::InvalidData));
    }
    Ok(())
}

fn validate_transform(tf: TransformData) -> Result<TransformData> {
    match tf {
        TransformData::Aead(ref inner) => {
            validate_base_transform(&inner.base)?;
            validate_aead_transform(inner)?;
            Ok(tf)
        }
        TransformData::AsyncCompression(ref inner) => {
            validate_base_transform(&inner.base)?;
            validate_async_compression_transform(inner)?;
            Ok(tf)
        }
        TransformData::AsyncHash(ref inner) => {
            validate_base_transform(&inner.base)?;
            validate_async_hash_transform(inner)?;
            Ok(tf)
        }
        TransformData::PublicKeyCipher(ref inner) => {
            validate_base_transform(&inner.base)?;
            validate_public_key_transform(inner)?;
            Ok(tf)
        }
        TransformData::Cipher(ref inner) => {
            validate_base_transform(&inner.base)?;
            validate_cipher_transform(inner)?;
            Ok(tf)
        }
        TransformData::Compression(ref inner) => {
            validate_base_transform(&inner.base)?;
            validate_compression_transform(inner)?;
            Ok(tf)
        }
        TransformData::KeyAgreementProtocolPrimitive(ref inner) => {
            validate_base_transform(&inner.base)?;
            validate_key_agreement_protocol_primitive_transform(inner)?;
            Ok(tf)
        }
        TransformData::LinearSymmetricKeyCipher(ref inner) => {
            validate_base_transform(&inner.base)?;
            validate_linear_symmetric_key_transform(inner)?;
            Ok(tf)
        }
        TransformData::Rng(ref inner) => {
            validate_base_transform(&inner.base)?;
            validate_rng_transform(inner)?;
            Ok(tf)
        }
        TransformData::SyncCompression(ref inner) => {
            validate_base_transform(&inner.base)?;
            validate_sync_compression_transform(inner)?;
            Ok(tf)
        }
        TransformData::SyncHash(ref inner) => {
            validate_base_transform(&inner.base)?;
            validate_sync_hash_transform(inner)?;
            Ok(tf)
        }
        TransformData::SymmetricKeyCipher(ref inner) => {
            validate_base_transform(&inner.base)?;
            validate_symmetric_key_cipher_transform(inner)?;
            Ok(tf)
        }
    }
}

fn parse_transformations(contents: impl BufRead) -> Result<Vec<TransformData>> {
    let entries = parse_entries(contents)?;

    let mut output = Vec::new();

    for (entry_name, entry_contents) in entries {
        if let Ok(transform) = validate_transform(build_transform(&entry_contents)?) {
            output.push(transform);
        }
    }

    Ok(output)
}

#[cfg(test)]
mod parsing_tests {
    use super::*;
    use std::fs::File;
    use std::io::BufReader;

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
    fn parsing_to_transform_from_map() {
        let f = BufReader::new(File::open(CRYPTO_FILE_PATH).unwrap());
        let output = parse_entries(f).unwrap();
        assert!(!output.is_empty());

        for (transform_name, transform_entry_map) in output {
            assert!(!transform_name.is_empty());
            assert!(!transform_entry_map.is_empty());

            let _ = build_transform(&transform_entry_map).unwrap();
        }
    }

    #[test]
    fn parsing_to_transform_vec() {
        let f = BufReader::new(File::open(CRYPTO_FILE_PATH).unwrap());
        let output = parse_transformations(f).unwrap();
        assert!(!output.is_empty());
    }
}
