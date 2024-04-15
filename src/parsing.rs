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
            assert!(entry_map.contains_key(&EntryKey::Type));
            assert!(entry_map.contains_key(&EntryKey::RefCnt));
            assert!(entry_map.contains_key(&EntryKey::Internal));
            assert!(entry_map.contains_key(&EntryKey::SelfTest));
        }
    }
}
