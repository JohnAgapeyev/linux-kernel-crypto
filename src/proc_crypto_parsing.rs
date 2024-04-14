use itertools::Itertools;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Error, ErrorKind, Result};

const CRYPTO_FILE_PATH: &str = "/proc/crypto";

fn chunk_entries(contents: impl BufRead) -> Result<Vec<Vec<String>>> {
    contents
        .lines()
        .group_by(|line| line.as_ref().is_ok_and(|l| !l.is_empty()))
        .into_iter()
        .filter_map(|(key, group)| key.then_some(group.try_collect()))
        .try_collect()
}

fn trim_line(line: &str) -> Result<(&str, &str)> {
    let tokens: Vec<&str> = line.split(':').collect();

    match tokens.len() {
        2 => Ok((tokens[0].trim(), tokens[1].trim())),
        _ => Err(Error::from(ErrorKind::InvalidData)),
    }
}

#[cfg(test)]
mod parsing_tests {
    use super::*;

    #[test]
    fn entry_chunking() {
        let f = BufReader::new(File::open(CRYPTO_FILE_PATH).unwrap());
        let output = chunk_entries(f).unwrap();
        assert!(!output.is_empty());
        println!("{:#?}", output[0])
    }

    #[test]
    fn line_stripping() {
        let (key, value) = trim_line("driver       : cryptd(__generic-gcm-aesni)").unwrap();
        assert_eq!(key, "driver");
        assert_eq!(value, "cryptd(__generic-gcm-aesni)");
    }
}
