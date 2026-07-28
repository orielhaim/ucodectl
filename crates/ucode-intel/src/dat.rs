//! Parser for the legacy Intel `.dat` text distribution format.
//!
//! The format is a sequence of comma-separated 32-bit hexadecimal literals,
//! four per line by convention, with `/* ... */` block comments. It carries
//! exactly the same bytes as the binary form, so we simply reassemble the
//! little-endian byte stream and hand it to the binary parser.

use crate::{IntelError, Result};

/// Convert `.dat` text into the equivalent binary bundle.
pub fn dat_to_binary(text: &str) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(text.len() / 3);
    let mut in_block_comment = false;

    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let mut line = raw_line;

        // Strip block comments, possibly spanning lines.
        let mut cleaned = String::with_capacity(line.len());
        while !line.is_empty() {
            if in_block_comment {
                match line.find("*/") {
                    Some(end) => {
                        in_block_comment = false;
                        line = line.get(end + 2..).unwrap_or("");
                    }
                    None => {
                        line = "";
                    }
                }
            } else {
                match line.find("/*") {
                    Some(start) => {
                        cleaned.push_str(line.get(..start).unwrap_or(""));
                        in_block_comment = true;
                        line = line.get(start + 2..).unwrap_or("");
                    }
                    None => {
                        cleaned.push_str(line);
                        line = "";
                    }
                }
            }
        }

        // Line comments.
        if let Some(pos) = cleaned.find("//") {
            cleaned.truncate(pos);
        }
        if let Some(pos) = cleaned.find(';') {
            cleaned.truncate(pos);
        }

        for token in cleaned.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            let digits = token
                .strip_prefix("0x")
                .or_else(|| token.strip_prefix("0X"))
                .ok_or_else(|| IntelError::Dat {
                    line: line_no,
                    reason: format!("token {token:?} is not a 0x-prefixed hex literal"),
                })?;
            if digits.is_empty() || digits.len() > 8 {
                return Err(IntelError::Dat {
                    line: line_no,
                    reason: format!("token {token:?} is not a 32-bit value"),
                });
            }
            let value = u32::from_str_radix(digits, 16).map_err(|e| IntelError::Dat {
                line: line_no,
                reason: format!("token {token:?}: {e}"),
            })?;
            out.extend_from_slice(&value.to_le_bytes());
        }
    }

    if in_block_comment {
        return Err(IntelError::Dat {
            line: text.lines().count(),
            reason: "unterminated block comment".to_string(),
        });
    }
    if out.is_empty() {
        return Err(IntelError::Dat {
            line: 0,
            reason: "no data words found".to_string(),
        });
    }
    Ok(out)
}

/// Heuristic sniff for `.dat` content.
pub fn looks_like_dat(bytes: &[u8]) -> bool {
    let head = bytes.get(..4096).unwrap_or(bytes);
    let Ok(text) = core::str::from_utf8(head) else {
        return false;
    };
    text.contains("0x") && text.contains(',')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_four_words_per_line() {
        let text = "/* header */\n0x00000001, 0x000000ff, 0x11172023, 0x000806ec,\n";
        let bin = dat_to_binary(text).expect("parse");
        assert_eq!(bin.len(), 16);
        assert_eq!(&bin[0..4], &1u32.to_le_bytes());
        assert_eq!(&bin[12..16], &0x000806ecu32.to_le_bytes());
    }

    #[test]
    fn rejects_non_hex() {
        assert!(dat_to_binary("hello, world").is_err());
    }
}
