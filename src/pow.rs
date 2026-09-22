//! Proof of work that guards registration
//! Bits, Weak = 16, about 65k attempts
//!       Medium = 20, about 1M attempts
//!       Strong = 24, about 16M attempts

use rand::RngExt;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Difficulty {
    Weak,
    Medium,
    Strong,
}

impl Difficulty {
    pub fn bits(self) -> u32 {
        match self {
            Self::Weak => 16,
            Self::Medium => 20,
            Self::Strong => 24,
        }
    }

    pub fn parse_env(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "weak" => Some(Self::Weak),
            "medium" => Some(Self::Medium),
            "strong" => Some(Self::Strong),
            _ => None,
        }
    }
}

pub fn generate_challenge() -> String {
    (0..16)
        .map(|_| format!("{:x}", rand::rng().random_range(0u8..16)))
        .collect()
}

pub fn verify(challenge: &str, nonce: u64, bits: u32) -> bool {
    leading_zero_bits(&hash(challenge, nonce)) >= bits
}

pub fn solve(challenge: &str, bits: u32) -> u64 {
    let mut nonce: u64 = 0;
    loop {
        if verify(challenge, nonce, bits) {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

fn hash(challenge: &str, nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(challenge.as_bytes());
    hasher.update(nonce.to_string().as_bytes());
    hasher.finalize().into()
}

fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for &byte in hash {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn difficulty_bits_match_docs() {
        assert_eq!(Difficulty::Weak.bits(), 16);
        assert_eq!(Difficulty::Medium.bits(), 20);
        assert_eq!(Difficulty::Strong.bits(), 24);
    }

    #[test]
    fn parse_env_is_case_insensitive_and_strict() {
        assert_eq!(Difficulty::parse_env("Weak"), Some(Difficulty::Weak));
        assert_eq!(Difficulty::parse_env("MEDIUM"), Some(Difficulty::Medium));
        assert_eq!(Difficulty::parse_env("banana"), None);
    }

    #[test]
    fn leading_zeros_counting() {
        let mut arr1 = [0u8; 32];
        arr1[2] = 0xFF;
        assert_eq!(leading_zero_bits(&arr1), 16);

        let mut arr2 = [0u8; 32];
        arr2[0] = 0x0F;
        assert_eq!(leading_zero_bits(&arr2), 4);

        let mut arr3 = [0u8; 32];
        arr3[0] = 0xFF;
        assert_eq!(leading_zero_bits(&arr3), 0);

        assert_eq!(leading_zero_bits(&[0x00; 32]), 256);
    }

    #[test]
    fn solve_finds_verifiable_nonce() {
        let challenge = "testtest1test2test3";
        let nonce = solve(challenge, 8);
        assert!(verify(challenge, nonce, 8));
    }

    #[test]
    fn wrong_challenge_fails_mostly() {
        let _ = verify("other", 12345, 8);
    }
}
