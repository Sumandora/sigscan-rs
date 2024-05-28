//! # Signature scanner
//!
//! This is an extremely simple implementation of a pattern scanner for game hacking purposes
//!
//! ## Example
//!
//! ```rust
//! use signature_scanner::Signature;
//!
//! // Creation of a IDA byte signature:
//! let ida_sig = Signature::ida("12 34");
//! let string_sig = Signature::string("lo, wor", /*include_terminator: */false);
//!
//! // Search inside u8 slice:
//! ida_sig.next(&[0x00u8, /*matches here*/0x12, 0x34, 0x56, 0x12, 0x54, 0x12, 0x34, 0x00, 0x55, 0xAA]); // == Some(1)
//! string_sig.next("Hello, world!".as_bytes()); // == Some(3)
//! ```
//!

#[derive(PartialEq, Debug)]
pub struct PatternElement(pub Option<u8>);

impl std::cmp::PartialEq<u8> for PatternElement {
    fn eq(&self, other: &u8) -> bool {
        self.0.map(|b| b == *other).unwrap_or(true)
    }
}

pub struct Signature(Vec<PatternElement>);

impl Signature {
    /// Creates a signature with the pattern being taken directly from the vector
    pub fn new(vec: Vec<PatternElement>) -> Self {
        Self(vec)
    }

    /// Creates a signature with the pattern being a ida-style bytes sequence
    pub fn ida(pattern: &str) -> Self {
        Self(
            pattern
                .split_ascii_whitespace()
                .map(|word| {
                    if word.chars().all(|c| c == '?') {
                        PatternElement(None)
                    } else {
                        PatternElement(Some(
                            word.chars()
                                .rev()
                                .map(|c| c.to_digit(16))
                                .map(|opt| opt.unwrap())
                                .enumerate()
                                .map(|(i, num)| if i == 0 { num } else { num * (i * 16) as u32 })
                                .map(|num| num as u8)
                                .sum(),
                        ))
                    }
                })
                .collect::<Vec<_>>(),
        )
    }

    /// Creates a signature with the pattern being a string without wildcards
    pub fn string(string: &str, include_terminator: bool) -> Self {
        let mut elements = Vec::new();

        for c in string.chars() {
            elements.push(PatternElement(Some(c as u8)))
        }

        if include_terminator {
            elements.push(PatternElement(Some(0x00u8)))
        }

        Self(elements)
    }

    /// Creates a signature with the pattern being a string with wildcards
    pub fn wildcard_string(string: &str, wildcard: char, include_terminator: bool) -> Self {
        let mut elements = Vec::new();

        for c in string.chars() {
            if c == wildcard {
                elements.push(PatternElement(None))
            } else {
                elements.push(PatternElement(Some(c as u8)))
            }
        }

        if include_terminator {
            elements.push(PatternElement(Some(0x00u8)))
        }

        Self(elements)
    }

    /// Finds the next occurrence of the pattern in `slice`
    pub fn next(&self, slice: &[u8]) -> Option<usize> {
        slice
            .windows(self.0.len())
            .position(|window| self.0 == window)
    }

    /// Finds the previous occurrence of the pattern in `slice`
    pub fn prev(&self, slice: &[u8]) -> Option<usize> {
        slice
            .windows(self.0.len())
            .rev()
            .position(|window| self.0 == window)
            .map(|offset| offset + self.0.len() - 1)
    }

    /// Finds all occurrences of the pattern in `slice`
    pub fn all<'a>(&'a self, slice: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
        slice
            .windows(self.0.len())
            .enumerate()
            .filter(|(_, window)| self.0 == *window)
            .map(|(i, _)| i)
    }

    pub fn matches(&self, slice: &[u8]) -> bool {
        self.0 == slice
    }

    pub fn get_elements(&self) -> &Vec<PatternElement> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ida_construction() {
        assert_eq!(
            Signature::ida("AA BB CC DD EE FF").0,
            [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        );
        assert_eq!(
            Signature::ida("12 34 56 78 89").0,
            [0x12u8, 0x34, 0x56, 0x78, 0x89]
        );
        assert_eq!(
            Signature::ida("12    34      56 \t78\t89").0,
            [0x12u8, 0x34, 0x56, 0x78, 0x89]
        );
    }

    #[test]
    fn test_string_construction() {
        assert_eq!(Signature::string("Test", false).0, [b'T', b'e', b's', b't']);
        assert_eq!(
            Signature::string("Test", true).0,
            [b'T', b'e', b's', b't', b'\0']
        );
        assert_eq!(
            Signature::wildcard_string("T?st", '?', false).0,
            [
                PatternElement(Some(b'T')),
                PatternElement(None),
                PatternElement(Some(b's')),
                PatternElement(Some(b't'))
            ]
        );
        assert_eq!(
            Signature::wildcard_string("T?st", '?', true).0,
            [
                PatternElement(Some(b'T')),
                PatternElement(None),
                PatternElement(Some(b's')),
                PatternElement(Some(b't')),
                PatternElement(Some(b'\0'))
            ]
        );
    }

    #[test]
    fn test_next_search_behavior() {
        assert_eq!(
            Signature::ida("12 34")
                .next(&[0x00u8, 0x12, 0x34, 0x56, 0x12, 0x54, 0x12, 0x34, 0x00, 0x55, 0xAA]),
            Some(1)
        );

        assert_eq!(
            Signature::string("lo, wor", false).next("Hello, world!".as_bytes()),
            Some(3)
        );
    }

    #[test]
    fn test_prev_search_behavior() {
        assert_eq!(
            Signature::ida("12 34")
                .prev(&[0x00u8, 0x12, 0x34, 0x56, 0x12, 0x54, 0x12, 0x34, 0x00, 0x55, 0xAA]),
            Some(4)
        );

        assert_eq!(
            Signature::string("lo, wor", false).prev("Hello, world!".as_bytes()),
            Some(9)
        );
    }

    #[test]
    fn test_all_search_behavior() {
        assert_eq!(
            Signature::ida("12 34")
                .all(&[0x00u8, 0x12, 0x34, 0x56, 0x12, 0x54, 0x12, 0x34, 0x00, 0x55, 0xAA])
                .collect::<Vec<usize>>(),
            [1, 6]
        );

        assert_eq!(
            Signature::string("lo, wor", false)
                .all("Hello, world!".as_bytes())
                .collect::<Vec<usize>>(),
            [3]
        );
    }

    #[test]
    fn test_matches_behavior() {
        assert!(Signature::ida("12 34").matches(&[0x12u8, 0x34]));

        assert!(Signature::string("lo, wor", false).matches("lo, wor".as_bytes()));
    }
}
