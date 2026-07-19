/// Error returned when BPF compilation fails.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CompileError {
    /// Pattern exceeds BPF verifier instruction limit.
    #[error("pattern length {len} exceeds BPF verifier limit of {max} bytes. Fix: use userspace matching for patterns longer than {max} bytes.")]
    PatternTooLong {
        /// Actual pattern length.
        len: usize,
        /// Maximum supported length.
        max: usize,
    },
    /// Pattern syntax is not supported.
    #[error("invalid pattern: {reason}. Fix: use a supported subset (literal bytes, alternation, and ranges with start <= end).")]
    InvalidPattern {
        /// Pattern validation failure reason.
        reason: &'static str,
    },
}

/// Maximum pattern length the BPF verifier can handle.
///
/// Each pattern byte generates ~3 instructions (load + compare + jump).
/// The classic BPF limit is 4096 instructions. With overhead (~20 insns),
/// max usable is ~1350 pattern bytes. We use 1024 for safety margin.
/// Patterns longer than this should use userspace matching.
pub const MAX_BPF_PATTERN_LEN: usize = 1024;
const MAX_BPF_INSTRUCTION_LEN: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PatternRange {
    /// A single byte that must match exactly.
    Single(u8),
    /// An inclusive byte range.
    Span(u8, u8),
}

/// A token in the flat stream produced by scanning a character class.
#[derive(Debug)]
enum Token {
    /// A single literal byte (e.g. `a` or `\.`).
    Byte(u8),
    /// A raw, unescaped hyphen that may act as a range operator.
    Dash,
    /// A pre-expanded class escape (e.g. `\d` becomes `0-9`).
    Class(Vec<PatternRange>),
}

/// Decode an escape sequence starting at `class[idx]`, which must be `b'\'`.
/// Returns the token and the number of input bytes consumed.
fn decode_character_class_escape(class: &[u8], idx: usize) -> Result<(Token, usize), CompileError> {
    if idx + 1 >= class.len() {
        return Err(CompileError::InvalidPattern {
            reason: "unterminated character-class escape",
        });
    }
    let escaped = class[idx + 1];
    let token = match escaped {
        b'n' => Token::Byte(b'\n'),
        b'r' => Token::Byte(b'\r'),
        b't' => Token::Byte(b'\t'),
        b'\\' => Token::Byte(b'\\'),
        b']' => Token::Byte(b']'),
        b'[' => Token::Byte(b'['),
        b'-' => Token::Byte(b'-'),
        b'.' => Token::Byte(b'.'),
        b'd' => Token::Class(vec![PatternRange::Span(b'0', b'9')]),
        b's' => Token::Class(vec![
            PatternRange::Span(b'\t', b'\r'),
            PatternRange::Single(b' '),
        ]),
        b'w' => Token::Class(vec![
            PatternRange::Span(b'a', b'z'),
            PatternRange::Span(b'A', b'Z'),
            PatternRange::Span(b'0', b'9'),
            PatternRange::Single(b'_'),
        ]),
        b'D' | b'S' | b'W' => {
            return Err(CompileError::InvalidPattern {
                reason: "negated character-class escapes are not supported",
            });
        }
        _ => {
            return Err(CompileError::InvalidPattern {
                reason: "unknown character-class escape sequence",
            });
        }
    };
    Ok((token, 2))
}

/// Convert a flat token stream into a list of `PatternRange` values, treating
/// an unescaped `-` as a range operator only when it sits between two literal bytes.
fn tokens_to_ranges(tokens: &[Token]) -> Result<Vec<PatternRange>, CompileError> {
    let mut ranges = Vec::new();
    let mut idx = 0;
    while idx < tokens.len() {
        if idx + 2 < tokens.len() {
            if let (Token::Byte(start), Token::Dash, Token::Byte(end)) =
                (&tokens[idx], &tokens[idx + 1], &tokens[idx + 2])
            {
                if start > end {
                    return Err(CompileError::InvalidPattern {
                        reason: "character class range endpoints are reversed",
                    });
                }
                ranges.push(PatternRange::Span(*start, *end));
                idx += 3;
                continue;
            }
        }
        if matches!(tokens[idx], Token::Dash)
            && idx + 1 < tokens.len()
            && matches!(tokens[idx + 1], Token::Dash)
        {
            return Err(CompileError::InvalidPattern {
                reason: "character class contains consecutive unescaped dashes",
            });
        }
        match &tokens[idx] {
            Token::Byte(b) => ranges.push(PatternRange::Single(*b)),
            Token::Dash => ranges.push(PatternRange::Single(b'-')),
            Token::Class(c) => ranges.extend(c.iter().copied()),
        }
        idx += 1;
    }
    Ok(ranges)
}

pub(crate) fn parse_character_class(class: &[u8]) -> Result<Vec<PatternRange>, CompileError> {
    // Character classes match a single byte. If the input is valid UTF-8 and
    // contains any non-ASCII byte, it must contain a multi-byte codepoint; reject
    // it rather than silently split the codepoint into unrelated byte ranges.
    if std::str::from_utf8(class).is_ok() && class.iter().any(|b| *b >= 0x80) {
        return Err(CompileError::InvalidPattern {
            reason:
                "character class contains non-ASCII codepoints; use raw bytes or an escape sequence",
        });
    }

    let mut tokens = Vec::new();
    let mut idx = 0;
    while idx < class.len() {
        if class[idx] == b'\\' {
            let (token, consumed) = decode_character_class_escape(class, idx)?;
            tokens.push(token);
            idx += consumed;
        } else if class[idx] == b'-' {
            tokens.push(Token::Dash);
            idx += 1;
        } else {
            tokens.push(Token::Byte(class[idx]));
            idx += 1;
        }
    }

    tokens_to_ranges(&tokens)
}

/// Validates generated instruction count before assembling BPF code.
///
/// # Errors
///
/// Returns [`CompileError::PatternTooLong`] when the expected instruction
/// count would exceed the eBPF verifier cap of 4096 instructions.
pub fn compile_with_limit(expected_instruction_count: usize) -> Result<(), CompileError> {
    if expected_instruction_count > MAX_BPF_INSTRUCTION_LEN {
        return Err(CompileError::PatternTooLong {
            len: expected_instruction_count,
            max: MAX_BPF_INSTRUCTION_LEN,
        });
    }

    Ok(())
}

pub(crate) fn literal_search_instruction_count(pattern_len: usize) -> usize {
    if pattern_len == 0 {
        return 4;
    }

    // 2 context loads, 1 loop index init, 5 setup insns (R5/R6 + bounds placeholder),
    // 2 instructions per literal byte, and 6 fixed control-flow insns.
    14 + pattern_len * 2
}

#[cfg(test)]
pub(crate) fn estimate_character_class_instructions(ranges: &[PatternRange]) -> usize {
    if ranges.is_empty() {
        return 2;
    }

    // Must equal compile_char_class's emitted length exactly (it is used
    // both as the compile_with_limit bound and the Vec capacity). The
    // canonical character-class program emits JLT + JLE per range and a
    // fixed fail (MOV R0,0 + EXIT) + match (MOV R0,1 + EXIT) block = 4.
    4 + ranges.len() * 2
}

pub(crate) fn estimate_alternation_instructions(alternatives: &[&[u8]]) -> usize {
    if alternatives.is_empty() || alternatives.iter().any(|alt| alt.is_empty()) {
        return 2;
    }

    // Must equal compile_alternation's emitted length exactly (bound + Vec
    // capacity). Per alternative: bound check = MOV R6,R5 + ADD R6,len +
    // JGT R6,R3 = 3; per byte LDX_B + JNE = 2 (=> 2*len); match jump JA = 1;
    // total 4 + 2*len. Fixed blocks: fail (MOV+EXIT) + success (MOV+EXIT) = 4.
    // (The previous estimate charged the 3-instruction bound check as 1 and the
    // fixed blocks as 2, so it UNDER-estimated by 2 per alternative + 2.)
    let alternative_count = alternatives.iter().map(|alt| {
        if alt.is_empty() {
            0
        } else {
            4 + (alt.len() * 2)
        }
    });

    4 + alternative_count.sum::<usize>()
}

#[derive(Debug, Clone, Copy)]
pub struct CharRange {
    /// Inclusive start of the range.
    pub lo: u8,
    /// Inclusive end of the range.
    pub hi: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_empty_class_escapes() {
        assert!(matches!(
            parse_character_class(b"\\"),
            Err(CompileError::InvalidPattern {
                reason: "unterminated character-class escape"
            })
        ));
        assert!(matches!(
            parse_character_class(b"a-\\"),
            Err(CompileError::InvalidPattern {
                reason: "unterminated character-class escape"
            })
        ));
    }

    #[test]
    fn parse_range_requires_ordered_endpoints() {
        assert!(matches!(
            parse_character_class(b"z-a"),
            Err(CompileError::InvalidPattern {
                reason: "character class range endpoints are reversed"
            })
        ));
    }

    #[test]
    fn compile_limit_safeguards_instruction_cap() {
        assert!(matches!(
            compile_with_limit(4097),
            Err(CompileError::PatternTooLong {
                len: 4097,
                max: 4096
            })
        ));
    }

    #[test]
    fn literal_count_for_empty_pattern_is_fixed() {
        assert_eq!(literal_search_instruction_count(0), 4);
    }

    #[test]
    fn literal_count_matches_compiled_program_length() {
        use crate::compiler::compile_literal_search;
        for len in [1, 3, 10, 100, 1024] {
            let pattern = vec![b'a'; len];
            let prog = compile_literal_search(&pattern).unwrap();
            assert_eq!(
                literal_search_instruction_count(len),
                prog.len(),
                "instruction count estimate must equal actual compiled length for len {len}"
            );
        }
    }

    #[test]
    fn character_class_rejects_non_ascii_codepoints() {
        // Valid UTF-8 with a multi-byte codepoint must be rejected, not split
        // into unrelated byte ranges.
        assert!(matches!(
            parse_character_class("é".as_bytes()),
            Err(CompileError::InvalidPattern {
                reason: "character class contains non-ASCII codepoints; use raw bytes or an escape sequence"
            })
        ));
    }

    #[test]
    fn character_class_accepts_raw_invalid_utf8_bytes() {
        // Invalid UTF-8 bytes should be matched as raw bytes, not silently
        // reinterpreted as a multi-byte codepoint.
        let ranges = parse_character_class(b"\x00-\xFF").unwrap();
        assert_eq!(ranges, vec![PatternRange::Span(0x00, 0xFF)]);
    }

    #[test]
    fn character_class_decodes_standard_escapes() {
        assert_eq!(
            parse_character_class(br"\n\r\t\\.\-\]\[").unwrap(),
            vec![
                PatternRange::Single(b'\n'),
                PatternRange::Single(b'\r'),
                PatternRange::Single(b'\t'),
                PatternRange::Single(b'\\'),
                PatternRange::Single(b'.'),
                PatternRange::Single(b'-'),
                PatternRange::Single(b']'),
                PatternRange::Single(b'['),
            ]
        );
    }

    #[test]
    fn character_class_expands_class_escapes() {
        assert_eq!(
            parse_character_class(br"\d").unwrap(),
            vec![PatternRange::Span(b'0', b'9')]
        );
        assert_eq!(
            parse_character_class(br"\s").unwrap(),
            vec![PatternRange::Span(b'\t', b'\r'), PatternRange::Single(b' '),]
        );
        assert_eq!(
            parse_character_class(br"\w").unwrap(),
            vec![
                PatternRange::Span(b'a', b'z'),
                PatternRange::Span(b'A', b'Z'),
                PatternRange::Span(b'0', b'9'),
                PatternRange::Single(b'_'),
            ]
        );
    }

    #[test]
    fn character_class_rejects_negated_class_escapes() {
        for class in [br"\D", br"\S", br"\W"] {
            assert!(
                matches!(
                    parse_character_class(class),
                    Err(CompileError::InvalidPattern {
                        reason: "negated character-class escapes are not supported"
                    })
                ),
                "class {class:?} should be rejected"
            );
        }
    }

    #[test]
    fn character_class_range_with_escape_endpoint_works() {
        // \d-\w is not a valid range; the dash is interpreted as a literal
        // byte between the two expanded classes.
        let ranges = parse_character_class(br"\d-\w").unwrap();
        let mut expected = vec![PatternRange::Span(b'0', b'9')];
        expected.push(PatternRange::Single(b'-'));
        expected.extend([
            PatternRange::Span(b'a', b'z'),
            PatternRange::Span(b'A', b'Z'),
            PatternRange::Span(b'0', b'9'),
            PatternRange::Single(b'_'),
        ]);
        assert_eq!(ranges, expected);
    }

    #[test]
    fn character_class_rejects_consecutive_dashes() {
        for class in [&b"a--z"[..], &b"-----"[..], &b"a---b"[..]] {
            assert!(
                matches!(
                    parse_character_class(class),
                    Err(CompileError::InvalidPattern {
                        reason: "character class contains consecutive unescaped dashes"
                    })
                ),
                "class {class:?} should be rejected for consecutive unescaped dashes"
            );
        }
    }

    #[test]
    fn char_class_estimate_equals_actual_compiled_length() {
        use crate::compiler::compile_character_class;
        // The estimate must MATCH the real emitted program length (it is used as
        // both the compile_with_limit bound and the Vec capacity). Assert exact
        // equality across single, span, and mixed classes, computing the ranges
        // via the same parser compile uses.
        for class in [
            &b"a"[..],       // single Span/Single after parse
            &b"az"[..],      // two singles
            &b"a-z"[..],     // one span
            &b"a-z0-9"[..],  // two spans
            &b"a-z0-9_"[..], // two spans + single
        ] {
            let ranges = parse_character_class(class).unwrap();
            let estimate = estimate_character_class_instructions(&ranges);
            let actual = compile_character_class(class).unwrap().len();
            assert_eq!(
                estimate, actual,
                "char-class estimate {estimate} != actual {actual} for {class:?}"
            );
        }
        // Concrete anchor: a single Single range is JEQ+JA + 4 fixed = 6.
        assert_eq!(
            estimate_character_class_instructions(&[PatternRange::Single(0x41)]),
            6
        );
    }

    #[test]
    fn alternation_estimate_equals_actual_compiled_length() {
        use crate::compiler::compile_alternation;
        for alts in [
            vec![&b"aa"[..], &b"b"[..]],
            vec![&b"foo"[..]],
            vec![&b"ab"[..], &b"cd"[..], &b"ef"[..]],
        ] {
            let estimate = estimate_alternation_instructions(&alts);
            let actual = compile_alternation(&alts).unwrap().len();
            assert_eq!(
                estimate, actual,
                "alternation estimate {estimate} != actual {actual} for {alts:?}"
            );
        }
        // Concrete anchor: ["aa","b"] = 4 fixed + (4+2*2) + (4+2*1) = 18.
        let alternates: Vec<&[u8]> = vec![b"aa", b"b"];
        assert_eq!(estimate_alternation_instructions(&alternates), 18);
    }
}
