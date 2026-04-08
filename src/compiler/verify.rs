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

#[derive(Clone, Copy)]
pub(super) enum PatternRange {
    Single(u8),
    Span(u8, u8),
}

pub(crate) fn parse_character_class(class: &[u8]) -> Result<Vec<PatternRange>, CompileError> {
    let mut ranges = Vec::new();
    let mut idx = 0;

    while idx < class.len() {
        let start = match class[idx] {
            b'\\' => {
                if idx + 1 >= class.len() {
                    return Err(CompileError::InvalidPattern {
                        reason: "unterminated character-class escape",
                    });
                }
                let escaped = class[idx + 1];
                idx += 2;
                escaped
            }
            b => {
                idx += 1;
                b
            }
        };

        let is_range = idx + 1 < class.len() && class[idx] == b'-';
        if is_range {
            let end = match class[idx + 1] {
                b'\\' => {
                    if idx + 2 >= class.len() {
                        return Err(CompileError::InvalidPattern {
                            reason: "unterminated character-class range escape",
                        });
                    }

                    let escaped = class[idx + 2];
                    idx += 3;
                    escaped
                }
                b => {
                    idx += 2;
                    b
                }
            };

            if start > end {
                return Err(CompileError::InvalidPattern {
                    reason: "character class range endpoints are reversed",
                });
            }

            ranges.push(PatternRange::Span(start, end));
            continue;
        }

        ranges.push(PatternRange::Single(start));
    }

    Ok(ranges)
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

    // 2 loads for start/end, 1 loop index init, 1 bounds setup,
    // and 2 instructions per literal byte plus fixed control-flow.
    10 + pattern_len * 2
}

pub(crate) fn estimate_character_class_instructions(ranges: &[PatternRange]) -> usize {
    if ranges.is_empty() {
        return 2;
    }

    // Single-byte comparisons use 1 instruction and span comparisons use 3.
    // Always include false/true return blocks.
    let compare_count = ranges.iter().fold(0usize, |acc, range| match range {
        PatternRange::Single(_) => acc + 1,
        PatternRange::Span(_, _) => acc + 3,
    });
    2 + compare_count
}

pub(crate) fn estimate_alternation_instructions(alternatives: &[&[u8]]) -> usize {
    if alternatives.is_empty() || alternatives.iter().any(|alt| alt.is_empty()) {
        return 2;
    }

    // per alternative:
    // 1 bound check, one load+compare per byte, one match jump.
    let alternative_count = alternatives.iter().map(|alt| {
        if alt.is_empty() {
            0
        } else {
            1 + (alt.len() * 2) + 1
        }
    });

    2 + alternative_count.sum::<usize>()
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
                reason: "unterminated character-class range escape"
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
        assert_eq!(literal_search_instruction_count(3), 16);
    }

    #[test]
    fn range_estimate_is_non_empty_for_singleton() {
        let ranges = vec![PatternRange::Single(0x41)];
        assert_eq!(estimate_character_class_instructions(&ranges), 3);
    }

    #[test]
    fn alternation_estimate_counts_bound_checks() {
        let alternates: Vec<&[u8]> = vec![b"aa", b"b"];
        assert_eq!(
            estimate_alternation_instructions(&alternates),
            2 + ((1 + 4 + 1) + (1 + 2 + 1))
        );
    }
}
