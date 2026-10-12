//! RFC 7233 byte-range parsing for `GET`/`HEAD`.
//!
//! Only a single range is supported; multi-range requests fall back to the
//! full representation (a server is always free to ignore `Range`), and
//! syntactically valid but out-of-bounds ranges yield `416`.

/// Outcome of parsing a `Range` header against a known content length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeOutcome {
    /// No usable range; serve the full representation with `200`.
    Full,
    /// Valid syntax but nothing overlaps the representation (`416`).
    Unsatisfiable,
    /// Serve bytes `start..end` (end exclusive) with `206`.
    Satisfiable {
        /// First byte, inclusive.
        start: u64,
        /// One past the last byte.
        end: u64,
    },
}

/// Parses a `Range` header for a representation of `size` bytes.
pub fn parse(header: &str, size: u64) -> RangeOutcome {
    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return RangeOutcome::Full;
    };
    // Multiple ranges are not supported; serve the whole entity instead.
    if spec.contains(',') {
        return RangeOutcome::Full;
    }
    let Some((start_s, end_s)) = spec.split_once('-') else {
        return RangeOutcome::Full;
    };
    let start_s = start_s.trim();
    let end_s = end_s.trim();

    if start_s.is_empty() {
        // Suffix range: the final `end_s` bytes.
        let Ok(suffix) = end_s.parse::<u64>() else {
            return RangeOutcome::Full;
        };
        if suffix == 0 || size == 0 {
            return RangeOutcome::Unsatisfiable;
        }
        return RangeOutcome::Satisfiable {
            start: size.saturating_sub(suffix),
            end: size,
        };
    }

    let Ok(start) = start_s.parse::<u64>() else {
        return RangeOutcome::Full;
    };
    if start >= size {
        return RangeOutcome::Unsatisfiable;
    }
    let end = if end_s.is_empty() {
        size
    } else {
        let Ok(last) = end_s.parse::<u64>() else {
            return RangeOutcome::Full;
        };
        if last < start {
            return RangeOutcome::Full;
        }
        (last + 1).min(size)
    };
    RangeOutcome::Satisfiable { start, end }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_when_absent_or_malformed() {
        assert_eq!(parse("items=0-1", 100), RangeOutcome::Full);
        assert_eq!(parse("bytes=abc-", 100), RangeOutcome::Full);
        assert_eq!(parse("bytes=-abc", 100), RangeOutcome::Full);
        assert_eq!(parse("bytes=0-1,4-5", 100), RangeOutcome::Full);
    }

    #[test]
    fn bounded_and_open_ranges() {
        assert_eq!(
            parse("bytes=0-9", 100),
            RangeOutcome::Satisfiable { start: 0, end: 10 }
        );
        assert_eq!(
            parse("bytes=90-", 100),
            RangeOutcome::Satisfiable {
                start: 90,
                end: 100
            }
        );
        assert_eq!(
            parse("bytes=10-200", 100),
            RangeOutcome::Satisfiable {
                start: 10,
                end: 100
            }
        );
    }

    #[test]
    fn suffix_range() {
        assert_eq!(
            parse("bytes=-10", 100),
            RangeOutcome::Satisfiable {
                start: 90,
                end: 100
            }
        );
        assert_eq!(
            parse("bytes=-1000", 100),
            RangeOutcome::Satisfiable { start: 0, end: 100 }
        );
        assert_eq!(parse("bytes=-0", 100), RangeOutcome::Unsatisfiable);
    }

    #[test]
    fn unsatisfiable_when_start_past_end() {
        assert_eq!(parse("bytes=100-", 100), RangeOutcome::Unsatisfiable);
        assert_eq!(parse("bytes=5-", 0), RangeOutcome::Unsatisfiable);
    }
}
