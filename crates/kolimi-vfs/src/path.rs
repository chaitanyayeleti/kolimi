use crate::error::PathError;

/// Maximum number of segments in a path.
pub const MAX_DEPTH: usize = 256;
/// Maximum length of a single path segment in bytes.
// Client-side encrypted names are stored as opaque `k1_…` segments and
// are longer than the plaintext they hide (a 255-byte name encodes to ~400
// bytes), so the server cap is raised accordingly. WebDAV never sees these
// names: encrypted subtrees reject DAV writes.
pub const MAX_SEGMENT_LEN: usize = 512;

/// Splits a path into validated segments.
///
/// Leading, trailing, and repeated slashes are tolerated and ignored.
/// `.`, `..`, control characters, NUL, and over-long segments are rejected.
pub fn parse(path: &str) -> Result<Vec<String>, PathError> {
    let mut segments = Vec::new();
    for raw in path.split('/') {
        if raw.is_empty() {
            continue;
        }
        if raw == "." || raw == ".." {
            return Err(PathError::Segment(raw.to_string()));
        }
        if raw.len() > MAX_SEGMENT_LEN {
            return Err(PathError::Segment(raw.to_string()));
        }
        if raw.chars().any(|c| c.is_control() || c == '\0') {
            return Err(PathError::Segment(raw.to_string()));
        }
        segments.push(raw.to_string());
    }
    if segments.len() > MAX_DEPTH {
        return Err(PathError::TooDeep);
    }
    Ok(segments)
}

/// Joins segments back into an absolute path string.
pub fn join(segments: &[String]) -> String {
    let mut path = String::from("/");
    path.push_str(&segments.join("/"));
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_paths() {
        assert_eq!(parse("/a/b/c").unwrap(), vec!["a", "b", "c"]);
        assert_eq!(parse("a/b").unwrap(), vec!["a", "b"]);
        assert_eq!(parse("/").unwrap(), Vec::<String>::new());
        assert_eq!(parse("").unwrap(), Vec::<String>::new());
        assert_eq!(parse("//a//b//").unwrap(), vec!["a", "b"]);
    }

    #[test]
    fn rejects_traversal_segments() {
        assert!(parse("/a/../b").is_err());
        assert!(parse("/a/./b").is_err());
        assert!(parse("..").is_err());
        assert!(parse(".").is_err());
    }

    #[test]
    fn rejects_control_characters_and_nul() {
        assert!(parse("/a\u{0000}b").is_err());
        assert!(parse("/a\nb").is_err());
        assert!(parse("/a\tb").is_err());
    }

    #[test]
    fn rejects_overlong_names_and_deep_paths() {
        let long = "x".repeat(513);
        assert!(parse(&format!("/{long}")).is_err());

        let deep: Vec<String> = (0..300).map(|i| format!("s{i}")).collect();
        assert!(parse(&format!("/{}", deep.join("/"))).is_err());
    }

    #[test]
    fn join_roundtrips() {
        let segments = parse("/a/b/c").unwrap();
        assert_eq!(join(&segments), "/a/b/c");
        assert_eq!(join(&[]), "/");
    }
}
