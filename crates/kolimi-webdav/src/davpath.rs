use kolimi_vfs::path::MAX_SEGMENT_LEN;
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};

const SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// Decodes a raw WebDAV path (the part after `/dav`) into VFS segments.
///
/// Percent-decodes every segment and applies the same validation as the
/// VFS: no `.`, `..`, NUL, control characters, embedded slashes, or
/// oversized segments. Repeated and trailing slashes are ignored.
pub fn to_segments(raw: &str) -> Result<Vec<String>, ()> {
    let mut segments = Vec::new();
    for segment in raw.split('/') {
        if segment.is_empty() {
            continue;
        }
        let decoded = percent_decode_str(segment).decode_utf8().map_err(|_| ())?;
        let decoded = decoded.as_ref();
        if decoded.is_empty() || decoded == "." || decoded == ".." {
            return Err(());
        }
        if decoded.contains('/') || decoded.contains('\0') {
            return Err(());
        }
        if decoded.chars().any(char::is_control) {
            return Err(());
        }
        if decoded.len() > MAX_SEGMENT_LEN {
            return Err(());
        }
        segments.push(decoded.to_string());
    }
    Ok(segments)
}

/// Decodes a raw WebDAV path into a joined VFS path.
pub fn to_vfs_path(raw: &str) -> Result<String, ()> {
    Ok(kolimi_vfs::path::join(&to_segments(raw)?))
}

/// Encodes VFS segments into a WebDAV href (root is `/dav/`).
pub fn encode_href(segments: &[String]) -> String {
    if segments.is_empty() {
        return "/dav/".to_string();
    }
    let encoded: Vec<String> = segments
        .iter()
        .map(|s| utf8_percent_encode(s, SEGMENT).to_string())
        .collect();
    format!("/dav/{}", encoded.join("/"))
}

/// Parses a `Destination` header value (absolute URI or path) into a VFS path.
pub fn destination_to_vfs_path(value: &str) -> Option<String> {
    let path = if value.starts_with('/') {
        value.split(['?', '#']).next()?.to_string()
    } else {
        let uri: axum::http::Uri = value.parse().ok()?;
        uri.path().to_string()
    };
    let rest = path.strip_prefix("/dav")?;
    to_vfs_path(rest).ok()
    // A destination of exactly the server root maps to "/"; handled by caller.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_simple_and_encoded_segments() {
        assert_eq!(to_vfs_path("").unwrap(), "/");
        assert_eq!(to_vfs_path("/").unwrap(), "/");
        assert_eq!(to_vfs_path("/docs/report.txt").unwrap(), "/docs/report.txt");
        assert_eq!(
            to_vfs_path("/docs/my%20report.txt").unwrap(),
            "/docs/my report.txt"
        );
        assert_eq!(to_vfs_path("/%C3%BCber/").unwrap(), "/über");
        assert_eq!(to_vfs_path("/a//b").unwrap(), "/a/b");
    }

    #[test]
    fn rejects_traversal_and_encoded_slashes() {
        assert!(to_vfs_path("/../etc/passwd").is_err());
        assert!(to_vfs_path("/%2e%2e/x").is_err());
        assert!(to_vfs_path("/a%2Fb").is_err());
        assert!(to_vfs_path("/%00").is_err());
        assert!(to_vfs_path("/a%01b").is_err());
        assert!(to_vfs_path("/%ff%fe").is_err());
    }

    #[test]
    fn encodes_hrefs_without_over_encoding() {
        let segments = vec!["docs".to_string(), "my report.txt".to_string()];
        assert_eq!(encode_href(&segments), "/dav/docs/my%20report.txt");
        assert_eq!(encode_href(&[]), "/dav/");
        let unicode = vec!["über".to_string()];
        assert_eq!(encode_href(&unicode), "/dav/%C3%BCber");
    }

    #[test]
    fn parses_absolute_and_relative_destinations() {
        assert_eq!(
            destination_to_vfs_path("http://localhost:8080/dav/a/b.txt").unwrap(),
            "/a/b.txt"
        );
        assert_eq!(
            destination_to_vfs_path("/dav/a%20b.txt").unwrap(),
            "/a b.txt"
        );
        assert_eq!(destination_to_vfs_path("/dav/").unwrap(), "/");
        assert!(destination_to_vfs_path("/other/x").is_none());
        assert!(destination_to_vfs_path("http://localhost/dav/../x").is_none());
    }
}
