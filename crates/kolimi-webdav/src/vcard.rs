//! vCard (RFC 6350/2426) validation for CardDAV object uploads.
//!
//! Apple and Thunderbird still send vCard 3.0, so validation is structural
//! (one vCard per resource, a VERSION, a UID) rather than a strict 4.0
//! parse. Values are preserved byte-for-byte.

/// Why a vCard payload was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VcardError {
    /// Not exactly one BEGIN:VCARD..END:VCARD block.
    #[error("malformed vCard data")]
    Malformed,
    /// No VERSION property.
    #[error("vCard is missing VERSION")]
    MissingVersion,
    /// No UID property (CardDAV requires one per resource).
    #[error("vCard is missing UID")]
    MissingUid,
}

/// Unfolds content lines (RFC 6350 §3.2): a CRLF followed by a space or tab
/// continues the previous line.
fn unfold(data: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for raw in data.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(continuation) = line.strip_prefix([' ', '\t'])
            && let Some(last) = lines.last_mut()
        {
            last.push_str(continuation);
            continue;
        }
        lines.push(line.to_string());
    }
    lines
}

/// Extracts the value of a property, honouring parameters (`UID;x=1:v`) and
/// grouping prefixes (`item1.UID`).
fn property_value(line: &str, name: &str) -> Option<String> {
    let (key, value) = line.split_once(':')?;
    let key = key.split(';').next()?;
    let base = key.rsplit('.').next().unwrap_or(key);
    if base.eq_ignore_ascii_case(name) {
        Some(value.trim().to_string())
    } else {
        None
    }
}

/// Validates a vCard object resource and returns its UID.
pub fn validate_vcard(data: &str) -> Result<String, VcardError> {
    let data = data.strip_prefix('\u{feff}').unwrap_or(data);
    let lines = unfold(data);
    let begin = lines
        .first()
        .map(|line| line.trim().eq_ignore_ascii_case("BEGIN:VCARD"))
        .unwrap_or(false);
    let end = lines
        .iter()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().eq_ignore_ascii_case("END:VCARD"))
        .unwrap_or(false);
    if !begin || !end {
        return Err(VcardError::Malformed);
    }

    let mut version = false;
    let mut uid: Option<String> = None;
    let mut begins = 0u32;
    let mut ends = 0u32;
    for line in &lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.eq_ignore_ascii_case("BEGIN:VCARD") {
            begins += 1;
            continue;
        }
        if trimmed.eq_ignore_ascii_case("END:VCARD") {
            ends += 1;
            continue;
        }
        if property_value(trimmed, "VERSION").is_some() {
            version = true;
        }
        if let Some(value) = property_value(trimmed, "UID")
            && !value.is_empty()
        {
            uid = Some(value);
        }
        // Nested components are not allowed in a single object resource.
        if trimmed.to_ascii_uppercase().starts_with("BEGIN:V") {
            return Err(VcardError::Malformed);
        }
    }
    if begins != 1 || ends != 1 {
        return Err(VcardError::Malformed);
    }
    if !version {
        return Err(VcardError::MissingVersion);
    }
    uid.ok_or(VcardError::MissingUid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V3: &str = "BEGIN:VCARD\r\n\
VERSION:3.0\r\n\
UID:contact-1\r\n\
FN:Ada Lovelace\r\n\
N:Lovelace;Ada;;;\r\n\
EMAIL:ada@example.com\r\n\
END:VCARD\r\n";

    #[test]
    fn accepts_vcard_30() {
        assert_eq!(validate_vcard(V3).unwrap(), "contact-1");
    }

    #[test]
    fn accepts_vcard_40_with_parameters_and_folding() {
        let data = "BEGIN:VCARD\nVERSION:4.0\nUID;X-CUSTOM=1:contact-\n 2\nFN:Ada\nEND:VCARD\n";
        assert_eq!(validate_vcard(data).unwrap(), "contact-2");
    }

    #[test]
    fn rejects_malformed_blocks() {
        assert_eq!(validate_vcard("hello"), Err(VcardError::Malformed));
        assert_eq!(
            validate_vcard(
                "BEGIN:VCARD\r\nVERSION:3.0\r\nEND:VCARD\r\nBEGIN:VCARD\r\nEND:VCARD\r\n"
            ),
            Err(VcardError::Malformed)
        );
    }

    #[test]
    fn rejects_missing_version_or_uid() {
        assert_eq!(
            validate_vcard("BEGIN:VCARD\r\nUID:x\r\nFN:x\r\nEND:VCARD\r\n"),
            Err(VcardError::MissingVersion)
        );
        assert_eq!(
            validate_vcard("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:x\r\nEND:VCARD\r\n"),
            Err(VcardError::MissingUid)
        );
    }
}
