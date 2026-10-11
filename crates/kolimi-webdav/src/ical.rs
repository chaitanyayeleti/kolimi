//! iCalendar (RFC 5545) validation for CalDAV object uploads.
//!
//! Parsing is delegated to the `icalendar` crate's raw parser; this module
//! enforces the CalDAV structural rules (RFC 4791 §4.1): one VCALENDAR per
//! resource, at least one schedulable component, a UID on every component,
//! and one shared UID across all components.

/// Why an iCalendar payload was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IcalError {
    /// The payload is not a syntactically valid VCALENDAR.
    #[error("malformed iCalendar data")]
    Malformed,
    /// No VEVENT/VTODO/VJOURNAL/VFREEBUSY component.
    #[error("calendar contains no schedulable component")]
    NoComponent,
    /// A component is missing its UID.
    #[error("calendar component is missing a UID")]
    MissingUid,
    /// Components disagree about the UID.
    #[error("calendar components must share one UID")]
    InconsistentUid,
}

/// Validates a calendar object resource and returns its UID.
pub fn validate_calendar(data: &str) -> Result<String, IcalError> {
    let unfolded = icalendar::parser::unfold(data);
    let calendar = icalendar::parser::read_calendar(&unfolded).map_err(|_| IcalError::Malformed)?;

    let mut uid: Option<String> = None;
    let mut found = false;
    for component in &calendar.components {
        let name = component.name.as_ref().to_ascii_uppercase();
        if !matches!(name.as_str(), "VEVENT" | "VTODO" | "VJOURNAL" | "VFREEBUSY") {
            continue;
        }
        found = true;
        let component_uid = component
            .find_prop("UID")
            .map(|property| property.val.as_ref().trim().to_string())
            .filter(|value| !value.is_empty());
        match component_uid {
            Some(value) => match &uid {
                None => uid = Some(value),
                Some(existing) if *existing == value => {}
                Some(_) => return Err(IcalError::InconsistentUid),
            },
            None => return Err(IcalError::MissingUid),
        }
    }
    if !found {
        return Err(IcalError::NoComponent);
    }
    uid.ok_or(IcalError::MissingUid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENT: &str = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//Kolimi//Test//EN\r\n\
BEGIN:VEVENT\r\n\
UID:event-1@example.com\r\n\
DTSTAMP:20261011T000000Z\r\n\
DTSTART:20261012T090000Z\r\n\
DTEND:20261012T100000Z\r\n\
SUMMARY:Standup\r\n\
BEGIN:VALARM\r\n\
ACTION:DISPLAY\r\n\
DESCRIPTION:Reminder\r\n\
TRIGGER:-PT15M\r\n\
END:VALARM\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

    #[test]
    fn extracts_uid_from_event() {
        assert_eq!(validate_calendar(EVENT).unwrap(), "event-1@example.com");
    }

    #[test]
    fn accepts_multiple_components_with_one_uid() {
        let data = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
BEGIN:VEVENT\r\nUID:shared-1\r\nDTSTART:20261012T090000Z\r\nEND:VEVENT\r\n\
BEGIN:VEVENT\r\nUID:shared-1\r\nDTSTART:20261013T090000Z\r\nEND:VEVENT\r\n\
END:VCALENDAR\r\n";
        assert_eq!(validate_calendar(data).unwrap(), "shared-1");
    }

    #[test]
    fn accepts_unfolded_lines() {
        let data = "BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nUID:long-\n  uid\nEND:VEVENT\nEND:VCALENDAR\n";
        assert_eq!(validate_calendar(data).unwrap(), "long- uid");
    }

    #[test]
    fn rejects_malformed_payloads() {
        assert_eq!(
            validate_calendar("not a calendar"),
            Err(IcalError::Malformed)
        );
        assert_eq!(
            validate_calendar("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n"),
            Err(IcalError::NoComponent)
        );
    }

    #[test]
    fn rejects_missing_and_conflicting_uids() {
        let missing = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
BEGIN:VEVENT\r\nDTSTART:20261012T090000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert_eq!(validate_calendar(missing), Err(IcalError::MissingUid));

        let conflicting = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
BEGIN:VEVENT\r\nUID:a\r\nDTSTART:20261012T090000Z\r\nEND:VEVENT\r\n\
BEGIN:VTODO\r\nUID:b\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
        assert_eq!(
            validate_calendar(conflicting),
            Err(IcalError::InconsistentUid)
        );
    }

    #[test]
    fn accepts_todos_and_journals() {
        let todo = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\n\
BEGIN:VTODO\r\nUID:todo-1\r\nDUE:20261012T090000Z\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
        assert_eq!(validate_calendar(todo).unwrap(), "todo-1");
    }
}
