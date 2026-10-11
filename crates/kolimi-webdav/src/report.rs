//! REPORT request parsing (RFC 3253 core + RFC 6578 `sync-collection`,
//! CalDAV/CardDAV query and multiget reports).

use quick_xml::events::Event;

use crate::xml::{RequestedProp, Scope, collect_attrs};

/// CalDAV namespace.
pub const CALDAV_NS: &str = "urn:ietf:params:xml:ns:caldav";
/// CardDAV namespace.
pub const CARDDAV_NS: &str = "urn:ietf:params:xml:ns:carddav";
/// CalendarServer extension namespace (`getctag`).
pub const CS_NS: &str = "http://calendarserver.org/ns/";
/// Apple iCalendar extension namespace (`calendar-color`).
pub const APPLE_NS: &str = "http://apple.com/ns/ical/";

const DAV_NS: &str = "DAV:";

/// Which properties a report asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportProps {
    /// No `prop` element: return a default set.
    Default,
    /// `<allprop/>`: return the full defined set.
    All,
    /// Exactly these properties.
    Only(Vec<RequestedProp>),
}

/// A parsed REPORT request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    /// RFC 6578 `sync-collection`.
    SyncCollection {
        /// Client's sync token (`None` = initial sync).
        sync_token: Option<String>,
        /// Requested sync level (`1` supported; `0` = infinite).
        level: u32,
        /// Requested properties.
        props: ReportProps,
    },
    /// CalDAV `calendar-query` (filters are not evaluated; the full
    /// collection is returned).
    CalendarQuery {
        /// Requested properties.
        props: ReportProps,
    },
    /// CalDAV `calendar-multiget`.
    CalendarMultiget {
        /// Requested hrefs.
        hrefs: Vec<String>,
        /// Requested properties.
        props: ReportProps,
    },
    /// CardDAV `addressbook-query`.
    AddressbookQuery {
        /// Requested properties.
        props: ReportProps,
    },
    /// CardDAV `addressbook-multiget`.
    AddressbookMultiget {
        /// Requested hrefs.
        hrefs: Vec<String>,
        /// Requested properties.
        props: ReportProps,
    },
}

/// Parses a REPORT body. Malformed XML or an unknown report type is an
/// error (the caller returns 400/403).
pub fn parse_report(body: &[u8]) -> Result<Report, ()> {
    if body.is_empty() {
        return Err(());
    }
    let mut reader = quick_xml::Reader::from_reader(body);
    reader.config_mut().trim_text(false);

    let mut scope = Scope::new();
    let mut stack: Vec<(String, Option<String>)> = Vec::new();
    let mut root: Option<(String, Option<String>)> = None;
    let mut props: Vec<RequestedProp> = Vec::new();
    let mut hrefs: Vec<String> = Vec::new();
    let mut sync_token: Option<String> = None;
    let mut level: Option<u32> = None;
    let mut allprop = false;
    let mut saw_prop = false;
    let mut capture: Option<CaptureKind> = None;
    let mut buffer = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = e.name().as_ref().to_string();
                let attrs = collect_attrs(&e)?;
                scope.push_element(&attrs)?;
                let (local, ns) = scope.resolve_name(&name);
                if stack.is_empty() {
                    if root.is_some() {
                        return Err(());
                    }
                    root = Some((local.clone(), ns.clone()));
                } else {
                    let parent = stack.last().cloned();
                    let in_prop = parent
                        .as_ref()
                        .is_some_and(|(l, n)| l == "prop" && n.as_deref() == Some(DAV_NS));
                    if in_prop {
                        saw_prop = true;
                        props.push(RequestedProp {
                            raw: name.clone(),
                            local: local.clone(),
                            namespace: ns.clone(),
                        });
                    } else if local == "allprop" && ns.as_deref() == Some(DAV_NS) {
                        allprop = true;
                    } else if local == "sync-token" && ns.as_deref() == Some(DAV_NS) {
                        capture = Some(CaptureKind::SyncToken);
                        buffer.clear();
                    } else if local == "sync-level" && ns.as_deref() == Some(DAV_NS) {
                        capture = Some(CaptureKind::SyncLevel);
                        buffer.clear();
                    } else if local == "href" && ns.as_deref() == Some(DAV_NS) {
                        capture = Some(CaptureKind::Href);
                        buffer.clear();
                    }
                }
                stack.push((local, ns));
            }
            Ok(Event::Empty(e)) => {
                let name = e.name().as_ref().to_string();
                let attrs = collect_attrs(&e)?;
                scope.push_element(&attrs)?;
                let (local, ns) = scope.resolve_name(&name);
                scope.pop_element();
                if stack.is_empty() {
                    return Err(());
                }
                let parent = stack.last().cloned();
                let in_prop = parent
                    .as_ref()
                    .is_some_and(|(l, n)| l == "prop" && n.as_deref() == Some(DAV_NS));
                if in_prop {
                    saw_prop = true;
                    props.push(RequestedProp {
                        raw: name,
                        local,
                        namespace: ns,
                    });
                } else if local == "allprop" && ns.as_deref() == Some(DAV_NS) {
                    allprop = true;
                }
            }
            Ok(Event::Text(text)) => {
                if capture.is_some() {
                    let raw = text.into_inner();
                    let unescaped = quick_xml::escape::unescape(raw.as_ref()).map_err(|_| ())?;
                    buffer.push_str(&unescaped);
                }
            }
            Ok(Event::CData(text)) => {
                if capture.is_some() {
                    buffer.push_str(&text.into_inner());
                }
            }
            Ok(Event::GeneralRef(reference)) => {
                if capture.is_some() {
                    buffer.push_str(&reference_name(&reference.into_inner())?);
                }
            }
            Ok(Event::End(end)) => {
                scope.pop_element();
                let Some((local, ns)) = stack.pop() else {
                    return Err(());
                };
                if let Some(kind) = &capture
                    && kind.matches(&local, ns.as_deref())
                {
                    let value = buffer.trim().to_string();
                    buffer.clear();
                    match kind {
                        CaptureKind::SyncToken => sync_token = Some(value),
                        CaptureKind::SyncLevel => {
                            level = Some(match value.as_str() {
                                "1" => 1,
                                "infinite" => 0,
                                _ => return Err(()),
                            });
                        }
                        CaptureKind::Href => {
                            if !value.is_empty() {
                                hrefs.push(value);
                            }
                        }
                    }
                    capture = None;
                }
                let _ = end;
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(()),
        }
    }

    if !stack.is_empty() || capture.is_some() {
        return Err(());
    }
    let Some((local, ns)) = root else {
        return Err(());
    };
    let props = if allprop {
        ReportProps::All
    } else if saw_prop {
        ReportProps::Only(props)
    } else {
        ReportProps::Default
    };

    match (local.as_str(), ns.as_deref()) {
        ("sync-collection", Some(DAV_NS)) => Ok(Report::SyncCollection {
            sync_token,
            level: level.unwrap_or(1),
            props,
        }),
        ("calendar-query", Some(CALDAV_NS)) => Ok(Report::CalendarQuery { props }),
        ("calendar-multiget", Some(CALDAV_NS)) => Ok(Report::CalendarMultiget { hrefs, props }),
        ("addressbook-query", Some(CARDDAV_NS)) => Ok(Report::AddressbookQuery { props }),
        ("addressbook-multiget", Some(CARDDAV_NS)) => {
            Ok(Report::AddressbookMultiget { hrefs, props })
        }
        _ => Err(()),
    }
}

enum CaptureKind {
    SyncToken,
    SyncLevel,
    Href,
}

impl CaptureKind {
    fn matches(&self, local: &str, ns: Option<&str>) -> bool {
        ns == Some(DAV_NS)
            && matches!(
                (self, local),
                (Self::SyncToken, "sync-token")
                    | (Self::SyncLevel, "sync-level")
                    | (Self::Href, "href")
            )
    }
}

fn reference_name(name: &str) -> Result<String, ()> {
    match name {
        "amp" => Ok("&".to_string()),
        "lt" => Ok("<".to_string()),
        "gt" => Ok(">".to_string()),
        "quot" => Ok("\"".to_string()),
        "apos" => Ok("'".to_string()),
        other if other.starts_with('#') => {
            let number = &other[1..];
            let (radix, digits) = match number.strip_prefix(['x', 'X']) {
                Some(hex) => (16, hex),
                None => (10, number),
            };
            let codepoint = u32::from_str_radix(digits, radix).map_err(|_| ())?;
            char::from_u32(codepoint).map(|c| c.to_string()).ok_or(())
        }
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sync_collection_initial() {
        let body = br#"<?xml version="1.0"?>
            <d:sync-collection xmlns:d="DAV:">
              <d:sync-level>1</d:sync-level>
              <d:prop><d:getetag/><d:getcontenttype/></d:prop>
            </d:sync-collection>"#;
        let report = parse_report(body).unwrap();
        let Report::SyncCollection {
            sync_token,
            level,
            props,
        } = report
        else {
            panic!("wrong report");
        };
        assert!(sync_token.is_none());
        assert_eq!(level, 1);
        let ReportProps::Only(list) = props else {
            panic!("wrong props");
        };
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].local, "getetag");
    }

    #[test]
    fn parses_sync_collection_with_token() {
        let body = br#"<d:sync-collection xmlns:d="DAV:">
              <d:sync-token>urn:kolimi:sync:7:42</d:sync-token>
              <d:sync-level>1</d:sync-level>
              <d:prop><d:getetag/></d:prop>
            </d:sync-collection>"#;
        let Report::SyncCollection { sync_token, .. } = parse_report(body).unwrap() else {
            panic!("wrong report");
        };
        assert_eq!(sync_token.as_deref(), Some("urn:kolimi:sync:7:42"));
    }

    #[test]
    fn parses_calendar_multiget_hrefs() {
        let body = br#"<c:calendar-multiget xmlns:d="DAV:"
              xmlns:c="urn:ietf:params:xml:ns:caldav">
              <d:prop><d:getetag/><c:calendar-data/></d:prop>
              <d:href>/dav/calendars/alice/work/a.ics</d:href>
              <d:href>/dav/calendars/alice/work/b.ics</d:href>
            </c:calendar-multiget>"#;
        let Report::CalendarMultiget { hrefs, props } = parse_report(body).unwrap() else {
            panic!("wrong report");
        };
        assert_eq!(hrefs.len(), 2);
        let ReportProps::Only(list) = props else {
            panic!("wrong props");
        };
        assert_eq!(list[1].namespace.as_deref(), Some(CALDAV_NS));
    }

    #[test]
    fn parses_queries_and_allprop() {
        let body = br#"<c:calendar-query xmlns:d="DAV:"
              xmlns:c="urn:ietf:params:xml:ns:caldav">
              <d:prop><d:getetag/></d:prop>
              <c:filter><c:comp-filter name="VCALENDAR"/></c:filter>
            </c:calendar-query>"#;
        assert!(matches!(
            parse_report(body).unwrap(),
            Report::CalendarQuery { .. }
        ));

        let body = br#"<card:addressbook-query xmlns:d="DAV:"
              xmlns:card="urn:ietf:params:xml:ns:carddav">
              <d:allprop/>
            </card:addressbook-query>"#;
        let Report::AddressbookQuery { props } = parse_report(body).unwrap() else {
            panic!("wrong report");
        };
        assert_eq!(props, ReportProps::All);
    }

    #[test]
    fn rejects_unknown_or_malformed_reports() {
        assert!(parse_report(b"").is_err());
        assert!(parse_report(b"<d:expand-property xmlns:d='DAV:'/>").is_err());
        assert!(parse_report(b"<d:sync-collection xmlns:d='DAV:'>").is_err());
        assert!(
            parse_report(
                b"<d:sync-collection xmlns:d='DAV:'><d:sync-level>2</d:sync-level></d:sync-collection>"
            )
            .is_err()
        );
    }
}
