use quick_xml::{
    Reader, Writer,
    events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event},
};

use crate::cond;
use crate::davpath;

type QResult<T = ()> = Result<T, quick_xml::Error>;

const SUPPORTED: &[&str] = &[
    "displayname",
    "resourcetype",
    "getcontentlength",
    "getcontenttype",
    "getlastmodified",
    "getetag",
    "creationdate",
];

/// What a PROPFIND request asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestedProps {
    /// Every supported property with its value.
    All,
    /// Every supported property name, no values.
    Names,
    /// Exactly these properties (by local name, prefix stripped).
    Only(Vec<String>),
}

/// Parses a PROPFIND body. An empty body means `allprop`.
pub fn parse_propfind(body: &[u8]) -> Result<RequestedProps, ()> {
    if body.is_empty() {
        return Ok(RequestedProps::All);
    }
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut only: Vec<String> = Vec::new();
    let mut saw_children = false;
    let mut names_mode = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = e.name().as_ref().to_string();
                note_element(&name, &stack, &mut names_mode, &mut saw_children, &mut only);
                stack.push(name);
            }
            Ok(Event::Empty(e)) => {
                let name = e.name().as_ref().to_string();
                note_element(&name, &stack, &mut names_mode, &mut saw_children, &mut only);
            }
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(()),
        }
    }

    if names_mode {
        Ok(RequestedProps::Names)
    } else if saw_children {
        Ok(RequestedProps::Only(only))
    } else {
        Ok(RequestedProps::All)
    }
}

fn note_element(
    name: &str,
    stack: &[String],
    names_mode: &mut bool,
    saw_children: &mut bool,
    only: &mut Vec<String>,
) {
    let local = local_name(name);
    match local {
        "propname" => *names_mode = true,
        "allprop" => {}
        _ => {}
    }
    if stack
        .last()
        .is_some_and(|parent| local_name(parent) == "prop")
    {
        *saw_children = true;
        only.push(name.to_string());
    }
}

fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

/// One resource in a multistatus response.
pub struct PropEntry {
    /// Encoded href.
    pub href: String,
    /// Display name (root shows `/`).
    pub display_name: String,
    /// Whether the resource is a collection.
    pub is_dir: bool,
    /// Size in bytes.
    pub size: u64,
    /// Guessed content type for files.
    pub content_type: Option<String>,
    /// Last modification time in Unix milliseconds.
    pub modified_ms: i64,
    /// Creation time in Unix milliseconds.
    pub created_ms: i64,
    /// Pre-quoted ETag.
    pub etag: String,
}

impl PropEntry {
    /// Builds an entry from resolved VFS segments and a node.
    pub fn new(segments: &[String], node: &kolimi_vfs::Node) -> Self {
        let display_name = if segments.is_empty() {
            "/".to_string()
        } else {
            node.name.clone()
        };
        let content_type = if node.is_dir() {
            None
        } else {
            Some(
                mime_guess::from_path(&node.name)
                    .first_or_octet_stream()
                    .to_string(),
            )
        };
        Self {
            href: davpath::encode_href(segments),
            display_name,
            is_dir: node.is_dir(),
            size: node.size,
            content_type,
            modified_ms: node.modified_at,
            created_ms: node.created_at,
            etag: node.etag(),
        }
    }
}

/// Renders a `207 Multi-Status` body.
pub fn multistatus(entries: &[PropEntry], requested: &RequestedProps) -> QResult<Vec<u8>> {
    let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);
    w.write_event(Event::Decl(BytesDecl::new("1.0", Some("utf-8"), None)))?;

    let mut ms = BytesStart::new("d:multistatus");
    ms.push_attribute(("xmlns:d", "DAV:"));
    w.write_event(Event::Start(ms))?;

    for entry in entries {
        write_response(&mut w, entry, requested)?;
    }

    w.write_event(Event::End(BytesEnd::new("d:multistatus")))?;
    Ok(w.into_inner())
}

fn write_response(
    w: &mut Writer<Vec<u8>>,
    entry: &PropEntry,
    requested: &RequestedProps,
) -> QResult {
    let mut unsupported: Vec<String> = Vec::new();

    w.write_event(Event::Start(BytesStart::new("d:response")))?;
    text(w, "d:href", &entry.href)?;
    w.write_event(Event::Start(BytesStart::new("d:propstat")))?;
    w.write_event(Event::Start(BytesStart::new("d:prop")))?;

    match requested {
        RequestedProps::Names => {
            for name in SUPPORTED {
                w.create_element(format!("d:{name}")).write_empty()?;
            }
        }
        RequestedProps::All => {
            for name in SUPPORTED {
                write_prop(w, name, entry, false)?;
            }
        }
        RequestedProps::Only(list) => {
            let mut written: Vec<&str> = Vec::new();
            for raw in list {
                let local = local_name(raw);
                if SUPPORTED.contains(&local) {
                    if !written.contains(&local) {
                        write_prop(w, local, entry, false)?;
                        written.push(local);
                    }
                } else if is_valid_ncname(local) {
                    unsupported.push(local.to_string());
                } else {
                    unsupported.push("unknown".to_string());
                }
            }
        }
    }

    w.write_event(Event::End(BytesEnd::new("d:prop")))?;
    text(w, "d:status", "HTTP/1.1 200 OK")?;
    w.write_event(Event::End(BytesEnd::new("d:propstat")))?;

    if !unsupported.is_empty() {
        w.write_event(Event::Start(BytesStart::new("d:propstat")))?;
        w.write_event(Event::Start(BytesStart::new("d:prop")))?;
        for name in &unsupported {
            w.create_element(format!("d:{name}")).write_empty()?;
        }
        w.write_event(Event::End(BytesEnd::new("d:prop")))?;
        text(w, "d:status", "HTTP/1.1 404 Not Found")?;
        w.write_event(Event::End(BytesEnd::new("d:propstat")))?;
    }

    w.write_event(Event::End(BytesEnd::new("d:response")))?;
    Ok(())
}

fn write_prop(w: &mut Writer<Vec<u8>>, local: &str, entry: &PropEntry, _empty: bool) -> QResult {
    match local {
        "displayname" => text(w, "d:displayname", &entry.display_name)?,
        "resourcetype" => {
            if entry.is_dir {
                w.create_element("d:resourcetype")
                    .write_inner_content(|w| {
                        w.create_element("d:collection").write_empty()?;
                        Ok(())
                    })?;
            } else {
                w.create_element("d:resourcetype").write_empty()?;
            }
        }
        "getcontentlength" if !entry.is_dir => {
            text(w, "d:getcontentlength", &entry.size.to_string())?
        }
        "getcontenttype" if !entry.is_dir => {
            if let Some(content_type) = &entry.content_type {
                text(w, "d:getcontenttype", content_type)?;
            }
        }
        "getlastmodified" => text(w, "d:getlastmodified", &cond::http_date(entry.modified_ms))?,
        "getetag" => text(w, "d:getetag", &entry.etag)?,
        "creationdate" => text(w, "d:creationdate", &cond::rfc3339(entry.created_ms))?,
        _ => {}
    }
    Ok(())
}

fn text(w: &mut Writer<Vec<u8>>, name: &str, value: &str) -> QResult {
    w.create_element(name)
        .write_text_content(BytesText::new(value))?;
    Ok(())
}

fn is_valid_ncname(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_body_means_all() {
        assert_eq!(parse_propfind(b"").unwrap(), RequestedProps::All);
    }

    #[test]
    fn parses_allprop_and_propname() {
        let all = br#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:allprop/></d:propfind>"#;
        assert_eq!(parse_propfind(all).unwrap(), RequestedProps::All);
        let names = br#"<d:propfind xmlns:d="DAV:"><d:propname/></d:propfind>"#;
        assert_eq!(parse_propfind(names).unwrap(), RequestedProps::Names);
    }

    #[test]
    fn parses_specific_props() {
        let body = br#"<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
            <d:prop><d:displayname/><d:getetag/><oc:checksums/></d:prop>
        </d:propfind>"#;
        assert_eq!(
            parse_propfind(body).unwrap(),
            RequestedProps::Only(vec![
                "d:displayname".to_string(),
                "d:getetag".to_string(),
                "oc:checksums".to_string(),
            ])
        );
    }

    #[test]
    fn rejects_malformed_xml() {
        assert!(parse_propfind(b"<not-closed").is_err());
    }

    fn entry(name: &str, is_dir: bool) -> PropEntry {
        PropEntry {
            href: format!("/dav/{name}"),
            display_name: name.to_string(),
            is_dir,
            size: 5,
            content_type: Some("text/plain".to_string()),
            modified_ms: 0,
            created_ms: 0,
            etag: "\"abc\"".to_string(),
        }
    }

    #[test]
    fn renders_allprop_values() {
        let xml = multistatus(&[entry("a.txt", false)], &RequestedProps::All).unwrap();
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("<d:multistatus xmlns:d=\"DAV:\">"));
        assert!(text.contains("<d:href>/dav/a.txt</d:href>"));
        assert!(text.contains("<d:displayname>a.txt</d:displayname>"));
        assert!(text.contains("<d:getcontentlength>5</d:getcontentlength>"));
        assert!(text.contains("<d:getcontenttype>text/plain</d:getcontenttype>"));
        assert!(text.contains("<d:getetag>&quot;abc&quot;</d:getetag>"));
        assert!(text.contains("<d:status>HTTP/1.1 200 OK</d:status>"));
    }

    #[test]
    fn renders_collection_resourcetype() {
        let xml = multistatus(&[entry("docs", true)], &RequestedProps::All).unwrap();
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("<d:resourcetype>"));
        assert!(text.contains("<d:collection/>"));
        assert!(!text.contains("getcontentlength"));
    }

    #[test]
    fn unsupported_props_get_404_propstat() {
        let requested = RequestedProps::Only(vec![
            "d:displayname".to_string(),
            "oc:checksums".to_string(),
        ]);
        let xml = multistatus(&[entry("a.txt", false)], &requested).unwrap();
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("<d:displayname>a.txt</d:displayname>"));
        assert!(text.contains("<d:checksums/>"));
        assert!(text.contains("<d:status>HTTP/1.1 404 Not Found</d:status>"));
    }

    #[test]
    fn propname_returns_empty_names() {
        let xml = multistatus(&[entry("a.txt", false)], &RequestedProps::Names).unwrap();
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("<d:displayname/>"));
        assert!(!text.contains(">a.txt<"));
    }
}
