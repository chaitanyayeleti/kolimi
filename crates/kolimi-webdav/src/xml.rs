use std::collections::HashMap;

use quick_xml::{
    Reader, Writer,
    events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event},
};

use crate::cond;
use crate::davpath;

type QResult<T = ()> = Result<T, quick_xml::Error>;

const DAV_NS: &str = "DAV:";

const SUPPORTED: &[&str] = &[
    "displayname",
    "resourcetype",
    "getcontentlength",
    "getcontenttype",
    "getlastmodified",
    "getetag",
    "creationdate",
    "current-user-principal",
];

/// A property requested in a PROPFIND body, with its namespace resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedProp {
    /// Name as written in the request (may carry a prefix).
    pub raw: String,
    /// Local name.
    pub local: String,
    /// Resolved XML namespace; `None` when the name has no prefix and no
    /// default namespace applies.
    pub namespace: Option<String>,
}

/// What a PROPFIND request asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestedProps {
    /// Every supported property with its value.
    All,
    /// Every supported property name, no values.
    Names,
    /// Exactly these properties.
    Only(Vec<RequestedProp>),
}

/// One PROPPATCH operation, in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchOp {
    /// Set or replace a dead property.
    Set {
        /// Resolved namespace (empty string for no namespace).
        namespace: String,
        /// Local name.
        name: String,
        /// Text or inner-markup value.
        value: String,
    },
    /// Remove a dead property.
    Remove {
        /// Resolved namespace (empty string for no namespace).
        namespace: String,
        /// Local name.
        name: String,
    },
}

impl PatchOp {
    /// Namespace of the targeted property.
    pub fn namespace(&self) -> &str {
        match self {
            PatchOp::Set { namespace, .. } | PatchOp::Remove { namespace, .. } => namespace,
        }
    }

    /// Local name of the targeted property.
    pub fn name(&self) -> &str {
        match self {
            PatchOp::Set { name, .. } | PatchOp::Remove { name, .. } => name,
        }
    }
}

pub(crate) struct Scope {
    frames: Vec<HashMap<String, String>>,
}

impl Scope {
    pub(crate) fn new() -> Self {
        Self { frames: Vec::new() }
    }

    pub(crate) fn push_element(&mut self, attrs: &[(String, String)]) -> Result<(), ()> {
        let mut frame = HashMap::new();
        for (key, value) in attrs {
            if key == "xmlns" {
                // `xmlns=""` legally un-declares the default namespace.
                frame.insert(String::new(), value.clone());
            } else if let Some(prefix) = key.strip_prefix("xmlns:") {
                if value.is_empty() || prefix.is_empty() {
                    return Err(());
                }
                frame.insert(prefix.to_string(), value.clone());
            }
        }
        self.frames.push(frame);
        Ok(())
    }

    pub(crate) fn pop_element(&mut self) {
        self.frames.pop();
    }

    fn resolve(&self, prefix: Option<&str>) -> Option<String> {
        let key = prefix.unwrap_or("");
        for frame in self.frames.iter().rev() {
            if let Some(uri) = frame.get(key) {
                return Some(uri.clone());
            }
        }
        None
    }

    pub(crate) fn resolve_name(&self, qname: &str) -> (String, Option<String>) {
        match qname.split_once(':') {
            Some((prefix, local)) => (local.to_string(), self.resolve(Some(prefix))),
            None => (qname.to_string(), self.resolve(None)),
        }
    }
}

pub(crate) fn collect_attrs(element: &BytesStart<'_>) -> Result<Vec<(String, String)>, ()> {
    let mut out = Vec::new();
    for attr in element.attributes() {
        let attr = attr.map_err(|_| ())?;
        let key = attr.key.as_ref().to_string();
        let value = attr
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|_| ())?
            .into_owned();
        out.push((key, value));
    }
    Ok(out)
}

fn escape_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
}

/// Parses a PROPFIND body.
///
/// An empty body means `allprop`. Non-well-formed XML, invalid namespace
/// declarations (empty namespace URIs), or a missing `{DAV:}propfind` root
/// are rejected so the caller can return `400`.
pub fn parse_propfind(body: &[u8]) -> Result<RequestedProps, ()> {
    if body.is_empty() {
        return Ok(RequestedProps::All);
    }
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(true);

    let mut scope = Scope::new();
    let mut stack: Vec<(String, Option<String>)> = Vec::new();
    let mut only: Vec<RequestedProp> = Vec::new();
    let mut saw_children = false;
    let mut names_mode = false;
    let mut allprop_saw = false;
    let mut saw_root = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = e.name().as_ref().to_string();
                let attrs = collect_attrs(&e)?;
                scope.push_element(&attrs)?;
                let (local, ns) = scope.resolve_name(&name);
                let in_prop = stack
                    .last()
                    .is_some_and(|(l, n)| l == "prop" && n.as_deref() == Some(DAV_NS));
                if in_prop {
                    saw_children = true;
                    only.push(RequestedProp {
                        raw: name.clone(),
                        local: local.clone(),
                        namespace: ns.clone(),
                    });
                } else if local == "propname" && ns.as_deref() == Some(DAV_NS) {
                    names_mode = true;
                } else if local == "allprop" && ns.as_deref() == Some(DAV_NS) {
                    allprop_saw = true;
                }
                if stack.is_empty() {
                    if local != "propfind" || ns.as_deref() != Some(DAV_NS) || saw_root {
                        return Err(());
                    }
                    saw_root = true;
                }
                stack.push((local, ns));
            }
            Ok(Event::Empty(e)) => {
                let name = e.name().as_ref().to_string();
                let attrs = collect_attrs(&e)?;
                scope.push_element(&attrs)?;
                let (local, ns) = scope.resolve_name(&name);
                scope.pop_element();
                let in_prop = stack
                    .last()
                    .is_some_and(|(l, n)| l == "prop" && n.as_deref() == Some(DAV_NS));
                if in_prop {
                    saw_children = true;
                    only.push(RequestedProp {
                        raw: name,
                        local: local.clone(),
                        namespace: ns.clone(),
                    });
                } else if local == "propname" && ns.as_deref() == Some(DAV_NS) {
                    names_mode = true;
                } else if local == "allprop" && ns.as_deref() == Some(DAV_NS) {
                    allprop_saw = true;
                }
                if stack.is_empty() {
                    return Err(());
                }
            }
            Ok(Event::End(_)) => {
                scope.pop_element();
                if stack.pop().is_none() {
                    return Err(());
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(()),
        }
    }

    if !saw_root || !stack.is_empty() {
        return Err(());
    }
    if names_mode {
        Ok(RequestedProps::Names)
    } else if saw_children {
        Ok(RequestedProps::Only(only))
    } else {
        let _ = allprop_saw;
        Ok(RequestedProps::All)
    }
}

/// Parses a PROPPATCH body into ordered operations.
pub fn parse_proppatch(body: &[u8]) -> Result<Vec<PatchOp>, ()> {
    if body.is_empty() {
        return Err(());
    }
    let mut reader = Reader::from_reader(body);
    // Property values must keep their whitespace; only structural
    // whitespace between elements is irrelevant to us.
    reader.config_mut().trim_text(false);

    let mut scope = Scope::new();
    let mut stack: Vec<(String, Option<String>)> = Vec::new();
    let mut ops: Vec<PatchOp> = Vec::new();
    let mut saw_root = false;
    let mut current_op: Option<bool /* set? */> = None;
    let mut capture: Option<Capture> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = e.name().as_ref().to_string();
                let attrs = collect_attrs(&e)?;
                scope.push_element(&attrs)?;
                let (local, ns) = scope.resolve_name(&name);
                let parent = stack.last().cloned();
                if stack.is_empty() {
                    if local != "propertyupdate" || ns.as_deref() != Some(DAV_NS) || saw_root {
                        return Err(());
                    }
                    saw_root = true;
                } else if let Some((parent_local, parent_ns)) = &parent
                    && parent_local == "propertyupdate"
                    && parent_ns.as_deref() == Some(DAV_NS)
                {
                    if local == "set" && ns.as_deref() == Some(DAV_NS) {
                        current_op = Some(true);
                    } else if local == "remove" && ns.as_deref() == Some(DAV_NS) {
                        current_op = Some(false);
                    }
                }
                if let Some((parent_local, parent_ns)) = &parent
                    && parent_local == "prop"
                    && parent_ns.as_deref() == Some(DAV_NS)
                {
                    let namespace = ns.clone().unwrap_or_default();
                    match current_op {
                        Some(true) => {
                            capture = Some(Capture {
                                depth: stack.len(),
                                namespace,
                                name: local.clone(),
                                out: String::new(),
                                open: Vec::new(),
                            });
                        }
                        Some(false) => {
                            ops.push(PatchOp::Remove {
                                namespace,
                                name: local.clone(),
                            });
                        }
                        None => return Err(()),
                    }
                }
                if let Some(c) = capture.as_mut()
                    && stack.len() > c.depth
                {
                    c.append_start(&local, &attrs);
                }
                stack.push((local, ns));
            }
            Ok(Event::Empty(e)) => {
                let name = e.name().as_ref().to_string();
                let attrs = collect_attrs(&e)?;
                scope.push_element(&attrs)?;
                let (local, ns) = scope.resolve_name(&name);
                scope.pop_element();
                let parent = stack.last().cloned();
                if let Some((parent_local, parent_ns)) = &parent
                    && parent_local == "prop"
                    && parent_ns.as_deref() == Some(DAV_NS)
                {
                    let namespace = ns.clone().unwrap_or_default();
                    match current_op {
                        Some(true) => {
                            ops.push(PatchOp::Set {
                                namespace,
                                name: local.clone(),
                                value: String::new(),
                            });
                        }
                        Some(false) => {
                            ops.push(PatchOp::Remove {
                                namespace,
                                name: local.clone(),
                            });
                        }
                        None => return Err(()),
                    }
                } else if let Some(c) = capture.as_mut()
                    && stack.len() > c.depth
                {
                    c.append_empty(&local, &attrs);
                }
                if stack.is_empty() {
                    return Err(());
                }
            }
            Ok(Event::Text(t)) => {
                if let Some(c) = capture.as_mut() {
                    let raw = t.into_inner();
                    let unescaped = quick_xml::escape::unescape(raw.as_ref()).map_err(|_| ())?;
                    c.out.push_str(&unescaped);
                }
            }
            Ok(Event::CData(t)) => {
                if let Some(c) = capture.as_mut() {
                    c.out.push_str(&t.into_inner());
                }
            }
            Ok(Event::End(end)) => {
                scope.pop_element();
                let Some((local, ns)) = stack.pop() else {
                    return Err(());
                };
                if (local == "set" || local == "remove") && ns.as_deref() == Some(DAV_NS) {
                    current_op = None;
                }
                if let Some(c) = &capture {
                    if stack.len() == c.depth {
                        let done = capture.take().ok_or(())?;
                        ops.push(PatchOp::Set {
                            namespace: done.namespace,
                            name: done.name,
                            value: done.out,
                        });
                    } else if stack.len() < c.depth {
                        return Err(());
                    } else if let Some(c) = capture.as_mut() {
                        c.close_element();
                    }
                }
                let _ = end;
            }
            Ok(Event::GeneralRef(reference)) => {
                if let Some(c) = capture.as_mut() {
                    c.out.push_str(&resolve_reference(&reference.into_inner())?);
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(()),
        }
    }

    if !saw_root || !stack.is_empty() || capture.is_some() || current_op.is_some() {
        return Err(());
    }
    Ok(ops)
}

fn resolve_reference(name: &str) -> Result<String, ()> {
    if let Some(number) = name.strip_prefix('#') {
        let (radix, digits) = match number.strip_prefix(['x', 'X']) {
            Some(hex) => (16, hex),
            None => (10, number),
        };
        let codepoint = u32::from_str_radix(digits, radix).map_err(|_| ())?;
        return char::from_u32(codepoint).map(|c| c.to_string()).ok_or(());
    }
    match name {
        "amp" => Ok("&".to_string()),
        "lt" => Ok("<".to_string()),
        "gt" => Ok(">".to_string()),
        "quot" => Ok("\"".to_string()),
        "apos" => Ok("'".to_string()),
        _ => Err(()),
    }
}

struct Capture {
    depth: usize,
    namespace: String,
    name: String,
    out: String,
    open: Vec<String>,
}

impl Capture {
    fn append_start(&mut self, local: &str, attrs: &[(String, String)]) {
        self.out.push('<');
        self.out.push_str(local);
        for (key, value) in attrs {
            if key == "xmlns" || key.starts_with("xmlns:") {
                continue;
            }
            self.out.push(' ');
            self.out.push_str(key);
            self.out.push_str("=\"");
            self.out.push_str(&escape_attr(value));
            self.out.push('"');
        }
        self.out.push('>');
        self.open.push(local.to_string());
    }

    fn append_empty(&mut self, local: &str, attrs: &[(String, String)]) {
        self.append_start(local, attrs);
        self.out.push_str("</");
        self.out.push_str(local);
        self.out.push('>');
        self.open.pop();
    }

    fn close_element(&mut self) {
        if let Some(local) = self.open.pop() {
            self.out.push_str("</");
            self.out.push_str(&local);
            self.out.push('>');
        }
    }
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
    /// Dead properties (namespace, name, value) of this resource.
    pub dead_props: Vec<(String, String, String)>,
    /// `current-user-principal` href (for DAV discovery), if known.
    pub principal_href: Option<String>,
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
            dead_props: Vec::new(),
            principal_href: None,
        }
    }
}

/// Outcome of a single PROPPATCH operation, for the response body.
pub struct PatchResult {
    /// Namespace of the property.
    pub namespace: String,
    /// Local name of the property.
    pub name: String,
    /// HTTP status code (200 or 403).
    pub status: u16,
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

/// Renders a `207 Multi-Status` body for a PROPPATCH.
pub fn proppatch_response(href: &str, results: &[PatchResult]) -> QResult<Vec<u8>> {
    let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);
    w.write_event(Event::Decl(BytesDecl::new("1.0", Some("utf-8"), None)))?;

    let mut ms = BytesStart::new("d:multistatus");
    ms.push_attribute(("xmlns:d", "DAV:"));
    w.write_event(Event::Start(ms))?;

    w.write_event(Event::Start(BytesStart::new("d:response")))?;
    text(&mut w, "d:href", href)?;

    let mut statuses: Vec<u16> = Vec::new();
    for result in results {
        if !statuses.contains(&result.status) {
            statuses.push(result.status);
        }
    }
    for status in statuses {
        w.write_event(Event::Start(BytesStart::new("d:propstat")))?;
        w.write_event(Event::Start(BytesStart::new("d:prop")))?;
        for result in results.iter().filter(|r| r.status == status) {
            write_prop_element(&mut w, &result.namespace, &result.name, None)?;
        }
        w.write_event(Event::End(BytesEnd::new("d:prop")))?;
        text(
            &mut w,
            "d:status",
            &format!("HTTP/1.1 {status} {}", status_text(status)),
        )?;
        w.write_event(Event::End(BytesEnd::new("d:propstat")))?;
    }

    w.write_event(Event::End(BytesEnd::new("d:response")))?;
    w.write_event(Event::End(BytesEnd::new("d:multistatus")))?;
    Ok(w.into_inner())
}

/// Renders a `207 Multi-Status` body for a `sync-collection` REPORT:
/// changed resources, deleted hrefs (reported with a 404 status), and the
/// collection's new sync token.
pub fn multistatus_sync(
    entries: &[PropEntry],
    deleted_hrefs: &[String],
    requested: &RequestedProps,
    sync_token: &str,
) -> QResult<Vec<u8>> {
    let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);
    w.write_event(Event::Decl(BytesDecl::new("1.0", Some("utf-8"), None)))?;

    let mut ms = BytesStart::new("d:multistatus");
    ms.push_attribute(("xmlns:d", "DAV:"));
    w.write_event(Event::Start(ms))?;

    for entry in entries {
        write_response(&mut w, entry, requested)?;
    }
    for href in deleted_hrefs {
        w.write_event(Event::Start(BytesStart::new("d:response")))?;
        text(&mut w, "d:href", href)?;
        text(&mut w, "d:status", "HTTP/1.1 404 Not Found")?;
        w.write_event(Event::End(BytesEnd::new("d:response")))?;
    }
    text(&mut w, "d:sync-token", sync_token)?;

    w.write_event(Event::End(BytesEnd::new("d:multistatus")))?;
    Ok(w.into_inner())
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Unknown",
    }
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
                write_prop(w, name, entry)?;
            }
        }
        RequestedProps::Only(list) => {
            let mut written: Vec<&str> = Vec::new();
            for requested in list {
                let ns = requested.namespace.clone().unwrap_or_default();
                let is_dav = requested.namespace.is_none() || ns == DAV_NS;
                if is_dav && SUPPORTED.contains(&requested.local.as_str()) {
                    if !written.contains(&requested.local.as_str()) {
                        write_prop(w, &requested.local, entry)?;
                        written.push(&requested.local);
                    }
                    continue;
                }
                let dead = find_dead(entry, &ns, &requested.local).or_else(|| {
                    // Properties registered without a namespace (xmlns="")
                    // may be requested in the DAV: default namespace.
                    if is_dav {
                        find_dead(entry, "", &requested.local)
                    } else {
                        None
                    }
                });
                if let Some((dead_ns, dead_name, value)) = dead {
                    write_prop_element(w, dead_ns, dead_name, Some(value))?;
                } else if is_valid_ncname(&requested.local) {
                    unsupported.push(requested.raw.clone());
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
            let local = name.rsplit(':').next().unwrap_or(name);
            if is_valid_ncname(local) {
                w.create_element(format!("d:{local}")).write_empty()?;
            } else {
                w.create_element("d:unknown").write_empty()?;
            }
        }
        w.write_event(Event::End(BytesEnd::new("d:prop")))?;
        text(w, "d:status", "HTTP/1.1 404 Not Found")?;
        w.write_event(Event::End(BytesEnd::new("d:propstat")))?;
    }

    w.write_event(Event::End(BytesEnd::new("d:response")))?;
    Ok(())
}

fn find_dead<'a>(
    entry: &'a PropEntry,
    ns: &str,
    local: &str,
) -> Option<&'a (String, String, String)> {
    entry
        .dead_props
        .iter()
        .find(|(dead_ns, dead_name, _)| dead_ns == ns && dead_name == local)
}

fn write_prop(w: &mut Writer<Vec<u8>>, local: &str, entry: &PropEntry) -> QResult {
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
        "current-user-principal" => {
            if let Some(href) = &entry.principal_href {
                w.write_event(Event::Start(BytesStart::new("d:current-user-principal")))?;
                text(w, "d:href", href)?;
                w.write_event(Event::End(BytesEnd::new("d:current-user-principal")))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn write_prop_element(
    w: &mut Writer<Vec<u8>>,
    namespace: &str,
    name: &str,
    value: Option<&str>,
) -> QResult {
    let local = if is_valid_ncname(name) {
        name
    } else {
        "unknown"
    };
    let start_name = if namespace.is_empty() {
        local.to_string()
    } else {
        format!("x:{local}")
    };
    let mut start = BytesStart::new(start_name.as_str());
    if !namespace.is_empty() {
        start.push_attribute(("xmlns:x", namespace));
    }
    w.write_event(Event::Start(start))?;
    if let Some(value) = value {
        w.write_event(Event::Text(BytesText::new(value)))?;
    }
    w.write_event(Event::End(BytesEnd::new(start_name.as_str())))?;
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

    fn requested(local: &str) -> RequestedProp {
        RequestedProp {
            raw: local.to_string(),
            local: local.to_string(),
            namespace: Some(DAV_NS.to_string()),
        }
    }

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
    fn parses_specific_props_with_namespaces() {
        let body = br#"<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
            <d:prop><d:displayname/><d:getetag/><oc:checksums/></d:prop>
        </d:propfind>"#;
        let parsed = parse_propfind(body).unwrap();
        let RequestedProps::Only(list) = parsed else {
            panic!("expected Only");
        };
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].local, "displayname");
        assert_eq!(list[0].namespace.as_deref(), Some(DAV_NS));
        assert_eq!(list[2].raw, "oc:checksums");
        assert_eq!(list[2].namespace.as_deref(), Some("http://owncloud.org/ns"));
    }

    #[test]
    fn default_namespace_is_resolved() {
        let body = br#"<propfind xmlns="DAV:"><prop><displayname xmlns=""/></prop></propfind>"#;
        let RequestedProps::Only(list) = parse_propfind(body).unwrap() else {
            panic!("expected Only");
        };
        assert_eq!(list[0].namespace.as_deref(), Some(""));
    }

    #[test]
    fn rejects_malformed_xml() {
        assert!(parse_propfind(b"<foo>").is_err());
        assert!(parse_propfind(b"<not-closed").is_err());
        assert!(parse_propfind(b"<wrong-root xmlns='DAV:'/>").is_err());
    }

    #[test]
    fn rejects_invalid_namespace_declarations() {
        let body =
            br#"<D:propfind xmlns:D="DAV:"><D:prop><bar:foo xmlns:bar=""/></D:prop></D:propfind>"#;
        assert!(parse_propfind(body).is_err());
    }

    #[test]
    fn ignores_extended_elements() {
        let body = br#"<propfind xmlns="DAV:"><foobar/><allprop/></propfind>"#;
        assert_eq!(parse_propfind(body).unwrap(), RequestedProps::All);
    }

    #[test]
    fn parses_proppatch_in_order() {
        let body = br#"<?xml version="1.0"?><propertyupdate xmlns="DAV:">
            <remove><prop><removeset xmlns="http://example.com/ns"/></prop></remove>
            <set><prop><removeset xmlns="http://example.com/ns">x</removeset></prop></set>
            <set><prop><removeset xmlns="http://example.com/ns">y</removeset></prop></set>
        </propertyupdate>"#;
        let ops = parse_proppatch(body).unwrap();
        assert_eq!(
            ops,
            vec![
                PatchOp::Remove {
                    namespace: "http://example.com/ns".to_string(),
                    name: "removeset".to_string()
                },
                PatchOp::Set {
                    namespace: "http://example.com/ns".to_string(),
                    name: "removeset".to_string(),
                    value: "x".to_string()
                },
                PatchOp::Set {
                    namespace: "http://example.com/ns".to_string(),
                    name: "removeset".to_string(),
                    value: "y".to_string()
                },
            ]
        );
    }

    #[test]
    fn parses_proppatch_values_with_markup() {
        let body = br#"<propertyupdate xmlns="DAV:"><set><prop><t:valnspace xmlns:t="http://example.com/ns"><foo xmlns="http://bar"/></t:valnspace></prop></set></propertyupdate>"#;
        let ops = parse_proppatch(body).unwrap();
        assert_eq!(
            ops,
            vec![PatchOp::Set {
                namespace: "http://example.com/ns".to_string(),
                name: "valnspace".to_string(),
                value: "<foo></foo>".to_string()
            }]
        );
    }

    #[test]
    fn parses_proppatch_empty_value_and_removals() {
        let body = br#"<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>
            <Z:prop0 xmlns:Z="http://example.com/ns">value0</Z:prop0>
        </D:prop></D:set><D:remove><D:prop>
            <Z:prop1 xmlns:Z="http://example.com/ns"/>
        </D:prop></D:remove></D:propertyupdate>"#;
        let ops = parse_proppatch(body).unwrap();
        assert_eq!(ops.len(), 2);
        assert_eq!(
            ops[0],
            PatchOp::Set {
                namespace: "http://example.com/ns".to_string(),
                name: "prop0".to_string(),
                value: "value0".to_string()
            }
        );
        assert_eq!(
            ops[1],
            PatchOp::Remove {
                namespace: "http://example.com/ns".to_string(),
                name: "prop1".to_string()
            }
        );
    }

    #[test]
    fn parses_proppatch_numeric_references() {
        let body = br#"<propertyupdate xmlns='DAV:'><set><prop>
            <high-unicode xmlns='http://example.com/ns'>&#65536;</high-unicode>
        </prop></set></propertyupdate>"#;
        let ops = parse_proppatch(body).unwrap();
        assert_eq!(
            ops,
            vec![PatchOp::Set {
                namespace: "http://example.com/ns".to_string(),
                name: "high-unicode".to_string(),
                value: "\u{10000}".to_string()
            }]
        );

        let body = br#"<propertyupdate xmlns='DAV:'><set><prop>
            <text xmlns='http://example.com/ns'>a &amp; b</text>
        </prop></set></propertyupdate>"#;
        let ops = parse_proppatch(body).unwrap();
        assert_eq!(
            ops,
            vec![PatchOp::Set {
                namespace: "http://example.com/ns".to_string(),
                name: "text".to_string(),
                value: "a & b".to_string()
            }]
        );
    }

    #[test]
    fn rejects_malformed_proppatch() {
        assert!(parse_proppatch(b"").is_err());
        assert!(parse_proppatch(b"<propertyupdate xmlns='DAV:'>").is_err());
        assert!(parse_proppatch(b"<wrong xmlns='DAV:'/>").is_err());
    }

    fn entry(name: &str) -> PropEntry {
        PropEntry {
            href: format!("/dav/{name}"),
            display_name: name.to_string(),
            is_dir: false,
            size: 5,
            content_type: Some("text/plain".to_string()),
            modified_ms: 0,
            created_ms: 0,
            etag: "\"abc\"".to_string(),
            dead_props: Vec::new(),
            principal_href: None,
        }
    }

    #[test]
    fn renders_allprop_values() {
        let xml = multistatus(&[entry("a.txt")], &RequestedProps::All).unwrap();
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("<d:multistatus xmlns:d=\"DAV:\">"));
        assert!(text.contains("<d:href>/dav/a.txt</d:href>"));
        assert!(text.contains("<d:displayname>a.txt</d:displayname>"));
        assert!(text.contains("<d:getcontentlength>5</d:getcontentlength>"));
        assert!(text.contains("<d:getcontenttype>text/plain</d:getcontenttype>"));
        assert!(text.contains("<d:status>HTTP/1.1 200 OK</d:status>"));
    }

    #[test]
    fn renders_collection_resourcetype() {
        let mut coll = entry("docs");
        coll.is_dir = true;
        coll.content_type = None;
        let xml = multistatus(&[coll], &RequestedProps::All).unwrap();
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("<d:resourcetype>"));
        assert!(text.contains("<d:collection/>"));
        assert!(!text.contains("getcontentlength"));
    }

    #[test]
    fn unsupported_props_get_404_propstat() {
        let requested = RequestedProps::Only(vec![
            requested("displayname"),
            RequestedProp {
                raw: "oc:checksums".to_string(),
                local: "checksums".to_string(),
                namespace: Some("http://owncloud.org/ns".to_string()),
            },
        ]);
        let xml = multistatus(&[entry("a.txt")], &requested).unwrap();
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("<d:displayname>a.txt</d:displayname>"));
        assert!(text.contains("<d:checksums/>"));
        assert!(text.contains("<d:status>HTTP/1.1 404 Not Found</d:status>"));
    }

    #[test]
    fn dead_props_are_rendered_with_their_namespace() {
        let mut e = entry("a.txt");
        e.dead_props.push((
            "http://example.com/ns".to_string(),
            "color".to_string(),
            "blue & green".to_string(),
        ));
        let requested = RequestedProps::Only(vec![RequestedProp {
            raw: "Z:color".to_string(),
            local: "color".to_string(),
            namespace: Some("http://example.com/ns".to_string()),
        }]);
        let xml = multistatus(&[e], &requested).unwrap();
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("xmlns:x=\"http://example.com/ns\""));
        assert!(text.contains("blue &amp; green"));
    }

    #[test]
    fn no_namespace_dead_props_are_rendered_bare() {
        let mut e = entry("a.txt");
        e.dead_props.push((
            String::new(),
            "nonamespace".to_string(),
            "randomvalue".to_string(),
        ));
        let requested = RequestedProps::Only(vec![RequestedProp {
            raw: "nonamespace".to_string(),
            local: "nonamespace".to_string(),
            namespace: Some(String::new()),
        }]);
        let xml = multistatus(&[e], &requested).unwrap();
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("<nonamespace>randomvalue</nonamespace>"));
    }

    #[test]
    fn propname_returns_empty_names() {
        let xml = multistatus(&[entry("a.txt")], &RequestedProps::Names).unwrap();
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("<d:displayname/>"));
        assert!(!text.contains(">a.txt<"));
    }

    #[test]
    fn proppatch_response_groups_statuses() {
        let results = vec![
            PatchResult {
                namespace: "http://example.com/ns".to_string(),
                name: "a".to_string(),
                status: 200,
            },
            PatchResult {
                namespace: DAV_NS.to_string(),
                name: "getetag".to_string(),
                status: 403,
            },
        ];
        let xml = proppatch_response("/dav/a.txt", &results).unwrap();
        let text = String::from_utf8(xml).unwrap();
        assert!(text.contains("HTTP/1.1 200 OK"));
        assert!(text.contains("HTTP/1.1 403 Forbidden"));
    }
}
