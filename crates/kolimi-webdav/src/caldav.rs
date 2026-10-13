//! CalDAV (RFC 4791) and CardDAV (RFC 6352) over `kolimi-db` collections,
//! including RFC 6578 `sync-collection`.
//!
//! These resources live at `/dav/principals/{user}/`,
//! `/dav/calendars/{user}/...`, and `/dav/addressbooks/{user}/...`. The
//! file tree never sees them (the root names are reserved).
//!
//! Documented M4 deviations: `calendar-query`/`addressbook-query` filters
//! are advisory (the whole collection is returned; clients filter locally),
//! and `sync-level: infinite` is rejected.
#![allow(clippy::result_large_err)]

use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use kolimi_auth::CurrentUser;
use kolimi_db::{DavCollection, DavObject, DavObjectMeta};
use kolimi_vfs::Vfs;
use quick_xml::{
    Writer,
    events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event},
};

use crate::cond;
use crate::davpath;
use crate::ical::validate_calendar;
use crate::report::{APPLE_NS, CALDAV_NS, CARDDAV_NS, CS_NS, Report, ReportProps, parse_report};
use crate::vcard::validate_vcard;
use crate::xml::{PatchResult, RequestedProp, RequestedProps, parse_propfind, parse_proppatch};

const DAV_NS: &str = "DAV:";
const MAX_OBJECT_BYTES: usize = 10 * 1024 * 1024;
const MAX_REPORT_BODY: usize = 1024 * 1024;
const MAX_CHANGES: i64 = 10_000;

/// The DAV header value advertised for calendar/address-book resources.
pub const DAV_HEADER: &str = "1, calendar-access, addressbook, extended-mkcol, sync-collection";

/// Handles `/dav/principals|calendars|addressbooks/...` requests.
pub(crate) async fn handle(
    vfs: &std::sync::Arc<Vfs>,
    user: &CurrentUser,
    segments: &[String],
    method: &Method,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    match segments.first().map(String::as_str) {
        Some("principals") => principals(user, segments, method, headers, body).await,
        Some("calendars") => {
            collections(vfs, user, segments, method, headers, body, Kind::Calendar).await
        }
        Some("addressbooks") => {
            collections(
                vfs,
                user,
                segments,
                method,
                headers,
                body,
                Kind::Addressbook,
            )
            .await
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Calendar,
    Addressbook,
}

impl Kind {
    fn db_kind(self) -> &'static str {
        match self {
            Self::Calendar => "calendar",
            Self::Addressbook => "addressbook",
        }
    }

    fn plural(self) -> &'static str {
        match self {
            Self::Calendar => "calendars",
            Self::Addressbook => "addressbooks",
        }
    }

    fn data_ns(self) -> &'static str {
        match self {
            Self::Calendar => CALDAV_NS,
            Self::Addressbook => CARDDAV_NS,
        }
    }

    fn data_prop(self) -> &'static str {
        match self {
            Self::Calendar => "calendar-data",
            Self::Addressbook => "address-data",
        }
    }

    fn content_type(self) -> &'static str {
        match self {
            Self::Calendar => "text/calendar; charset=utf-8",
            Self::Addressbook => "text/vcard; charset=utf-8",
        }
    }
}

// ---- resources and rendering ------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResType {
    Principal,
    Calendar,
    Addressbook,
    Collection,
    Object,
}

struct Resource {
    href: String,
    resourcetype: ResType,
    display_name: Option<String>,
    content_type: Option<String>,
    size: Option<u64>,
    etag: Option<String>,
    modified_ms: Option<i64>,
    created_ms: Option<i64>,
    data: Option<Vec<u8>>,
    ctag: Option<i64>,
    collection_id: Option<i64>,
    color: Option<String>,
    description: Option<String>,
    principal_href: Option<String>,
    calendar_home: Option<String>,
    addressbook_home: Option<String>,
}

impl Resource {
    fn empty(href: String, resourcetype: ResType) -> Self {
        Self {
            href,
            resourcetype,
            display_name: None,
            content_type: None,
            size: None,
            etag: None,
            modified_ms: None,
            created_ms: None,
            data: None,
            ctag: None,
            collection_id: None,
            color: None,
            description: None,
            principal_href: None,
            calendar_home: None,
            addressbook_home: None,
        }
    }
}

enum Wanted {
    All,
    Names,
    Only(Vec<RequestedProp>),
}

impl From<RequestedProps> for Wanted {
    fn from(props: RequestedProps) -> Self {
        match props {
            RequestedProps::All => Self::All,
            RequestedProps::Names => Self::Names,
            RequestedProps::Only(list) => Self::Only(list),
        }
    }
}

impl From<ReportProps> for Wanted {
    fn from(props: ReportProps) -> Self {
        match props {
            ReportProps::Default | ReportProps::All => Self::All,
            ReportProps::Only(list) => Self::Only(list),
        }
    }
}

impl Wanted {
    fn wants_data(&self, kind: Kind) -> bool {
        match self {
            Self::Only(list) => list.iter().any(|prop| {
                prop.local == kind.data_prop() && prop.namespace.as_deref() == Some(kind.data_ns())
            }),
            _ => false,
        }
    }
}

type QResult<T = ()> = Result<T, quick_xml::Error>;

/// The properties rendered for `allprop`-style requests.
const ALL_PROPS: &[(&str, &str)] = &[
    (DAV_NS, "resourcetype"),
    (DAV_NS, "displayname"),
    (DAV_NS, "getetag"),
    (DAV_NS, "getcontenttype"),
    (DAV_NS, "getcontentlength"),
    (DAV_NS, "getlastmodified"),
    (DAV_NS, "creationdate"),
    (DAV_NS, "sync-token"),
    (CS_NS, "getctag"),
];

fn render(
    resources: &[Resource],
    deleted: &[String],
    wanted: &Wanted,
    sync_token: Option<&str>,
) -> QResult<Vec<u8>> {
    let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);
    w.write_event(Event::Decl(BytesDecl::new("1.0", Some("utf-8"), None)))?;

    let mut ms = BytesStart::new("d:multistatus");
    ms.push_attribute(("xmlns:d", DAV_NS));
    ms.push_attribute(("xmlns:c", CALDAV_NS));
    ms.push_attribute(("xmlns:card", CARDDAV_NS));
    ms.push_attribute(("xmlns:cs", CS_NS));
    ms.push_attribute(("xmlns:apple", APPLE_NS));
    w.write_event(Event::Start(ms))?;

    for resource in resources {
        write_response(&mut w, resource, wanted)?;
    }
    for href in deleted {
        w.write_event(Event::Start(BytesStart::new("d:response")))?;
        text(&mut w, "d:href", href)?;
        text(&mut w, "d:status", "HTTP/1.1 404 Not Found")?;
        w.write_event(Event::End(BytesEnd::new("d:response")))?;
    }
    if let Some(token) = sync_token {
        text(&mut w, "d:sync-token", token)?;
    }

    w.write_event(Event::End(BytesEnd::new("d:multistatus")))?;
    Ok(w.into_inner())
}

fn write_response(w: &mut Writer<Vec<u8>>, resource: &Resource, wanted: &Wanted) -> QResult {
    w.write_event(Event::Start(BytesStart::new("d:response")))?;
    text(w, "d:href", &resource.href)?;
    w.write_event(Event::Start(BytesStart::new("d:propstat")))?;
    w.write_event(Event::Start(BytesStart::new("d:prop")))?;

    let mut unsupported: Vec<(String, String)> = Vec::new();
    match wanted {
        Wanted::Names => {
            for (ns, local) in ALL_PROPS {
                write_prop(w, resource, ns, local, true)?;
            }
        }
        Wanted::All => {
            for (ns, local) in ALL_PROPS {
                write_prop(w, resource, ns, local, false)?;
            }
        }
        Wanted::Only(list) => {
            for prop in list {
                let ns = prop.namespace.clone().unwrap_or_default();
                let ns = if ns.is_empty() { DAV_NS } else { &ns };
                if !write_prop(w, resource, ns, &prop.local, false)? {
                    unsupported.push((ns.to_string(), prop.local.clone()));
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
        for (ns, local) in &unsupported {
            write_empty_element(w, ns, local)?;
        }
        w.write_event(Event::End(BytesEnd::new("d:prop")))?;
        text(w, "d:status", "HTTP/1.1 404 Not Found")?;
        w.write_event(Event::End(BytesEnd::new("d:propstat")))?;
    }

    w.write_event(Event::End(BytesEnd::new("d:response")))?;
    Ok(())
}

/// Writes one property. Returns `false` when the property does not apply to
/// this resource (rendered as a 404 propstat by the caller).
fn write_prop(
    w: &mut Writer<Vec<u8>>,
    resource: &Resource,
    ns: &str,
    local: &str,
    name_only: bool,
) -> QResult<bool> {
    let applies = match (ns, local) {
        (DAV_NS, "displayname") => resource.display_name.is_some(),
        (DAV_NS, "resourcetype") => true,
        (DAV_NS, "getcontentlength") => resource.size.is_some(),
        (DAV_NS, "getcontenttype") => resource.content_type.is_some(),
        (DAV_NS, "getlastmodified") => resource.modified_ms.is_some(),
        (DAV_NS, "getetag") => resource.etag.is_some(),
        (DAV_NS, "creationdate") => resource.created_ms.is_some(),
        (DAV_NS, "current-user-principal") | (DAV_NS, "principal-URL") | (DAV_NS, "owner") => {
            resource.principal_href.is_some()
        }
        (DAV_NS, "current-user-privilege-set") => matches!(
            resource.resourcetype,
            ResType::Principal | ResType::Calendar | ResType::Addressbook | ResType::Collection
        ),
        (DAV_NS, "supported-report-set") => matches!(
            resource.resourcetype,
            ResType::Calendar | ResType::Addressbook | ResType::Collection
        ),
        (DAV_NS, "sync-token") => resource.ctag.is_some(),
        (CALDAV_NS, "calendar-data") | (CARDDAV_NS, "address-data") => resource.data.is_some(),
        (CALDAV_NS, "calendar-home-set") => resource.calendar_home.is_some(),
        (CARDDAV_NS, "addressbook-home-set") => resource.addressbook_home.is_some(),
        (CALDAV_NS, "calendar-description") | (CARDDAV_NS, "addressbook-description") => {
            resource.description.is_some()
        }
        (CALDAV_NS, "supported-calendar-component-set") => {
            resource.resourcetype == ResType::Calendar
        }
        (CARDDAV_NS, "supported-address-data") => resource.resourcetype == ResType::Addressbook,
        (CS_NS, "getctag") => resource.ctag.is_some(),
        (APPLE_NS, "calendar-color") => resource.color.is_some(),
        _ => false,
    };
    if !applies {
        return Ok(false);
    }
    if name_only {
        write_empty_element(w, ns, local)?;
        return Ok(true);
    }
    match (ns, local) {
        (DAV_NS, "resourcetype") => {
            w.write_event(Event::Start(BytesStart::new("d:resourcetype")))?;
            match resource.resourcetype {
                ResType::Principal => {
                    w.create_element("d:principal").write_empty()?;
                }
                ResType::Calendar => {
                    w.create_element("d:collection").write_empty()?;
                    w.create_element("c:calendar").write_empty()?;
                }
                ResType::Addressbook => {
                    w.create_element("d:collection").write_empty()?;
                    w.create_element("card:addressbook").write_empty()?;
                }
                ResType::Collection => {
                    w.create_element("d:collection").write_empty()?;
                }
                ResType::Object => {}
            }
            w.write_event(Event::End(BytesEnd::new("d:resourcetype")))?;
        }
        (DAV_NS, "current-user-principal") | (DAV_NS, "principal-URL") | (DAV_NS, "owner") => {
            let name = match local {
                "current-user-principal" => "d:current-user-principal",
                "principal-URL" => "d:principal-URL",
                _ => "d:owner",
            };
            href_element(w, name, resource.principal_href.as_deref().unwrap_or("/"))?;
        }
        (DAV_NS, "current-user-privilege-set") => {
            w.write_event(Event::Start(BytesStart::new(
                "d:current-user-privilege-set",
            )))?;
            for privilege in ["d:read", "d:write"] {
                w.write_event(Event::Start(BytesStart::new("d:privilege")))?;
                w.create_element(privilege).write_empty()?;
                w.write_event(Event::End(BytesEnd::new("d:privilege")))?;
            }
            w.write_event(Event::End(BytesEnd::new("d:current-user-privilege-set")))?;
        }
        (DAV_NS, "supported-report-set") => {
            w.write_event(Event::Start(BytesStart::new("d:supported-report-set")))?;
            let reports: &[&str] = match resource.resourcetype {
                ResType::Calendar => &[
                    "d:sync-collection",
                    "c:calendar-query",
                    "c:calendar-multiget",
                ],
                ResType::Addressbook => &[
                    "d:sync-collection",
                    "card:addressbook-query",
                    "card:addressbook-multiget",
                ],
                _ => &["d:sync-collection"],
            };
            for report in reports {
                w.write_event(Event::Start(BytesStart::new("d:supported-report")))?;
                w.write_event(Event::Start(BytesStart::new("d:report")))?;
                w.create_element(*report).write_empty()?;
                w.write_event(Event::End(BytesEnd::new("d:report")))?;
                w.write_event(Event::End(BytesEnd::new("d:supported-report")))?;
            }
            w.write_event(Event::End(BytesEnd::new("d:supported-report-set")))?;
        }
        (DAV_NS, "sync-token") => {
            let token = match resource.collection_id {
                Some(id) => format!("urn:kolimi:sync:{id}:{}", resource.ctag.unwrap_or(0)),
                None => String::new(),
            };
            text(w, "d:sync-token", &token)?;
        }
        (CALDAV_NS, "calendar-data") | (CARDDAV_NS, "address-data") => {
            let data = resource.data.as_deref().unwrap_or_default();
            let value = String::from_utf8_lossy(data);
            let name = if local == "calendar-data" {
                "c:calendar-data"
            } else {
                "card:address-data"
            };
            text(w, name, &value)?;
        }
        (CALDAV_NS, "calendar-home-set") => {
            href_element(
                w,
                "c:calendar-home-set",
                resource.calendar_home.as_deref().unwrap_or("/"),
            )?;
        }
        (CARDDAV_NS, "addressbook-home-set") => {
            href_element(
                w,
                "card:addressbook-home-set",
                resource.addressbook_home.as_deref().unwrap_or("/"),
            )?;
        }
        (CALDAV_NS, "supported-calendar-component-set") => {
            w.write_event(Event::Start(BytesStart::new(
                "c:supported-calendar-component-set",
            )))?;
            for component in ["VEVENT", "VTODO", "VJOURNAL"] {
                let mut comp = BytesStart::new("c:comp");
                comp.push_attribute(("name", component));
                w.write_event(Event::Empty(comp))?;
            }
            w.write_event(Event::End(BytesEnd::new(
                "c:supported-calendar-component-set",
            )))?;
        }
        (CARDDAV_NS, "supported-address-data") => {
            w.write_event(Event::Start(BytesStart::new("card:supported-address-data")))?;
            for version in ["3.0", "4.0"] {
                let mut data = BytesStart::new("card:address-data-type");
                data.push_attribute(("content-type", "text/vcard"));
                data.push_attribute(("version", version));
                w.write_event(Event::Empty(data))?;
            }
            w.write_event(Event::End(BytesEnd::new("card:supported-address-data")))?;
        }
        (DAV_NS, "displayname") => text(
            w,
            "d:displayname",
            resource.display_name.as_deref().unwrap_or_default(),
        )?,
        (DAV_NS, "getcontentlength") => text(
            w,
            "d:getcontentlength",
            &resource.size.unwrap_or(0).to_string(),
        )?,
        (DAV_NS, "getcontenttype") => text(
            w,
            "d:getcontenttype",
            resource.content_type.as_deref().unwrap_or_default(),
        )?,
        (DAV_NS, "getlastmodified") => text(
            w,
            "d:getlastmodified",
            &cond::http_date(resource.modified_ms.unwrap_or(0)),
        )?,
        (DAV_NS, "getetag") => text(
            w,
            "d:getetag",
            &quote_etag(resource.etag.as_deref().unwrap_or_default()),
        )?,
        (DAV_NS, "creationdate") => text(
            w,
            "d:creationdate",
            &cond::rfc3339(resource.created_ms.unwrap_or(0)),
        )?,
        (CALDAV_NS, "calendar-description") | (CARDDAV_NS, "addressbook-description") => text(
            w,
            if local == "calendar-description" {
                "c:calendar-description"
            } else {
                "card:addressbook-description"
            },
            resource.description.as_deref().unwrap_or_default(),
        )?,
        (CS_NS, "getctag") => text(w, "cs:getctag", &resource.ctag.unwrap_or(0).to_string())?,
        (APPLE_NS, "calendar-color") => text(
            w,
            "apple:calendar-color",
            resource.color.as_deref().unwrap_or_default(),
        )?,
        _ => return Ok(false),
    }
    Ok(true)
}

fn quote_etag(etag: &str) -> String {
    if etag.is_empty() {
        String::new()
    } else if etag.starts_with('"') {
        etag.to_string()
    } else {
        format!("\"{etag}\"")
    }
}

fn href_element(w: &mut Writer<Vec<u8>>, name: &str, href: &str) -> QResult {
    w.write_event(Event::Start(BytesStart::new(name)))?;
    text(w, "d:href", href)?;
    w.write_event(Event::End(BytesEnd::new(name)))?;
    Ok(())
}

fn write_empty_element(w: &mut Writer<Vec<u8>>, ns: &str, local: &str) -> QResult {
    let prefix = match ns {
        DAV_NS => "d",
        CALDAV_NS => "c",
        CARDDAV_NS => "card",
        CS_NS => "cs",
        APPLE_NS => "apple",
        _ => "d",
    };
    // The local name comes from client input; never emit a raw element name.
    let local = if crate::xml::is_valid_ncname(local) {
        local
    } else {
        "unknown"
    };
    w.create_element(format!("{prefix}:{local}"))
        .write_empty()?;
    Ok(())
}

fn text(w: &mut Writer<Vec<u8>>, name: &str, value: &str) -> QResult {
    w.create_element(name)
        .write_text_content(BytesText::new(value))?;
    Ok(())
}

// ---- request handling --------------------------------------------------

async fn principals(
    user: &CurrentUser,
    segments: &[String],
    method: &Method,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    if segments.len() != 2 || segments[1] != user.username {
        return StatusCode::NOT_FOUND.into_response();
    }
    match method.as_str() {
        "OPTIONS" => options(),
        "PROPFIND" => {
            let (depth, wanted) = match propfind_inputs(headers, body).await {
                Ok(inputs) => inputs,
                Err(response) => return response,
            };
            if depth > 1 {
                return StatusCode::FORBIDDEN.into_response();
            }
            let mut resource = Resource::empty(
                format!("/dav/principals/{}/", user.username),
                ResType::Principal,
            );
            resource.display_name = Some(user.username.clone());
            resource.principal_href = Some(principal_href(user));
            resource.calendar_home = Some(format!("/dav/calendars/{}/", user.username));
            resource.addressbook_home = Some(format!("/dav/addressbooks/{}/", user.username));
            let resources = vec![resource];
            render_response(&resources, &[], &wanted, None)
        }
        _ => method_not_allowed(),
    }
}

async fn collections(
    vfs: &Vfs,
    user: &CurrentUser,
    segments: &[String],
    method: &Method,
    headers: &HeaderMap,
    body: Body,
    kind: Kind,
) -> Response {
    if segments.len() < 2 || segments[1] != user.username {
        return StatusCode::NOT_FOUND.into_response();
    }
    match segments.len() {
        2 => home(vfs, user, segments, method, headers, body, kind).await,
        3 => collection(vfs, user, segments, method, headers, body, kind).await,
        4 => object(vfs, user, segments, method, headers, body, kind).await,
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn home(
    vfs: &Vfs,
    user: &CurrentUser,
    segments: &[String],
    method: &Method,
    headers: &HeaderMap,
    body: Body,
    kind: Kind,
) -> Response {
    match method.as_str() {
        "OPTIONS" => options(),
        "PROPFIND" => {
            let (depth, wanted) = match propfind_inputs(headers, body).await {
                Ok(inputs) => inputs,
                Err(response) => return response,
            };
            if depth > 1 {
                return StatusCode::FORBIDDEN.into_response();
            }
            let mut resources = vec![home_resource(user, segments, kind)];
            if depth == 1 {
                let collections = match vfs
                    .db()
                    .list_dav_collections(user.user_id, kind.db_kind())
                    .await
                {
                    Ok(collections) => collections,
                    Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                };
                for collection in &collections {
                    let ctag = match vfs.db().dav_latest_seq(collection.id).await {
                        Ok(seq) => seq,
                        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    };
                    resources.push(collection_resource(user, kind, collection, ctag, None));
                }
            }
            render_response(&resources, &[], &wanted, None)
        }
        "MKCALENDAR" | "MKCOL" => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        _ => method_not_allowed(),
    }
}

async fn collection(
    vfs: &Vfs,
    user: &CurrentUser,
    segments: &[String],
    method: &Method,
    headers: &HeaderMap,
    body: Body,
    kind: Kind,
) -> Response {
    // Creation does not require the collection to exist yet.
    match method.as_str() {
        "MKCALENDAR" if kind == Kind::Calendar => {
            return create_collection(vfs, user, segments, kind, body, true).await;
        }
        "MKCOL" => return create_collection(vfs, user, segments, kind, body, false).await,
        _ => {}
    }

    let name = &segments[2];
    let db = vfs.db();
    let collection = match db.dav_collection(user.user_id, kind.db_kind(), name).await {
        Ok(Some(collection)) => collection,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let ctag = match db.dav_latest_seq(collection.id).await {
        Ok(seq) => seq,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    match method.as_str() {
        "OPTIONS" => options(),
        "PROPFIND" => {
            let (depth, wanted) = match propfind_inputs(headers, body).await {
                Ok(inputs) => inputs,
                Err(response) => return response,
            };
            if depth > 1 {
                return StatusCode::FORBIDDEN.into_response();
            }
            let mut resources = vec![collection_resource(user, kind, &collection, ctag, None)];
            if depth == 1 {
                let objects = match db.list_dav_objects(collection.id).await {
                    Ok(objects) => objects,
                    Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                };
                for object in &objects {
                    let data = if wanted.wants_data(kind) {
                        db.dav_object(collection.id, &object.name)
                            .await
                            .ok()
                            .flatten()
                            .map(|object| object.data)
                    } else {
                        None
                    };
                    resources.push(object_resource(segments, kind, object, data));
                }
            }
            render_response(&resources, &[], &wanted, None)
        }
        "REPORT" => report(vfs, segments, &collection, kind, body).await,
        "PROPPATCH" => proppatch(vfs, user, segments, &collection, body).await,
        "DELETE" => match db.delete_dav_collection(user.user_id, collection.id).await {
            Ok(true) => StatusCode::NO_CONTENT.into_response(),
            Ok(false) => StatusCode::NOT_FOUND.into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        _ => method_not_allowed(),
    }
}

async fn create_collection(
    vfs: &Vfs,
    user: &CurrentUser,
    segments: &[String],
    kind: Kind,
    body: Body,
    mkcalendar: bool,
) -> Response {
    let body = match to_bytes(body, MAX_REPORT_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let parsed = match parse_create_body(&body, mkcalendar) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    // Extended MKCOL must declare the matching resourcetype; MKCALENDAR
    // implies a calendar.
    let declared = parsed.0;
    let required = match kind {
        Kind::Calendar => ResType::Calendar,
        Kind::Addressbook => ResType::Addressbook,
    };
    if !mkcalendar && declared != Some(required) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let name = &segments[2];
    let displayname = parsed
        .1
        .iter()
        .find(|(ns, local, _)| ns == DAV_NS && local == "displayname")
        .map(|(_, _, value)| value.as_str());
    let db = vfs.db();
    let created = match db
        .create_dav_collection(user.user_id, kind.db_kind(), name, displayname)
        .await
    {
        Ok(collection) => collection,
        Err(kolimi_db::DbError::Conflict(_)) => {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    for (ns, local, value) in &parsed.1 {
        if let Some(field) = prop_field(kind, ns, local) {
            let _ = db
                .set_dav_collection_prop(user.user_id, created.id, field, Some(value))
                .await;
        }
    }
    StatusCode::CREATED.into_response()
}

async fn proppatch(
    vfs: &Vfs,
    user: &CurrentUser,
    segments: &[String],
    collection: &DavCollection,
    body: Body,
) -> Response {
    let body = match to_bytes(body, MAX_REPORT_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let ops = match parse_proppatch(&body) {
        Ok(ops) if !ops.is_empty() => ops,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    let kind = if collection.kind == "calendar" {
        Kind::Calendar
    } else {
        Kind::Addressbook
    };
    let db = vfs.db();
    let mut results = Vec::new();
    for op in &ops {
        let ns = op.namespace().to_string();
        let local = op.name().to_string();
        let Some(field) = prop_field(kind, &ns, &local) else {
            results.push(PatchResult {
                namespace: ns,
                name: local,
                status: 403,
            });
            continue;
        };
        let value = match op {
            crate::xml::PatchOp::Set { value, .. } => Some(value.as_str()),
            crate::xml::PatchOp::Remove { .. } => None,
        };
        if db
            .set_dav_collection_prop(user.user_id, collection.id, field, value)
            .await
            .unwrap_or(false)
        {
            results.push(PatchResult {
                namespace: ns,
                name: local,
                status: 200,
            });
        } else {
            results.push(PatchResult {
                namespace: ns,
                name: local,
                status: 403,
            });
        }
    }
    match crate::xml::proppatch_response(&davpath::encode_href(segments), &results) {
        Ok(xml) => xml_response(xml),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn object(
    vfs: &Vfs,
    user: &CurrentUser,
    segments: &[String],
    method: &Method,
    headers: &HeaderMap,
    body: Body,
    kind: Kind,
) -> Response {
    let name = &segments[3];
    let db = vfs.db();
    let Some(collection) = db
        .dav_collection(user.user_id, kind.db_kind(), &segments[2])
        .await
        .ok()
        .flatten()
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let existing = db.dav_object(collection.id, name).await.ok().flatten();

    match method.as_str() {
        "OPTIONS" => options(),
        "GET" | "HEAD" => {
            let Some(object) = existing else {
                return StatusCode::NOT_FOUND.into_response();
            };
            let etag = quote_etag(&object.etag);
            if let Some(value) = header_str(headers, header::IF_NONE_MATCH)
                && cond::matches_etag(value, &etag, true)
            {
                return StatusCode::NOT_MODIFIED.into_response();
            }
            let mut response = Response::new(if method == Method::HEAD {
                Body::empty()
            } else {
                Body::from(object.data)
            });
            let headers_out = response.headers_mut();
            headers_out.insert(
                header::CONTENT_TYPE,
                content_type_value(&object.content_type),
            );
            if let Ok(value) = HeaderValue::from_str(&etag) {
                headers_out.insert(header::ETAG, value);
            }
            if let Ok(value) = HeaderValue::from_str(&cond::http_date(object.modified_at)) {
                headers_out.insert(header::LAST_MODIFIED, value);
            }
            response
        }
        "PUT" => put_object(vfs, user, &collection, name, existing, headers, body, kind).await,
        "DELETE" => match db.delete_dav_object(collection.id, name).await {
            Ok(true) => StatusCode::NO_CONTENT.into_response(),
            Ok(false) => StatusCode::NOT_FOUND.into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        "PROPFIND" => {
            let Some(object) = existing else {
                return StatusCode::NOT_FOUND.into_response();
            };
            let (_, wanted) = match propfind_inputs(headers, body).await {
                Ok(inputs) => inputs,
                Err(response) => return response,
            };
            let meta = DavObjectMeta {
                name: object.name.clone(),
                uid: object.uid.clone(),
                content_type: object.content_type.clone(),
                etag: object.etag.clone(),
                size: object.size,
                created_at: object.created_at,
                modified_at: object.modified_at,
            };
            let data = wanted.wants_data(kind).then_some(object.data);
            let resources = vec![object_resource(segments, kind, &meta, data)];
            render_response(&resources, &[], &wanted, None)
        }
        _ => method_not_allowed(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn put_object(
    vfs: &Vfs,
    _user: &CurrentUser,
    collection: &DavCollection,
    name: &str,
    existing: Option<DavObject>,
    headers: &HeaderMap,
    body: Body,
    kind: Kind,
) -> Response {
    let data = match to_bytes(body, MAX_OBJECT_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let Ok(text) = std::str::from_utf8(&data) else {
        return bad_request("object data must be UTF-8");
    };
    let uid = match kind {
        Kind::Calendar => match validate_calendar(text) {
            Ok(uid) => uid,
            Err(error) => return bad_request(&error.to_string()),
        },
        Kind::Addressbook => match validate_vcard(text) {
            Ok(uid) => uid,
            Err(error) => return bad_request(&error.to_string()),
        },
    };

    if let Some(value) = header_str(headers, header::IF_NONE_MATCH)
        && value.trim() == "*"
        && existing.is_some()
    {
        return StatusCode::PRECONDITION_FAILED.into_response();
    }
    if let Some(value) = header_str(headers, header::IF_MATCH) {
        match &existing {
            None => return StatusCode::PRECONDITION_FAILED.into_response(),
            Some(object) => {
                if !cond::matches_etag(value, &quote_etag(&object.etag), false) {
                    return StatusCode::PRECONDITION_FAILED.into_response();
                }
            }
        }
    }

    let etag = blake3::hash(&data).to_hex().to_string();
    let now = kolimi_db::now_millis();
    match vfs
        .db()
        .put_dav_object(
            collection.id,
            name,
            &uid,
            kind.content_type(),
            &data,
            &etag,
            data.len() as i64,
            now,
        )
        .await
    {
        Ok(object) => {
            let status = if existing.is_some() {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::CREATED
            };
            let mut response = status.into_response();
            if let Ok(value) = HeaderValue::from_str(&quote_etag(&object.etag)) {
                response.headers_mut().insert(header::ETAG, value);
            }
            response
        }
        Err(kolimi_db::DbError::Conflict(_)) => (
            StatusCode::CONFLICT,
            "another resource in this collection already uses that UID",
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn report(
    vfs: &Vfs,
    segments: &[String],
    collection: &DavCollection,
    kind: Kind,
    body: Body,
) -> Response {
    let body = match to_bytes(body, MAX_REPORT_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let report = match parse_report(&body) {
        Ok(report) => report,
        Err(()) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let db = vfs.db();

    match report {
        Report::SyncCollection {
            sync_token,
            level,
            props,
        } => {
            if level != 1 {
                return StatusCode::FORBIDDEN.into_response();
            }
            let wanted: Wanted = props.into();
            let since = match sync_token {
                None => 0,
                Some(token) => match parse_sync_token(&token) {
                    Some((id, seq)) if id == collection.id => seq,
                    _ => return invalid_sync_token(),
                },
            };
            let changes = match db
                .dav_changes_since(collection.id, since, MAX_CHANGES)
                .await
            {
                Ok(changes) => changes,
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
            let latest_seq = match db.dav_latest_seq(collection.id).await {
                Ok(seq) => seq.max(since),
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
            let mut resources = Vec::new();
            let mut deleted = Vec::new();
            // Keep only the latest change per object, so a delete followed by
            // a re-create in the same window reports the object as present.
            let mut latest: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            for (index, change) in changes.iter().enumerate() {
                latest.insert(change.object_name.clone(), index);
            }
            for (index, change) in changes.into_iter().enumerate() {
                if latest.get(&change.object_name) != Some(&index) {
                    continue;
                }
                let href = object_href(segments, &change.object_name);
                if change.op == "delete" {
                    deleted.push(href);
                    continue;
                }
                match db.dav_object(collection.id, &change.object_name).await {
                    Ok(Some(object)) => {
                        let data = wanted.wants_data(kind).then_some(object.data);
                        let meta = DavObjectMeta {
                            name: object.name,
                            uid: object.uid,
                            content_type: object.content_type,
                            etag: object.etag,
                            size: object.size,
                            created_at: object.created_at,
                            modified_at: object.modified_at,
                        };
                        resources.push(object_resource(segments, kind, &meta, data));
                    }
                    _ => deleted.push(href),
                }
            }
            let token = format!("urn:kolimi:sync:{}:{}", collection.id, latest_seq);
            render_response(&resources, &deleted, &wanted, Some(&token))
        }
        Report::CalendarQuery { props } if kind == Kind::Calendar => {
            query_all(vfs, segments, collection, kind, props.into()).await
        }
        Report::AddressbookQuery { props } if kind == Kind::Addressbook => {
            query_all(vfs, segments, collection, kind, props.into()).await
        }
        Report::CalendarMultiget { hrefs, props } if kind == Kind::Calendar => {
            multiget(vfs, segments, collection, kind, hrefs, props.into()).await
        }
        Report::AddressbookMultiget { hrefs, props } if kind == Kind::Addressbook => {
            multiget(vfs, segments, collection, kind, hrefs, props.into()).await
        }
        _ => StatusCode::FORBIDDEN.into_response(),
    }
}

async fn query_all(
    vfs: &Vfs,
    segments: &[String],
    collection: &DavCollection,
    kind: Kind,
    wanted: Wanted,
) -> Response {
    let db = vfs.db();
    let objects = match db.list_dav_objects(collection.id).await {
        Ok(objects) => objects,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let mut resources = Vec::with_capacity(objects.len());
    for object in &objects {
        let data = if wanted.wants_data(kind) {
            db.dav_object(collection.id, &object.name)
                .await
                .ok()
                .flatten()
                .map(|object| object.data)
        } else {
            None
        };
        resources.push(object_resource(segments, kind, object, data));
    }
    render_response(&resources, &[], &wanted, None)
}

#[allow(clippy::too_many_arguments)]
async fn multiget(
    vfs: &Vfs,
    segments: &[String],
    collection: &DavCollection,
    kind: Kind,
    hrefs: Vec<String>,
    wanted: Wanted,
) -> Response {
    let db = vfs.db();
    let mut resources = Vec::new();
    let mut deleted = Vec::new();
    for href in hrefs {
        let Some(name) = href_object_name(&href, segments) else {
            deleted.push(href);
            continue;
        };
        match db.dav_object(collection.id, &name).await {
            Ok(Some(object)) => {
                let data = wanted.wants_data(kind).then_some(object.data);
                let meta = DavObjectMeta {
                    name: object.name,
                    uid: object.uid,
                    content_type: object.content_type,
                    etag: object.etag,
                    size: object.size,
                    created_at: object.created_at,
                    modified_at: object.modified_at,
                };
                resources.push(object_resource(segments, kind, &meta, data));
            }
            _ => deleted.push(object_href(segments, &name)),
        }
    }
    render_response(&resources, &deleted, &wanted, None)
}

// ---- helpers -----------------------------------------------------------

fn principal_href(user: &CurrentUser) -> String {
    format!("/dav/principals/{}/", user.username)
}

fn home_resource(user: &CurrentUser, segments: &[String], kind: Kind) -> Resource {
    let mut resource = Resource::empty(
        format!("{}/", davpath::encode_href(segments)),
        ResType::Collection,
    );
    resource.display_name = Some(format!(
        "{} {}",
        user.username,
        if kind == Kind::Calendar {
            "calendars"
        } else {
            "addressbooks"
        }
    ));
    resource.principal_href = Some(principal_href(user));
    let home = format!("{}/", davpath::encode_href(segments));
    match kind {
        Kind::Calendar => resource.calendar_home = Some(home),
        Kind::Addressbook => resource.addressbook_home = Some(home),
    }
    resource
}

fn collection_resource(
    user: &CurrentUser,
    kind: Kind,
    collection: &DavCollection,
    ctag: i64,
    data: Option<Vec<u8>>,
) -> Resource {
    let segments = vec![
        kind.plural().to_string(),
        user.username.clone(),
        collection.name.clone(),
    ];
    let mut resource = Resource::empty(
        format!("{}/", davpath::encode_href(&segments)),
        match kind {
            Kind::Calendar => ResType::Calendar,
            Kind::Addressbook => ResType::Addressbook,
        },
    );
    resource.display_name = Some(
        collection
            .displayname
            .clone()
            .unwrap_or_else(|| collection.name.clone()),
    );
    resource.ctag = Some(ctag);
    resource.collection_id = Some(collection.id);
    resource.color = collection.color.clone();
    resource.description = collection.description.clone();
    resource.principal_href = Some(principal_href(user));
    resource.modified_ms = Some(collection.modified_at);
    resource.created_ms = Some(collection.created_at);
    resource.data = data;
    resource
}

fn object_resource(
    segments: &[String],
    _kind: Kind,
    object: &DavObjectMeta,
    data: Option<Vec<u8>>,
) -> Resource {
    let mut resource = Resource::empty(object_href(segments, &object.name), ResType::Object);
    resource.display_name = Some(object.name.clone());
    resource.content_type = Some(object.content_type.clone());
    resource.size = Some(object.size.max(0) as u64);
    resource.etag = Some(object.etag.clone());
    resource.modified_ms = Some(object.modified_at);
    resource.created_ms = Some(object.created_at);
    resource.data = data;
    resource
}

fn object_href(segments: &[String], name: &str) -> String {
    let mut full = segments.to_vec();
    full.push(name.to_string());
    davpath::encode_href(&full)
}

/// Maps a report href to an object name when it points into the target
/// collection.
fn href_object_name(href: &str, segments: &[String]) -> Option<String> {
    let path = if href.starts_with('/') {
        href.to_string()
    } else {
        let uri: axum::http::Uri = href.parse().ok()?;
        uri.path().to_string()
    };
    let rest = path.strip_prefix("/dav")?;
    let parts = davpath::to_segments(rest).ok()?;
    if parts.len() != segments.len() + 1 || parts[..segments.len()] != *segments {
        return None;
    }
    parts.last().cloned()
}

fn parse_sync_token(token: &str) -> Option<(i64, i64)> {
    let rest = token.strip_prefix("urn:kolimi:sync:")?;
    let (id, seq) = rest.split_once(':')?;
    Some((id.parse().ok()?, seq.parse().ok()?))
}

pub(crate) fn invalid_sync_token() -> Response {
    let body = concat!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
        "<d:error xmlns:d=\"DAV:\"><d:valid-sync-token/></d:error>"
    );
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::FORBIDDEN;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    response
}

/// Parses PROPFIND depth + requested props from headers/body.
async fn propfind_inputs(headers: &HeaderMap, body: Body) -> Result<(u32, Wanted), Response> {
    let depth = header_str(headers, "depth")
        .unwrap_or("0")
        .trim()
        .to_ascii_lowercase();
    let depth = match depth.as_str() {
        "0" => 0,
        "1" => 1,
        "infinity" => 2,
        _ => return Err(StatusCode::BAD_REQUEST.into_response()),
    };
    let body = match to_bytes(body, MAX_REPORT_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return Err(StatusCode::BAD_REQUEST.into_response()),
    };
    let props = match parse_propfind(&body) {
        Ok(props) => props,
        Err(()) => return Err(StatusCode::BAD_REQUEST.into_response()),
    };
    Ok((depth, props.into()))
}

/// The declared resourcetype and settable properties of a create body.
type CreateBody = (Option<ResType>, Vec<(String, String, String)>);

/// Parses an extended MKCOL / MKCALENDAR body:
/// returns the declared resourcetype and settable properties.
fn parse_create_body(body: &[u8], mkcalendar: bool) -> Result<CreateBody, Response> {
    use quick_xml::events::Event;

    if body.is_empty() {
        return Ok((None, Vec::new()));
    }
    let mut reader = quick_xml::Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut scope = crate::xml::Scope::new();
    let mut stack: Vec<(String, Option<String>)> = Vec::new();
    let mut root_ok = false;
    let mut declared: Option<ResType> = None;
    let mut props: Vec<(String, String, String)> = Vec::new();
    let mut capture: Option<(usize, String, String, String)> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = e.name().as_ref().to_string();
                let attrs = crate::xml::collect_attrs(&e)
                    .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
                scope
                    .push_element(&attrs)
                    .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
                let (local, ns_opt) = scope.resolve_name(&name);
                let ns = ns_opt.clone().unwrap_or_default();
                if stack.is_empty() {
                    let expected = if mkcalendar {
                        local == "mkcalendar" && ns == CALDAV_NS
                    } else {
                        local == "mkcol" && ns == DAV_NS
                    };
                    if !expected {
                        return Err(StatusCode::BAD_REQUEST.into_response());
                    }
                    root_ok = true;
                } else if local == "resourcetype" && ns == DAV_NS {
                    // Inner children mark the type.
                } else if ns == CALDAV_NS && local == "calendar" {
                    declared = Some(ResType::Calendar);
                } else if ns == CARDDAV_NS && local == "addressbook" {
                    declared = Some(ResType::Addressbook);
                } else if local == "prop" && ns == DAV_NS {
                    // Children are the properties themselves.
                } else if stack.len() >= 3 {
                    let parent = stack.last().cloned();
                    if parent
                        .as_ref()
                        .is_some_and(|(l, n)| l == "prop" && n.as_deref() == Some(DAV_NS))
                    {
                        capture = Some((stack.len(), ns.clone(), local.clone(), String::new()));
                    }
                }
                if let Some((depth, _, _, out)) = capture.as_mut()
                    && stack.len() > *depth
                {
                    out.push('<');
                    out.push_str(&local);
                    out.push('>');
                }
                stack.push((local, ns_opt));
            }
            Ok(Event::Empty(e)) => {
                let name = e.name().as_ref().to_string();
                let attrs = crate::xml::collect_attrs(&e)
                    .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
                scope
                    .push_element(&attrs)
                    .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
                let (local, ns) = scope.resolve_name(&name);
                scope.pop_element();
                let ns = ns.unwrap_or_default();
                if ns == CALDAV_NS && local == "calendar" {
                    declared = Some(ResType::Calendar);
                } else if ns == CARDDAV_NS && local == "addressbook" {
                    declared = Some(ResType::Addressbook);
                }
                if stack.is_empty() {
                    return Err(StatusCode::BAD_REQUEST.into_response());
                }
            }
            Ok(Event::Text(t)) => {
                if let Some((_, _, _, out)) = capture.as_mut() {
                    let raw = t.into_inner();
                    let unescaped = quick_xml::escape::unescape(raw.as_ref())
                        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
                    out.push_str(&unescaped);
                }
            }
            Ok(Event::End(_)) => {
                scope.pop_element();
                let Some(_) = stack.pop() else {
                    return Err(StatusCode::BAD_REQUEST.into_response());
                };
                if let Some((depth, ns, local, out)) = &capture
                    && stack.len() == *depth
                {
                    props.push((ns.clone(), local.clone(), out.clone()));
                    capture = None;
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(StatusCode::BAD_REQUEST.into_response()),
        }
    }
    if !root_ok || !stack.is_empty() || capture.is_some() {
        return Err(StatusCode::BAD_REQUEST.into_response());
    }
    Ok((declared, props))
}

/// Maps a property to the collection column it sets.
fn prop_field(kind: Kind, ns: &str, local: &str) -> Option<&'static str> {
    match (ns, local) {
        (DAV_NS, "displayname") => Some("displayname"),
        (CALDAV_NS, "calendar-description") if kind == Kind::Calendar => Some("description"),
        (CARDDAV_NS, "addressbook-description") if kind == Kind::Addressbook => Some("description"),
        (APPLE_NS, "calendar-color") if kind == Kind::Calendar => Some("color"),
        _ => None,
    }
}

fn render_response(
    resources: &[Resource],
    deleted: &[String],
    wanted: &Wanted,
    sync_token: Option<&str>,
) -> Response {
    match render(resources, deleted, wanted, sync_token) {
        Ok(xml) => xml_response(xml),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn xml_response(xml: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(xml));
    *response.status_mut() = StatusCode::from_u16(207).unwrap_or(StatusCode::MULTI_STATUS);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    response
}

fn content_type_value(content_type: &str) -> HeaderValue {
    HeaderValue::from_str(content_type)
        .unwrap_or(HeaderValue::from_static("application/octet-stream"))
}

fn options() -> Response {
    let mut response = StatusCode::OK.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::ALLOW,
        HeaderValue::from_static(
            "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, REPORT, MKCOL, MKCALENDAR",
        ),
    );
    headers.insert(
        axum::http::HeaderName::from_static("dav"),
        HeaderValue::from_static(DAV_HEADER),
    );
    response
}

fn method_not_allowed() -> Response {
    StatusCode::METHOD_NOT_ALLOWED.into_response()
}

fn bad_request(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, message.to_string()).into_response()
}

fn header_str(headers: &HeaderMap, name: impl axum::http::header::AsHeaderName) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_roundtrips_sync_tokens() {
        let token = "urn:kolimi:sync:7:42".to_string();
        assert_eq!(parse_sync_token(&token), Some((7, 42)));
        assert_eq!(parse_sync_token("bogus"), None);
        assert_eq!(parse_sync_token("urn:kolimi:sync:7"), None);
        assert_eq!(parse_sync_token("urn:kolimi:sync:x:1"), None);
    }

    #[test]
    fn hrefs_map_to_object_names() {
        let segments = vec![
            "calendars".to_string(),
            "alice".to_string(),
            "work".to_string(),
        ];
        assert_eq!(
            href_object_name("/dav/calendars/alice/work/a.ics", &segments).as_deref(),
            Some("a.ics")
        );
        assert_eq!(
            href_object_name("/dav/calendars/alice/work/event%201.ics", &segments).as_deref(),
            Some("event 1.ics")
        );
        assert!(href_object_name("/dav/calendars/alice/other/a.ics", &segments).is_none());
        assert!(href_object_name("/dav/calendars/alice/work", &segments).is_none());
        assert!(href_object_name("/dav/calendars/alice/work/../x", &segments).is_none());
    }

    #[test]
    fn parses_mkcalendar_body() {
        let body = br#"<?xml version="1.0"?>
            <c:mkcalendar xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"
                          xmlns:apple="http://apple.com/ns/ical/">
              <d:set><d:prop>
                <d:displayname>Work</d:displayname>
                <apple:calendar-color>#ff0000ff</apple:calendar-color>
                <c:calendar-description>Team calendar</c:calendar-description>
              </d:prop></d:set>
            </c:mkcalendar>"#;
        let (declared, props) = parse_create_body(body, true).unwrap();
        assert!(declared.is_none());
        assert_eq!(props.len(), 3);
        assert!(
            props.iter().any(|(ns, local, value)| ns == DAV_NS
                && local == "displayname"
                && value == "Work")
        );
        assert!(
            props
                .iter()
                .any(|(ns, _, value)| ns == APPLE_NS && value == "#ff0000ff")
        );
    }

    #[test]
    fn parses_extended_mkcol_resourcetype() {
        let body = br#"<d:mkcol xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
              <d:set><d:prop>
                <d:resourcetype><d:collection/><card:addressbook/></d:resourcetype>
                <d:displayname>Friends</d:displayname>
              </d:prop></d:set>
            </d:mkcol>"#;
        let (declared, props) = parse_create_body(body, false).unwrap();
        assert!(matches!(declared, Some(ResType::Addressbook)));
        assert!(props.iter().any(|(_, local, _)| local == "displayname"));
    }

    #[test]
    fn rejects_wrong_create_roots() {
        assert!(
            parse_create_body(
                b"<c:mkcalendar xmlns:c='urn:ietf:params:xml:ns:caldav'/>",
                false
            )
            .is_err()
        );
        assert!(parse_create_body(b"<d:mkcol xmlns:d='DAV:'/>", true).is_err());
    }
}
