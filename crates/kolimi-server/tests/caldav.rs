//! M4 integration tests: CalDAV/CardDAV discovery, collections, object
//! CRUD, reports, and `sync-collection` as seen by protocol clients.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use kolimi_auth::password::hash_password;
use kolimi_server::{AppState, build_app};
use tower::ServiceExt;

const ALICE: &str = "alice";
const BOB: &str = "bob";
const PASS: &str = "test password 123";
const ORIGIN: &str = "http://localhost:8080";

const EVENT: &str = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//Kolimi//Test//EN\r\n\
BEGIN:VEVENT\r\n\
UID:event-1@kolimi\r\n\
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

const EVENT_2: &str = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
BEGIN:VEVENT\r\n\
UID:event-2@kolimi\r\n\
DTSTAMP:20261011T000000Z\r\n\
DTSTART:20261013T090000Z\r\n\
SUMMARY:Review\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

const VCARD: &str = "BEGIN:VCARD\r\n\
VERSION:3.0\r\n\
UID:contact-1@kolimi\r\n\
FN:Ada Lovelace\r\n\
N:Lovelace;Ada;;;\r\n\
EMAIL:ada@example.com\r\n\
END:VCARD\r\n";

struct TestServer {
    app: Router,
    _dir: tempfile::TempDir,
}

async fn setup() -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    for user in [ALICE, BOB] {
        state
            .db
            .create_user(user, &hash_password(PASS).unwrap())
            .await
            .unwrap();
    }
    let app = build_app(state);
    TestServer { app, _dir: dir }
}

fn basic(username: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{username}:{PASS}")))
}

fn dav_request(
    method: &str,
    uri: &str,
    username: Option<&str>,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(username) = username {
        builder = builder.header(header::AUTHORIZATION, basic(username));
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder
        .body(Body::from(body.unwrap_or_default().to_vec()))
        .unwrap()
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

fn xml(body: &[u8]) -> String {
    String::from_utf8_lossy(body).to_string()
}

fn between(haystack: &str, start: &str, end: &str) -> String {
    let start = haystack.find(start).expect("start marker") + start.len();
    let rest = &haystack[start..];
    let end = rest.find(end).expect("end marker");
    rest[..end].to_string()
}

fn propfind(username: &str, uri: &str, depth: &str, body: &str) -> Request<Body> {
    dav_request(
        "PROPFIND",
        uri,
        Some(username),
        &[("depth", depth), ("content-type", "application/xml")],
        Some(body.as_bytes()),
    )
}

async fn mkcalendar(server: &TestServer, username: &str, uri: &str, body: &str) -> StatusCode {
    send(
        &server.app,
        dav_request(
            "MKCALENDAR",
            uri,
            Some(username),
            &[("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await
    .0
}

async fn put_object(
    server: &TestServer,
    username: &str,
    uri: &str,
    content_type: &str,
    data: &[u8],
) -> (StatusCode, HeaderMap) {
    let (status, headers, _) = send(
        &server.app,
        dav_request(
            "PUT",
            uri,
            Some(username),
            &[("content-type", content_type)],
            Some(data),
        ),
    )
    .await;
    (status, headers)
}

#[tokio::test]
async fn well_known_discovery_and_principal() {
    let server = setup().await;

    // RFC 6764 discovery: well-known redirects to the DAV root.
    for path in ["/.well-known/caldav", "/.well-known/carddav"] {
        let (status, headers, _) =
            send(&server.app, dav_request("GET", path, None, &[], None)).await;
        assert_eq!(status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(headers.get(header::LOCATION).unwrap(), "/dav/");
    }

    // The DAV root points at the caller's principal.
    let body = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop>
        <d:current-user-principal/><d:resourcetype/></d:prop></d:propfind>"#;
    let (status, _, response) = send(&server.app, propfind(ALICE, "/dav/", "0", body)).await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let text = xml(&response);
    assert!(text.contains("/dav/principals/alice/"), "{text}");

    // The principal advertises both homes.
    let body = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"
        xmlns:c="urn:ietf:params:xml:ns:caldav"
        xmlns:card="urn:ietf:params:xml:ns:carddav"><d:prop>
        <d:displayname/><d:resourcetype/>
        <c:calendar-home-set/><card:addressbook-home-set/></d:prop></d:propfind>"#;
    let (status, _, response) = send(
        &server.app,
        propfind(ALICE, "/dav/principals/alice/", "0", body),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let text = xml(&response);
    assert!(text.contains("<d:principal/>"), "{text}");
    assert!(text.contains("<c:calendar-home-set>"), "{text}");
    assert!(text.contains("/dav/calendars/alice/"), "{text}");
    assert!(text.contains("<card:addressbook-home-set>"), "{text}");
    assert!(text.contains("/dav/addressbooks/alice/"), "{text}");

    // Other users' principals are invisible.
    let (status, _, _) = send(
        &server.app,
        propfind(ALICE, "/dav/principals/bob/", "0", ""),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mkcalendar_listing_and_extended_mkcol() {
    let server = setup().await;
    let body = r#"<?xml version="1.0"?>
        <c:mkcalendar xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"
                      xmlns:apple="http://apple.com/ns/ical/">
          <d:set><d:prop>
            <d:displayname>Work</d:displayname>
            <apple:calendar-color>#ff0000ff</apple:calendar-color>
            <c:calendar-description>Team calendar</c:calendar-description>
          </d:prop></d:set>
        </c:mkcalendar>"#;
    assert_eq!(
        mkcalendar(&server, ALICE, "/dav/calendars/alice/work", body).await,
        StatusCode::CREATED
    );
    // Duplicates are rejected.
    assert_eq!(
        mkcalendar(&server, ALICE, "/dav/calendars/alice/work", "").await,
        StatusCode::METHOD_NOT_ALLOWED
    );

    // Extended MKCOL with a calendar resourcetype works too.
    let body = r#"<d:mkcol xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
        <d:set><d:prop>
          <d:resourcetype><d:collection/><c:calendar/></d:resourcetype>
          <d:displayname>Personal</d:displayname>
        </d:prop></d:set></d:mkcol>"#;
    let (status, _, _) = send(
        &server.app,
        dav_request(
            "MKCOL",
            "/dav/calendars/alice/personal",
            Some(ALICE),
            &[("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // The home lists both with calendar properties.
    let body = r#"<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"
        xmlns:cs="http://calendarserver.org/ns/" xmlns:apple="http://apple.com/ns/ical/">
        <d:prop><d:resourcetype/><d:displayname/><cs:getctag/>
        <c:supported-calendar-component-set/><apple:calendar-color/></d:prop></d:propfind>"#;
    let (status, _, response) = send(
        &server.app,
        propfind(ALICE, "/dav/calendars/alice/", "1", body),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let text = xml(&response);
    assert!(text.contains("/dav/calendars/alice/work"), "{text}");
    assert!(text.contains("/dav/calendars/alice/personal"), "{text}");
    assert!(text.contains("<d:collection/>"), "{text}");
    assert!(text.contains("<c:calendar/>"), "{text}");
    assert!(
        text.contains("<d:displayname>Work</d:displayname>"),
        "{text}"
    );
    assert!(text.contains("<c:comp name=\"VEVENT\"/>"), "{text}");
    assert!(
        text.contains("<apple:calendar-color>#ff0000ff</apple:calendar-color>"),
        "{text}"
    );
    assert!(text.contains("<cs:getctag>0</cs:getctag>"), "{text}");
}

#[tokio::test]
async fn event_crud_etags_and_valarm_preservation() {
    let server = setup().await;
    mkcalendar(&server, ALICE, "/dav/calendars/alice/work", "").await;
    let uri = "/dav/calendars/alice/work/event-1.ics";

    let (status, headers) =
        put_object(&server, ALICE, uri, "text/calendar", EVENT.as_bytes()).await;
    assert_eq!(status, StatusCode::CREATED);
    let etag = headers
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Byte-exact round trip (VALARM included).
    let (status, headers, body) =
        send(&server.app, dav_request("GET", uri, Some(ALICE), &[], None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, EVENT.as_bytes());
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "text/calendar; charset=utf-8"
    );
    assert_eq!(headers.get(header::ETAG).unwrap(), &etag);

    // Conditional GET.
    let (status, _, _) = send(
        &server.app,
        dav_request("GET", uri, Some(ALICE), &[("if-none-match", &etag)], None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);

    // Update with a stale If-Match fails; the current one succeeds.
    let (status, _) = put_object(&server, ALICE, uri, "text/calendar", EVENT_2.as_bytes()).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = send(
        &server.app,
        dav_request(
            "PUT",
            uri,
            Some(ALICE),
            &[("content-type", "text/calendar"), ("if-match", &etag)],
            Some(EVENT.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    let (status, _, _) = send(
        &server.app,
        dav_request(
            "PUT",
            uri,
            Some(ALICE),
            &[("content-type", "text/calendar"), ("if-none-match", "*")],
            Some(EVENT.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);

    // Depth-1 PROPFIND lists the object with its ETag and content type.
    let body = r#"<d:propfind xmlns:d="DAV:"><d:prop>
        <d:getetag/><d:getcontenttype/><d:getcontentlength/></d:prop></d:propfind>"#;
    let (status, _, response) = send(
        &server.app,
        propfind(ALICE, "/dav/calendars/alice/work/", "1", body),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let text = xml(&response);
    assert!(
        text.contains("/dav/calendars/alice/work/event-1.ics"),
        "{text}"
    );
    assert!(
        text.contains("<d:getcontenttype>text/calendar; charset=utf-8</d:getcontenttype>"),
        "{text}"
    );

    // Delete lifecycle.
    let (status, _, _) = send(
        &server.app,
        dav_request("DELETE", uri, Some(ALICE), &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = send(&server.app, dav_request("GET", uri, Some(ALICE), &[], None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = send(
        &server.app,
        dav_request("DELETE", uri, Some(ALICE), &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_payloads_and_uid_conflicts() {
    let server = setup().await;
    mkcalendar(&server, ALICE, "/dav/calendars/alice/work", "").await;

    let (status, _) = put_object(
        &server,
        ALICE,
        "/dav/calendars/alice/work/bad.ics",
        "text/calendar",
        b"this is not a calendar",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let no_uid = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nDTSTART:20261012T090000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let (status, _) = put_object(
        &server,
        ALICE,
        "/dav/calendars/alice/work/nouid.ics",
        "text/calendar",
        no_uid.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Two resources may not share a UID.
    let (status, _) = put_object(
        &server,
        ALICE,
        "/dav/calendars/alice/work/a.ics",
        "text/calendar",
        EVENT.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = put_object(
        &server,
        ALICE,
        "/dav/calendars/alice/work/b.ics",
        "text/calendar",
        EVENT.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    // Updating the same resource is fine.
    let (status, _) = put_object(
        &server,
        ALICE,
        "/dav/calendars/alice/work/a.ics",
        "text/calendar",
        EVENT.as_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn calendar_query_and_multiget_reports() {
    let server = setup().await;
    mkcalendar(&server, ALICE, "/dav/calendars/alice/work", "").await;
    put_object(
        &server,
        ALICE,
        "/dav/calendars/alice/work/event-1.ics",
        "text/calendar",
        EVENT.as_bytes(),
    )
    .await;
    put_object(
        &server,
        ALICE,
        "/dav/calendars/alice/work/event-2.ics",
        "text/calendar",
        EVENT_2.as_bytes(),
    )
    .await;

    // calendar-query returns the whole collection with data.
    let body = r#"<?xml version="1.0"?>
        <c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
          <d:prop><d:getetag/><c:calendar-data/></d:prop>
          <c:filter><c:comp-filter name="VCALENDAR">
            <c:comp-filter name="VEVENT">
              <c:time-range start="20261012T000000Z" end="20261014T000000Z"/>
            </c:comp-filter></c:comp-filter></c:filter>
        </c:calendar-query>"#;
    let (status, _, response) = send(
        &server.app,
        dav_request(
            "REPORT",
            "/dav/calendars/alice/work",
            Some(ALICE),
            &[("depth", "1"), ("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let text = xml(&response);
    assert!(
        text.contains("/dav/calendars/alice/work/event-1.ics"),
        "{text}"
    );
    assert!(
        text.contains("/dav/calendars/alice/work/event-2.ics"),
        "{text}"
    );
    assert!(text.contains("<c:calendar-data>BEGIN:VCALENDAR"), "{text}");
    assert!(text.contains("UID:event-1@kolimi"), "{text}");

    // calendar-multiget returns exactly the requested resources.
    let body = r#"<?xml version="1.0"?>
        <c:calendar-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
          <d:prop><d:getetag/><c:calendar-data/></d:prop>
          <d:href>/dav/calendars/alice/work/event-2.ics</d:href>
          <d:href>/dav/calendars/alice/work/missing.ics</d:href>
          <d:href>/dav/calendars/alice/other/elsewhere.ics</d:href>
        </c:calendar-multiget>"#;
    let (status, _, response) = send(
        &server.app,
        dav_request(
            "REPORT",
            "/dav/calendars/alice/work",
            Some(ALICE),
            &[("depth", "1"), ("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let text = xml(&response);
    assert!(text.contains("UID:event-2@kolimi"), "{text}");
    assert!(!text.contains("UID:event-1@kolimi"), "{text}");
    // Unknown and out-of-collection hrefs are reported as 404.
    assert!(
        text.matches("HTTP/1.1 404 Not Found").count() >= 2,
        "{text}"
    );
}

#[tokio::test]
async fn sync_collection_lifecycle() {
    let server = setup().await;
    mkcalendar(&server, ALICE, "/dav/calendars/alice/work", "").await;
    put_object(
        &server,
        ALICE,
        "/dav/calendars/alice/work/event-1.ics",
        "text/calendar",
        EVENT.as_bytes(),
    )
    .await;
    put_object(
        &server,
        ALICE,
        "/dav/calendars/alice/work/event-2.ics",
        "text/calendar",
        EVENT_2.as_bytes(),
    )
    .await;

    // Initial sync: everything, plus a token.
    let body = r#"<?xml version="1.0"?>
        <d:sync-collection xmlns:d="DAV:">
          <d:sync-level>1</d:sync-level>
          <d:prop><d:getetag/><d:getcontenttype/></d:prop>
        </d:sync-collection>"#;
    let (status, _, response) = send(
        &server.app,
        dav_request(
            "REPORT",
            "/dav/calendars/alice/work",
            Some(ALICE),
            &[("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let text = xml(&response);
    assert!(text.contains("event-1.ics"), "{text}");
    assert!(text.contains("event-2.ics"), "{text}");
    let token = between(&text, "<d:sync-token>", "</d:sync-token>");
    assert!(token.starts_with("urn:kolimi:sync:"), "{token}");

    // Change one object and delete another.
    put_object(
        &server,
        ALICE,
        "/dav/calendars/alice/work/event-1.ics",
        "text/calendar",
        EVENT_2.replace("event-2", "event-1").as_bytes(),
    )
    .await;
    let (status, _, _) = send(
        &server.app,
        dav_request(
            "DELETE",
            "/dav/calendars/alice/work/event-2.ics",
            Some(ALICE),
            &[],
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Incremental sync reports the upsert and the deletion.
    let body = format!(
        r#"<d:sync-collection xmlns:d="DAV:">
          <d:sync-token>{token}</d:sync-token>
          <d:sync-level>1</d:sync-level>
          <d:prop><d:getetag/></d:prop>
        </d:sync-collection>"#
    );
    let (status, _, response) = send(
        &server.app,
        dav_request(
            "REPORT",
            "/dav/calendars/alice/work",
            Some(ALICE),
            &[("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let text = xml(&response);
    assert!(
        text.contains("/dav/calendars/alice/work/event-1.ics"),
        "{text}"
    );
    assert!(text.contains("HTTP/1.1 404 Not Found"), "{text}");
    assert!(
        text.contains("/dav/calendars/alice/work/event-2.ics"),
        "{text}"
    );
    let new_token = between(&text, "<d:sync-token>", "</d:sync-token>");
    assert_ne!(new_token, token);

    // A bogus token is rejected with valid-sync-token.
    let body = r#"<d:sync-collection xmlns:d="DAV:">
          <d:sync-token>urn:kolimi:sync:999:1</d:sync-token>
          <d:sync-level>1</d:sync-level>
          <d:prop><d:getetag/></d:prop>
        </d:sync-collection>"#;
    let (status, _, response) = send(
        &server.app,
        dav_request(
            "REPORT",
            "/dav/calendars/alice/work",
            Some(ALICE),
            &[("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(xml(&response).contains("valid-sync-token"));

    // Infinite sync level is not supported.
    let body = r#"<d:sync-collection xmlns:d="DAV:">
          <d:sync-level>infinite</d:sync-level>
          <d:prop><d:getetag/></d:prop>
        </d:sync-collection>"#;
    let (status, _, _) = send(
        &server.app,
        dav_request(
            "REPORT",
            "/dav/calendars/alice/work",
            Some(ALICE),
            &[("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn addressbook_flow() {
    let server = setup().await;

    // macOS-style extended MKCOL creates an address book.
    let body = r#"<d:mkcol xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
        <d:set><d:prop>
          <d:resourcetype><d:collection/><card:addressbook/></d:resourcetype>
          <d:displayname>Friends</d:displayname>
        </d:prop></d:set></d:mkcol>"#;
    let (status, _, _) = send(
        &server.app,
        dav_request(
            "MKCOL",
            "/dav/addressbooks/alice/friends",
            Some(ALICE),
            &[("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let uri = "/dav/addressbooks/alice/friends/contact-1.vcf";
    let (status, _) = put_object(&server, ALICE, uri, "text/vcard", VCARD.as_bytes()).await;
    assert_eq!(status, StatusCode::CREATED);

    // PROPFIND on the home shows the address book resourcetype.
    let body = r#"<d:propfind xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
        <d:prop><d:resourcetype/><d:displayname/>
        <card:supported-address-data/></d:prop></d:propfind>"#;
    let (status, _, response) = send(
        &server.app,
        propfind(ALICE, "/dav/addressbooks/alice/", "1", body),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let text = xml(&response);
    assert!(text.contains("<card:addressbook/>"), "{text}");
    assert!(
        text.contains("<d:displayname>Friends</d:displayname>"),
        "{text}"
    );
    assert!(text.contains("address-data-type"), "{text}");

    // addressbook-multiget returns the vCard.
    let body = r#"<card:addressbook-multiget xmlns:d="DAV:"
        xmlns:card="urn:ietf:params:xml:ns:carddav">
        <d:prop><d:getetag/><card:address-data/></d:prop>
        <d:href>/dav/addressbooks/alice/friends/contact-1.vcf</d:href>
        </card:addressbook-multiget>"#;
    let (status, _, response) = send(
        &server.app,
        dav_request(
            "REPORT",
            "/dav/addressbooks/alice/friends",
            Some(ALICE),
            &[("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let text = xml(&response);
    assert!(text.contains("<card:address-data>BEGIN:VCARD"), "{text}");
    assert!(text.contains("FN:Ada Lovelace"), "{text}");

    // addressbook-query also works.
    let body = r#"<card:addressbook-query xmlns:d="DAV:"
        xmlns:card="urn:ietf:params:xml:ns:carddav">
        <d:prop><d:getetag/></d:prop>
        </card:addressbook-query>"#;
    let (status, _, response) = send(
        &server.app,
        dav_request(
            "REPORT",
            "/dav/addressbooks/alice/friends",
            Some(ALICE),
            &[("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    assert!(xml(&response).contains("contact-1.vcf"));

    // And sync-collection yields a token.
    let body = r#"<d:sync-collection xmlns:d="DAV:">
        <d:sync-level>1</d:sync-level><d:prop><d:getetag/></d:prop></d:sync-collection>"#;
    let (status, _, response) = send(
        &server.app,
        dav_request(
            "REPORT",
            "/dav/addressbooks/alice/friends",
            Some(ALICE),
            &[("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    assert!(xml(&response).contains("<d:sync-token>urn:kolimi:sync:"));
}

#[tokio::test]
async fn proppatch_updates_collection_properties() {
    let server = setup().await;
    mkcalendar(&server, ALICE, "/dav/calendars/alice/work", "").await;

    let body = r#"<d:propertyupdate xmlns:d="DAV:" xmlns:apple="http://apple.com/ns/ical/">
        <d:set><d:prop>
          <d:displayname>Renamed</d:displayname>
          <apple:calendar-color>#00ff00ff</apple:calendar-color>
        </d:prop></d:set></d:propertyupdate>"#;
    let (status, _, response) = send(
        &server.app,
        dav_request(
            "PROPPATCH",
            "/dav/calendars/alice/work",
            Some(ALICE),
            &[("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    assert!(xml(&response).contains("HTTP/1.1 200 OK"));

    let body = r#"<d:propfind xmlns:d="DAV:" xmlns:apple="http://apple.com/ns/ical/">
        <d:prop><d:displayname/><apple:calendar-color/></d:prop></d:propfind>"#;
    let (status, _, response) = send(
        &server.app,
        propfind(ALICE, "/dav/calendars/alice/work", "0", body),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let text = xml(&response);
    assert!(
        text.contains("<d:displayname>Renamed</d:displayname>"),
        "{text}"
    );
    assert!(text.contains("#00ff00ff"), "{text}");

    // Protected properties are refused.
    let body = r#"<d:propertyupdate xmlns:d="DAV:"><d:set><d:prop>
        <d:getetag>x</d:getetag></d:prop></d:set></d:propertyupdate>"#;
    let (status, _, response) = send(
        &server.app,
        dav_request(
            "PROPPATCH",
            "/dav/calendars/alice/work",
            Some(ALICE),
            &[("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    assert!(xml(&response).contains("HTTP/1.1 403 Forbidden"));
}

#[tokio::test]
async fn cross_user_isolation_and_reserved_names() {
    let server = setup().await;
    mkcalendar(&server, ALICE, "/dav/calendars/alice/work", "").await;
    put_object(
        &server,
        ALICE,
        "/dav/calendars/alice/work/event-1.ics",
        "text/calendar",
        EVENT.as_bytes(),
    )
    .await;

    for (method, uri) in [
        ("PROPFIND", "/dav/calendars/alice/"),
        ("PROPFIND", "/dav/calendars/alice/work"),
        ("GET", "/dav/calendars/alice/work/event-1.ics"),
        ("REPORT", "/dav/calendars/alice/work"),
        ("DELETE", "/dav/calendars/alice/work/event-1.ics"),
    ] {
        let (status, _, _) = send(
            &server.app,
            dav_request(method, uri, Some(BOB), &[("depth", "1")], None),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
    }

    // The DAV namespace roots are intercepted before the file tree.
    let (status, _, _) = send(
        &server.app,
        dav_request("MKCOL", "/dav/calendars", Some(ALICE), &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // And they are reserved as file names at the root of the file tree.
    let (status, _, _) = send(
        &server.app,
        dav_request("MKCOL", "/dav/tmp", Some(ALICE), &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = put_object(&server, ALICE, "/dav/tmp/x.txt", "text/plain", b"x").await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = send(
        &server.app,
        dav_request(
            "MOVE",
            "/dav/tmp/x.txt",
            Some(ALICE),
            &[("destination", "/dav/calendars/x.txt")],
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn file_tree_sync_collection() {
    let server = setup().await;
    let (status, _, _) = send(
        &server.app,
        dav_request("MKCOL", "/dav/folder", Some(ALICE), &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = put_object(&server, ALICE, "/dav/folder/a.txt", "text/plain", b"a").await;
    assert_eq!(status, StatusCode::CREATED);

    let body = r#"<d:sync-collection xmlns:d="DAV:">
        <d:sync-level>1</d:sync-level><d:prop><d:getetag/></d:prop></d:sync-collection>"#;
    let (status, _, response) = send(
        &server.app,
        dav_request(
            "REPORT",
            "/dav/",
            Some(ALICE),
            &[("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let text = xml(&response);
    assert!(text.contains("/dav/folder/a.txt"), "{text}");
    assert!(text.contains("/dav/folder"), "{text}");
    let token = between(&text, "<d:sync-token>", "</d:sync-token>");

    // Delete the file; the incremental sync reports it.
    let (status, _, _) = send(
        &server.app,
        dav_request("DELETE", "/dav/folder/a.txt", Some(ALICE), &[], None),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let body = format!(
        r#"<d:sync-collection xmlns:d="DAV:">
        <d:sync-token>{token}</d:sync-token>
        <d:sync-level>1</d:sync-level><d:prop><d:getetag/></d:prop></d:sync-collection>"#
    );
    let (status, _, response) = send(
        &server.app,
        dav_request(
            "REPORT",
            "/dav/",
            Some(ALICE),
            &[("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let text = xml(&response);
    assert!(text.contains("/dav/folder/a.txt"), "{text}");
    assert!(text.contains("HTTP/1.1 404 Not Found"), "{text}");

    // Scoped sync on a subdirectory filters unrelated changes.
    let body = r#"<d:sync-collection xmlns:d="DAV:">
        <d:sync-level>1</d:sync-level><d:prop><d:getetag/></d:prop></d:sync-collection>"#;
    let (status, _, response) = send(
        &server.app,
        dav_request(
            "REPORT",
            "/dav/folder",
            Some(ALICE),
            &[("content-type", "application/xml")],
            Some(body.as_bytes()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let text = xml(&response);
    assert!(text.contains("/dav/folder/a.txt"), "{text}");
    assert!(!text.contains("/dav/folder\""), "{text}");
}
