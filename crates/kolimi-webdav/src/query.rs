//! Evaluation of CalDAV/CardDAV query filters against stored objects.
//!
//! iCalendar and vCard are parsed structurally (BEGIN/END + property lines)
//! rather than fully, which is enough for `comp-filter`, `prop-filter`,
//! `text-match` and `time-range`. Time values are interpreted as UTC when
//! they are UTC or offset-qualified. Floating/TZID values are compared with
//! a ±1 day fudge so a client's month view never misses an event because the
//! server did not resolve a timezone; over-inclusion is preferred to loss.

use time::{Date, Month, PrimitiveDateTime, Time};

use crate::filter::{CompFilter, Filter, PropFilter, TextMatch, TimeRange};

#[derive(Debug)]
struct Prop {
    name: String,
    value: String,
    params: Vec<(String, String)>,
}

#[derive(Debug)]
struct Component {
    name: String,
    props: Vec<Prop>,
    children: Vec<Component>,
}

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

fn parse_component(data: &str) -> Option<Component> {
    let mut root: Option<Component> = None;
    let mut stack: Vec<Component> = Vec::new();
    for line in unfold(data) {
        if line.trim().is_empty() {
            continue;
        }
        let (head, value) = line.split_once(':')?;
        let mut pieces = head.split(';');
        let name = pieces.next()?.rsplit('.').next()?.to_ascii_uppercase();
        let params: Vec<(String, String)> = pieces
            .filter_map(|piece| {
                piece.split_once('=').map(|(key, value)| {
                    (
                        key.to_ascii_uppercase(),
                        value.trim_matches('"').to_string(),
                    )
                })
            })
            .collect();
        if name == "BEGIN" {
            stack.push(Component {
                name: value.trim().to_ascii_uppercase(),
                props: Vec::new(),
                children: Vec::new(),
            });
        } else if name == "END" {
            let component = stack.pop()?;
            if let Some(parent) = stack.last_mut() {
                parent.children.push(component);
            } else if root.is_none() {
                root = Some(component);
            } else {
                return None;
            }
        } else if let Some(current) = stack.last_mut() {
            current.props.push(Prop {
                name,
                value: value.trim().to_string(),
                params,
            });
        }
    }
    root
}

fn month(value: u8) -> Option<Month> {
    Month::try_from(value).ok()
}

/// Parses an iCalendar DATE or DATE-TIME. Returns `(epoch, is_date,
/// is_floating)`.
fn parse_dt(value: &str) -> Option<(i64, bool, bool)> {
    let value = value.trim();
    let (body, offset, qualified) = if let Some(stripped) = value.strip_suffix('Z') {
        (stripped, 0i64, true)
    } else if value.len() > 5 {
        let (body, tail) = value.split_at(value.len() - 5);
        let bytes = tail.as_bytes();
        if matches!(bytes.first(), Some(b'+' | b'-')) && bytes[1..].iter().all(u8::is_ascii_digit) {
            let hours: i64 = tail[1..3].parse().ok()?;
            let minutes: i64 = tail[3..5].parse().ok()?;
            let offset = (hours * 3600 + minutes * 60) * if bytes[0] == b'-' { -1 } else { 1 };
            (body, offset, true)
        } else {
            (value, 0, false)
        }
    } else {
        (value, 0, false)
    };
    if body.len() == 8 && body.bytes().all(|byte| byte.is_ascii_digit()) {
        let date = Date::from_calendar_date(
            body[0..4].parse().ok()?,
            month(body[4..6].parse().ok()?)?,
            body[6..8].parse().ok()?,
        )
        .ok()?;
        let stamp = PrimitiveDateTime::new(date, Time::MIDNIGHT)
            .assume_utc()
            .unix_timestamp();
        return Some((stamp, true, !qualified));
    }
    if body.len() >= 15 && body.as_bytes().get(8) == Some(&b'T') {
        let date = Date::from_calendar_date(
            body[0..4].parse().ok()?,
            month(body[4..6].parse().ok()?)?,
            body[6..8].parse().ok()?,
        )
        .ok()?;
        let time = Time::from_hms(
            body[9..11].parse().ok()?,
            body[11..13].parse().ok()?,
            body[13..15].parse().ok()?,
        )
        .ok()?;
        let stamp = PrimitiveDateTime::new(date, time)
            .assume_utc()
            .unix_timestamp()
            - offset;
        return Some((stamp, false, !qualified));
    }
    None
}

/// Parses an RFC 5545 DURATION (days/hours/minutes/seconds/weeks).
fn parse_duration(value: &str) -> Option<i64> {
    let mut total = 0i64;
    let mut number = 0i64;
    let mut in_time = false;
    let mut saw_unit = false;
    for character in value.trim().trim_start_matches('P').chars() {
        match character {
            '0'..='9' => {
                number = number
                    .checked_mul(10)?
                    .checked_add(i64::from(character as u8 - b'0'))?
            }
            'T' => in_time = true,
            'W' => {
                total += number * 604_800;
                number = 0;
                saw_unit = true;
            }
            'D' => {
                total += number * 86_400;
                number = 0;
                saw_unit = true;
            }
            'H' => {
                total += number * 3_600;
                number = 0;
                saw_unit = true;
            }
            'M' if in_time => {
                total += number * 60;
                number = 0;
                saw_unit = true;
            }
            'S' => {
                total += number;
                number = 0;
                saw_unit = true;
            }
            _ => return None,
        }
    }
    saw_unit.then_some(total)
}

fn prop<'a>(component: &'a Component, name: &str) -> Option<&'a Prop> {
    component
        .props
        .iter()
        .find(|property| property.name.eq_ignore_ascii_case(name))
}

fn prop_values<'a>(component: &'a Component, name: &str) -> Vec<&'a Prop> {
    component
        .props
        .iter()
        .filter(|property| property.name.eq_ignore_ascii_case(name))
        .collect()
}

fn compile_time_range(range: &TimeRange) -> (Option<i64>, Option<i64>) {
    (
        range.start.as_deref().and_then(parse_dt).map(|(t, _, _)| t),
        range.end.as_deref().and_then(parse_dt).map(|(t, _, _)| t),
    )
}

fn rrule_until(rule: &str) -> Option<i64> {
    rule.split(';')
        .find_map(|part| part.strip_prefix("UNTIL="))
        .and_then(|value| parse_dt(value).map(|(stamp, _, _)| stamp))
}

/// The interval a component occupies, or `None` when it carries no dates
/// (a dateless VTODO matches any time range).
fn interval(component: &Component) -> Option<(i64, i64, bool)> {
    let start_prop = prop(component, "DTSTART");
    let end_prop = prop(component, "DTEND").or_else(|| prop(component, "DUE"));
    let start = start_prop.and_then(|property| parse_dt(&property.value));
    let end = end_prop.and_then(|property| parse_dt(&property.value));
    let completed = prop(component, "COMPLETED").and_then(|property| parse_dt(&property.value));
    let floating = start_prop
        .is_some_and(|property| property.params.iter().any(|(key, _)| key == "TZID"))
        || start.is_some_and(|(_, _, floating)| floating);
    match (start, end) {
        (Some((start, is_date, _)), Some((end, _, _))) => Some((start, end, floating && !is_date)),
        (Some((start, is_date, _)), None) => {
            if let Some(duration) =
                prop(component, "DURATION").and_then(|property| parse_duration(&property.value))
            {
                return Some((start, start + duration, floating && !is_date));
            }
            let end = if is_date { start + 86_400 } else { start };
            Some((start, end, floating && !is_date))
        }
        (None, Some((end, _, _))) => Some((end, end, floating)),
        (None, None) => completed.map(|(stamp, _, _)| (stamp, stamp, false)),
    }
}

fn component_overlaps(component: &Component, range: &TimeRange) -> bool {
    let (range_start, range_end) = compile_time_range(range);
    let Some((start, end, floating)) = interval(component) else {
        return true;
    };
    let (start, end) = if floating {
        (start - 86_400, end + 86_400)
    } else {
        (start, end)
    };
    // Recurring series: compare conservatively (base start / UNTIL) so an
    // occurrence inside the window is never dropped.
    if let Some(rule) = prop(component, "RRULE") {
        let until = rrule_until(&rule.value);
        return start <= range_end.unwrap_or(i64::MAX)
            && until.is_none_or(|until| until >= range_start.unwrap_or(i64::MIN));
    }
    match (range_start, range_end) {
        (Some(start_range), Some(end_range)) => {
            if start == end {
                start_range <= start && start < end_range
            } else {
                start < end_range && end > start_range
            }
        }
        (Some(start_range), None) => end > start_range || (start == end && start >= start_range),
        (None, Some(end_range)) => start < end_range,
        (None, None) => true,
    }
}

fn unescape(value: &str) -> String {
    value
        .replace("\\n", "\n")
        .replace("\\N", "\n")
        .replace("\\,", ",")
        .replace("\\;", ";")
}

fn text_matches(value: &str, text: &TextMatch) -> bool {
    let value = unescape(value);
    let hit = if text.collation.eq_ignore_ascii_case("i;octet") {
        value.contains(&text.value)
    } else {
        value.to_lowercase().contains(&text.value.to_lowercase())
    };
    hit != text.negate
}

fn prop_filter_matches(component: &Component, filter: &PropFilter) -> bool {
    let values = prop_values(component, &filter.name);
    if filter.is_not_defined {
        return values.is_empty();
    }
    if values.is_empty() {
        return false;
    }
    if let Some(range) = &filter.time_range {
        let (range_start, range_end) = compile_time_range(range);
        let matched = values.iter().any(|property| {
            let Some((stamp, _, _)) = parse_dt(&property.value) else {
                return false;
            };
            range_start.is_none_or(|start| stamp >= start)
                && range_end.is_none_or(|end| stamp < end)
        });
        if !matched {
            return false;
        }
    }
    match &filter.text_match {
        Some(text) => values
            .iter()
            .any(|property| text_matches(&property.value, text)),
        None => true,
    }
}

fn comp_filter_matches(component: &Component, filter: &CompFilter) -> bool {
    if !component.name.eq_ignore_ascii_case(&filter.name) {
        return false;
    }
    comp_body_matches(component, filter)
}

/// Applies a comp-filter's body to a component already known to have the
/// right name.
fn comp_body_matches(component: &Component, filter: &CompFilter) -> bool {
    if let Some(range) = &filter.time_range
        && !component_overlaps(component, range)
    {
        return false;
    }
    if !filter
        .prop_filters
        .iter()
        .all(|prop_filter| prop_filter_matches(component, prop_filter))
    {
        return false;
    }
    filter.comp_filters.iter().all(|child| {
        if child.is_not_defined {
            !component
                .children
                .iter()
                .any(|candidate| candidate.name.eq_ignore_ascii_case(&child.name))
        } else {
            component
                .children
                .iter()
                .any(|candidate| comp_filter_matches(candidate, child))
        }
    })
}

fn filter_matches(root: &Component, filter: &Filter) -> bool {
    let mut results: Vec<bool> = Vec::new();
    for comp_filter in &filter.comp_filters {
        if root.name.eq_ignore_ascii_case(&comp_filter.name) {
            if comp_filter.is_not_defined {
                results.push(false);
            } else {
                results.push(comp_body_matches(root, comp_filter));
            }
        } else if comp_filter.is_not_defined {
            results.push(
                !root
                    .children
                    .iter()
                    .any(|child| child.name.eq_ignore_ascii_case(&comp_filter.name)),
            );
        } else {
            results.push(
                root.children
                    .iter()
                    .any(|child| comp_filter_matches(child, comp_filter)),
            );
        }
    }
    for prop_filter in &filter.prop_filters {
        results.push(prop_filter_matches(root, prop_filter));
    }
    if results.is_empty() {
        return true;
    }
    if filter.any {
        results.iter().any(|matched| *matched)
    } else {
        results.iter().all(|matched| *matched)
    }
}

/// Whether an iCalendar object matches a `calendar-query` filter.
pub fn calendar_matches(data: &str, filter: &Filter) -> bool {
    parse_component(data).is_some_and(|root| filter_matches(&root, filter))
}

/// Whether a vCard object matches an `addressbook-query` filter.
pub fn addressbook_matches(data: &str, filter: &Filter) -> bool {
    parse_component(data).is_some_and(|root| filter_matches(&root, filter))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::filter::{CompFilter, PropFilter, TextMatch, TimeRange};

    const EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\n\
UID:event-1\r\nDTSTART:20261012T090000Z\r\nDTEND:20261012T100000Z\r\n\
SUMMARY:Standup\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    fn comp(name: &str) -> CompFilter {
        CompFilter {
            name: name.to_string(),
            ..CompFilter::default()
        }
    }

    fn root(event: CompFilter) -> Filter {
        Filter {
            comp_filters: vec![CompFilter {
                name: "VCALENDAR".to_string(),
                comp_filters: vec![event],
                ..CompFilter::default()
            }],
            ..Filter::default()
        }
    }

    #[test]
    fn time_range_keeps_only_overlaps() {
        let mut event = comp("VEVENT");
        event.time_range = Some(TimeRange {
            start: Some("20261011T000000Z".to_string()),
            end: Some("20261013T000000Z".to_string()),
        });
        assert!(calendar_matches(EVENT, &root(event)));

        let mut outside = comp("VEVENT");
        outside.time_range = Some(TimeRange {
            start: Some("20261013T000000Z".to_string()),
            end: Some("20261014T000000Z".to_string()),
        });
        assert!(!calendar_matches(EVENT, &root(outside)));
    }

    #[test]
    fn text_match_and_negation() {
        let mut summary = comp("VEVENT");
        summary.prop_filters.push(PropFilter {
            name: "SUMMARY".to_string(),
            text_match: Some(TextMatch {
                value: "stand".to_string(),
                negate: false,
                collation: "i;ascii-casemap".to_string(),
            }),
            ..PropFilter::default()
        });
        assert!(calendar_matches(EVENT, &root(summary.clone())));

        summary.prop_filters[0].text_match.as_mut().unwrap().negate = true;
        assert!(!calendar_matches(EVENT, &root(summary)));
    }

    #[test]
    fn recurring_series_with_until_is_bounded() {
        let recurring = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\n\
UID:r\r\nDTSTART:20261001T090000Z\r\nRRULE:FREQ=WEEKLY;UNTIL=20261005T000000Z\r\n\
END:VEVENT\r\nEND:VCALENDAR\r\n";
        let mut event = comp("VEVENT");
        event.time_range = Some(TimeRange {
            start: Some("20261012T000000Z".to_string()),
            end: Some("20261013T000000Z".to_string()),
        });
        assert!(!calendar_matches(recurring, &root(event)));

        let open = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\n\
UID:r\r\nDTSTART:20261001T090000Z\r\nRRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert!(calendar_matches(open, &root(comp("VEVENT"))));
    }

    #[test]
    fn parses_dates_and_durations() {
        let (stamp, is_date, _) = parse_dt("20261012").unwrap();
        assert!(stamp > 0 && is_date);
        assert!(parse_dt("20261012T090000Z").is_some());
        assert_eq!(parse_duration("PT1H30M"), Some(5400));
        assert_eq!(parse_duration("P2D"), Some(172_800));
        assert_eq!(parse_duration("P1W"), Some(604_800));
    }

    #[test]
    fn vcard_text_match() {
        let card = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:c1\r\nFN:Ada Lovelace\r\n\
EMAIL:ada@example.com\r\nEND:VCARD\r\n";
        let filter = Filter {
            prop_filters: vec![PropFilter {
                name: "FN".to_string(),
                text_match: Some(TextMatch {
                    value: "lovelace".to_string(),
                    negate: false,
                    collation: "i;ascii-casemap".to_string(),
                }),
                ..PropFilter::default()
            }],
            ..Filter::default()
        };
        assert!(addressbook_matches(card, &filter));
    }
}
