//! Parsing of CalDAV/CardDAV query filters (RFC 4791 §9.7, RFC 6352 §10.5).
//!
//! The filter tree is parsed separately from the REPORT envelope so the
//! evaluator can stay independent of the XML shape.

use quick_xml::{Reader, events::Event};

/// A `<C:filter>` element.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Filter {
    /// `test="anyof"`; the default is all filters matching.
    pub any: bool,
    pub comp_filters: Vec<CompFilter>,
    pub prop_filters: Vec<PropFilter>,
}

/// A `<C:comp-filter>` element.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompFilter {
    pub name: String,
    pub time_range: Option<TimeRange>,
    pub prop_filters: Vec<PropFilter>,
    pub comp_filters: Vec<CompFilter>,
    pub is_not_defined: bool,
}

/// A `<C:prop-filter>` element.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PropFilter {
    pub name: String,
    pub is_not_defined: bool,
    pub text_match: Option<TextMatch>,
    pub time_range: Option<TimeRange>,
}

/// A `<C:text-match>` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextMatch {
    pub value: String,
    pub negate: bool,
    pub collation: String,
}

/// A `<C:time-range>` element; values are parsed by the evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TimeRange {
    pub start: Option<String>,
    pub end: Option<String>,
}

enum Node {
    Filter(Filter),
    Comp(CompFilter),
    Prop(PropFilter),
}

fn local(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_string()
}

fn attr(event: &quick_xml::events::BytesStart<'_>, wanted: &str) -> Option<String> {
    for attribute in event.attributes().flatten() {
        let key = attribute.key.as_ref();
        let key = key.rsplit(':').next().unwrap_or(key);
        if key.eq_ignore_ascii_case(wanted) {
            return Some(attribute.value.as_ref().to_string());
        }
    }
    None
}

/// Parses the first `<filter>` element, if any. Returns `None` when the
/// request carries no filter (the caller returns the whole collection).
pub fn parse_filter(body: &[u8]) -> Option<Filter> {
    let mut reader = Reader::from_reader(body);
    reader.config_mut().trim_text(false);
    let mut stack: Vec<Node> = Vec::new();
    let mut capturing_text = false;
    let mut text = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                let name = local(event.name().as_ref());
                match name.as_str() {
                    "filter" => stack.push(Node::Filter(Filter {
                        any: attr(&event, "test")
                            .is_some_and(|test| test.eq_ignore_ascii_case("anyof")),
                        ..Filter::default()
                    })),
                    "comp-filter" => stack.push(Node::Comp(CompFilter {
                        name: attr(&event, "name")
                            .unwrap_or_default()
                            .to_ascii_uppercase(),
                        ..CompFilter::default()
                    })),
                    "prop-filter" => stack.push(Node::Prop(PropFilter {
                        name: attr(&event, "name")
                            .unwrap_or_default()
                            .to_ascii_uppercase(),
                        ..PropFilter::default()
                    })),
                    "time-range" => {
                        let range = TimeRange {
                            start: attr(&event, "start"),
                            end: attr(&event, "end"),
                        };
                        if let Some(top) = stack.last_mut() {
                            match top {
                                Node::Comp(comp) => comp.time_range = Some(range),
                                Node::Prop(prop) => prop.time_range = Some(range),
                                Node::Filter(_) => {}
                            }
                        }
                    }
                    "is-not-defined" => {
                        if let Some(top) = stack.last_mut() {
                            match top {
                                Node::Comp(comp) => comp.is_not_defined = true,
                                Node::Prop(prop) => prop.is_not_defined = true,
                                Node::Filter(_) => {}
                            }
                        }
                    }
                    "text-match" => {
                        if let Some(Node::Prop(prop)) = stack.last_mut() {
                            prop.text_match = Some(TextMatch {
                                value: String::new(),
                                negate: attr(&event, "negate-condition")
                                    .is_some_and(|v| v.eq_ignore_ascii_case("yes")),
                                collation: attr(&event, "collation")
                                    .unwrap_or_else(|| "i;ascii-casemap".to_string()),
                            });
                            capturing_text = true;
                            text.clear();
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(event)) => {
                // Self-closing elements: apply without pushing.
                let name = local(event.name().as_ref());
                match name.as_str() {
                    "time-range" => {
                        let range = TimeRange {
                            start: attr(&event, "start"),
                            end: attr(&event, "end"),
                        };
                        if let Some(top) = stack.last_mut() {
                            match top {
                                Node::Comp(comp) => comp.time_range = Some(range),
                                Node::Prop(prop) => prop.time_range = Some(range),
                                Node::Filter(_) => {}
                            }
                        }
                    }
                    "is-not-defined" => {
                        if let Some(top) = stack.last_mut() {
                            match top {
                                Node::Comp(comp) => comp.is_not_defined = true,
                                Node::Prop(prop) => prop.is_not_defined = true,
                                Node::Filter(_) => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(event)) => {
                if capturing_text {
                    let raw = event.into_inner();
                    if let Ok(unescaped) = quick_xml::escape::unescape(raw.as_ref()) {
                        text.push_str(&unescaped);
                    }
                }
            }
            Ok(Event::End(event)) => {
                let name = local(event.name().as_ref());
                if name == "text-match" {
                    capturing_text = false;
                    if let Some(Node::Prop(prop)) = stack.last_mut()
                        && let Some(match_) = &mut prop.text_match
                    {
                        match_.value = std::mem::take(&mut text);
                    }
                    continue;
                }
                if matches!(name.as_str(), "filter" | "comp-filter" | "prop-filter") {
                    let node = stack.pop()?;
                    let attached = match node {
                        Node::Filter(filter) => {
                            if stack.is_empty() {
                                return Some(filter);
                            }
                            Node::Filter(filter)
                        }
                        Node::Comp(comp) => Node::Comp(comp),
                        Node::Prop(prop) => Node::Prop(prop),
                    };
                    if let Some(parent) = stack.last_mut() {
                        match (parent, attached) {
                            (Node::Filter(filter), Node::Comp(comp)) => {
                                filter.comp_filters.push(comp)
                            }
                            (Node::Filter(filter), Node::Prop(prop)) => {
                                filter.prop_filters.push(prop)
                            }
                            (Node::Comp(filter), Node::Comp(comp)) => {
                                filter.comp_filters.push(comp)
                            }
                            (Node::Comp(filter), Node::Prop(prop)) => {
                                filter.prop_filters.push(prop)
                            }
                            _ => {}
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
    }
    None
}
