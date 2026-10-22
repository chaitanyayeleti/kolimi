//! Full-text search over Kolimi files (tantivy).
//!
//! One index holds every user's documents; queries are filtered by a
//! `user` term so results never cross accounts. The index is fed from the
//! change feed by a background indexer, which makes it crash-safe: a
//! restart replays from the last committed sequence.

use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;
use tantivy::collector::TopDocs;
use tantivy::query::{BooleanQuery, Occur, QueryParser, TermQuery};
use tantivy::schema::{
    Field, IndexRecordOption, STORED, STRING, Schema, TantivyDocument, TextFieldIndexing,
    TextOptions, Value,
};
use tantivy::{Index, IndexReader, IndexWriter, ReloadPolicy, Term};

/// Errors from the search layer.
#[derive(Debug, thiserror::Error)]
pub enum SearchError {
    /// tantivy failure.
    #[error("index error: {0}")]
    Index(#[from] tantivy::TantivyError),
    /// Query syntax error.
    #[error("invalid query: {0}")]
    Query(String),
    /// Lock poisoned (a previous index operation panicked).
    #[error("index lock poisoned")]
    Locked,
    /// IO failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// A document to index.
#[derive(Debug, Clone)]
pub struct SearchDoc {
    /// Owning user.
    pub user_id: i64,
    /// Path within the user's namespace.
    pub path: String,
    /// File or directory name.
    pub name: String,
    /// Whether the node is a directory.
    pub is_dir: bool,
    /// Extracted text (already truncated); `None` for name-only documents.
    pub content: Option<String>,
    /// Size in bytes.
    pub size: u64,
    /// Modification time in Unix milliseconds.
    pub modified_at: i64,
}

/// One search hit.
#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    /// Path within the user's namespace.
    pub path: String,
    /// File or directory name.
    pub name: String,
    /// Whether the node is a directory.
    pub is_dir: bool,
    /// Size in bytes.
    pub size: u64,
    /// Modification time in Unix milliseconds.
    pub modified_at: i64,
    /// Relevance score.
    pub score: f32,
    /// A short excerpt around the first query-term match.
    pub snippet: String,
}

/// How many bytes of a document's text are kept for snippets.
pub const SNIPPET_BYTES: usize = 4096;

struct Fields {
    id: Field,
    user: Field,
    path: Field,
    name: Field,
    content: Field,
    snippet: Field,
    is_dir: Field,
    size: Field,
    modified: Field,
}

/// The search index (thread-safe handle).
pub struct SearchIndex {
    index: Index,
    reader: IndexReader,
    writer: Mutex<IndexWriter>,
    fields: Fields,
}

impl std::fmt::Debug for SearchIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchIndex").finish_non_exhaustive()
    }
}

impl SearchIndex {
    /// Opens (or creates) the index at `dir`.
    pub fn open(dir: &Path) -> Result<Self, SearchError> {
        std::fs::create_dir_all(dir)?;
        let index = if dir.join("meta.json").exists() {
            Index::open_in_dir(dir)?
        } else {
            Index::create_in_dir(dir, schema())?
        };
        Self::from_index(index)
    }

    /// Creates an in-memory index (tests).
    pub fn in_memory() -> Result<Self, SearchError> {
        Self::from_index(Index::create_in_ram(schema()))
    }

    fn from_index(index: Index) -> Result<Self, SearchError> {
        let schema = index.schema();
        let field = |name: &str| {
            schema
                .get_field(name)
                .map_err(|_| SearchError::Query(format!("missing schema field {name}")))
        };
        let fields = Fields {
            id: field("id")?,
            user: field("user")?,
            path: field("path")?,
            name: field("name")?,
            content: field("content")?,
            snippet: field("snippet")?,
            is_dir: field("is_dir")?,
            size: field("size")?,
            modified: field("modified")?,
        };
        let writer = index.writer(30_000_000)?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()?;
        Ok(Self {
            index,
            reader,
            writer: Mutex::new(writer),
            fields,
        })
    }

    fn document_id(user_id: i64, path: &str) -> String {
        format!("{user_id}:{path}")
    }

    /// Adds or replaces a document.
    pub fn upsert(&self, doc: &SearchDoc) -> Result<(), SearchError> {
        let writer = self.writer.lock().map_err(|_| SearchError::Locked)?;
        writer.delete_term(Term::from_field_text(
            self.fields.id,
            &Self::document_id(doc.user_id, &doc.path),
        ));
        let mut document = TantivyDocument::new();
        document.add_text(self.fields.id, Self::document_id(doc.user_id, &doc.path));
        document.add_text(self.fields.user, doc.user_id.to_string());
        document.add_text(self.fields.path, &doc.path);
        document.add_text(self.fields.name, &doc.name);
        document.add_u64(self.fields.is_dir, u64::from(doc.is_dir));
        document.add_u64(self.fields.size, doc.size);
        document.add_i64(self.fields.modified, doc.modified_at);
        if let Some(content) = &doc.content {
            document.add_text(self.fields.content, content);
            let snippet: String = content.chars().take(SNIPPET_BYTES).collect();
            document.add_text(self.fields.snippet, snippet);
        }
        writer.add_document(document)?;
        Ok(())
    }

    /// Removes a document by path.
    pub fn remove(&self, user_id: i64, path: &str) -> Result<(), SearchError> {
        let writer = self.writer.lock().map_err(|_| SearchError::Locked)?;
        writer.delete_term(Term::from_field_text(
            self.fields.id,
            &Self::document_id(user_id, path),
        ));
        Ok(())
    }

    /// Removes every document owned by a user (account deletion).
    /// Call [`commit`](Self::commit) afterwards to make it visible.
    pub fn delete_user(&self, user_id: i64) -> Result<(), SearchError> {
        let writer = self.writer.lock().map_err(|_| SearchError::Locked)?;
        writer.delete_term(Term::from_field_text(
            self.fields.user,
            &user_id.to_string(),
        ));
        Ok(())
    }

    /// Commits pending changes and makes them visible to searches.
    pub fn commit(&self) -> Result<(), SearchError> {
        {
            let mut writer = self.writer.lock().map_err(|_| SearchError::Locked)?;
            writer.commit()?;
        }
        self.reader.reload()?;
        Ok(())
    }

    /// Searches a user's documents.
    pub fn search(
        &self,
        user_id: i64,
        query_text: &str,
        limit: usize,
    ) -> Result<Vec<SearchHit>, SearchError> {
        let query_text = query_text.trim();
        if query_text.is_empty() {
            return Ok(Vec::new());
        }
        let searcher = self.reader.searcher();
        let parser = QueryParser::for_index(
            &self.index,
            vec![self.fields.name, self.fields.path, self.fields.content],
        );
        let parsed = parser
            .parse_query(query_text)
            .map_err(|error| SearchError::Query(error.to_string()))?;
        let user_query = TermQuery::new(
            Term::from_field_text(self.fields.user, &user_id.to_string()),
            IndexRecordOption::Basic,
        );
        let query = BooleanQuery::new(vec![
            (
                Occur::Must,
                Box::new(user_query) as Box<dyn tantivy::query::Query>,
            ),
            (Occur::Must, parsed),
        ]);

        let top = searcher.search(&query, &TopDocs::with_limit(limit.max(1)).order_by_score())?;
        let terms = query_terms(query_text);
        let mut hits = Vec::with_capacity(top.len());
        for (score, address) in top {
            let document = searcher.doc::<TantivyDocument>(address)?;
            let text = |field: Field| {
                document
                    .get_first(field)
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_string()
            };
            let snippet_source = text(self.fields.snippet);
            hits.push(SearchHit {
                path: text(self.fields.path),
                name: text(self.fields.name),
                is_dir: document
                    .get_first(self.fields.is_dir)
                    .and_then(|value| value.as_u64())
                    .unwrap_or(0)
                    == 1,
                size: document
                    .get_first(self.fields.size)
                    .and_then(|value| value.as_u64())
                    .unwrap_or(0),
                modified_at: document
                    .get_first(self.fields.modified)
                    .and_then(|value| value.as_i64())
                    .unwrap_or(0),
                score,
                snippet: make_snippet(&snippet_source, &terms),
            });
        }
        Ok(hits)
    }
}

fn schema() -> Schema {
    let mut builder = Schema::builder();
    builder.add_text_field("id", STRING);
    builder.add_text_field("user", STRING);
    let text = TextOptions::default().set_indexing_options(
        TextFieldIndexing::default()
            .set_tokenizer("default")
            .set_index_option(IndexRecordOption::WithFreqsAndPositions),
    );
    builder.add_text_field("path", text.clone() | STORED);
    builder.add_text_field("name", text.clone() | STORED);
    builder.add_text_field("content", text);
    builder.add_text_field("snippet", STORED);
    builder.add_u64_field("is_dir", tantivy::schema::FAST | tantivy::schema::STORED);
    builder.add_u64_field("size", STORED);
    builder.add_i64_field("modified", STORED);
    builder.build()
}

/// Lowercased words of the query, for snippet highlighting.
fn query_terms(query: &str) -> Vec<String> {
    query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|term| term.len() >= 2)
        .map(str::to_lowercase)
        .collect()
}

/// A short excerpt around the first matching term (or the head).
fn make_snippet(text: &str, terms: &[String]) -> String {
    const RADIUS: usize = 80;
    let lower = text.to_lowercase();
    let position = terms
        .iter()
        .filter_map(|term| lower.find(term))
        .min()
        .unwrap_or(0);
    // `position` is a byte offset into `lower`, whose byte length can differ
    // from `text` (e.g. `İ`). Clamp and snap to char boundaries so slicing
    // can never panic on multi-byte UTF-8.
    let start = position.saturating_sub(RADIUS).min(text.len());
    let end = (position + RADIUS * 2).min(text.len());
    let start = text.floor_char_boundary(start);
    let end = text.ceil_char_boundary(end).min(text.len());
    let (start, end) = if start <= end {
        (start, end)
    } else {
        (end, end)
    };
    let mut snippet: String = text.get(start..end).unwrap_or("").chars().collect();
    if snippet.len() < text.len() {
        if start > 0 {
            snippet.insert(0, '…');
        }
        snippet.push('…');
    }
    snippet.replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(user: i64, path: &str, content: Option<&str>) -> SearchDoc {
        SearchDoc {
            user_id: user,
            path: path.to_string(),
            name: path.rsplit('/').next().unwrap_or(path).to_string(),
            is_dir: false,
            content: content.map(str::to_string),
            size: content.map(|c| c.len() as u64).unwrap_or(0),
            modified_at: 1,
        }
    }

    #[test]
    fn indexes_searches_and_isolates_users() {
        let index = SearchIndex::in_memory().unwrap();
        index
            .upsert(&doc(
                1,
                "/notes/roadmap.md",
                Some("tantivy full text search"),
            ))
            .unwrap();
        index
            .upsert(&doc(1, "/notes/other.txt", Some("unrelated words")))
            .unwrap();
        index
            .upsert(&doc(
                2,
                "/notes/roadmap.md",
                Some("tantivy full text search"),
            ))
            .unwrap();
        index.commit().unwrap();

        let hits = index.search(1, "tantivy", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "/notes/roadmap.md");
        assert!(hits[0].snippet.contains("tantivy"));

        // User 2's identical document stays invisible to user 1.
        let hits = index.search(2, "tantivy", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(index.search(3, "tantivy", 10).unwrap().is_empty());
    }

    #[test]
    fn names_are_searchable_without_content() {
        let index = SearchIndex::in_memory().unwrap();
        index
            .upsert(&doc(1, "/invoices/2026-q1.pdf", None))
            .unwrap();
        index.commit().unwrap();
        let hits = index.search(1, "invoices", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "2026-q1.pdf");
    }

    #[test]
    fn upserts_replace_and_deletes_remove() {
        let index = SearchIndex::in_memory().unwrap();
        index.upsert(&doc(1, "/a.txt", Some("alpha"))).unwrap();
        index.commit().unwrap();
        index.upsert(&doc(1, "/a.txt", Some("beta"))).unwrap();
        index.commit().unwrap();
        assert!(index.search(1, "alpha", 10).unwrap().is_empty());
        assert_eq!(index.search(1, "beta", 10).unwrap().len(), 1);

        index.remove(1, "/a.txt").unwrap();
        index.commit().unwrap();
        assert!(index.search(1, "beta", 10).unwrap().is_empty());
    }

    #[test]
    fn query_syntax_errors_are_reported() {
        let index = SearchIndex::in_memory().unwrap();
        index.commit().unwrap();
        assert!(matches!(
            index.search(1, "AND OR", 10),
            Err(SearchError::Query(_))
        ));
        assert!(index.search(1, "   ", 10).unwrap().is_empty());
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let index = SearchIndex::open(dir.path()).unwrap();
            index
                .upsert(&doc(1, "/kept.txt", Some("persistent")))
                .unwrap();
            index.commit().unwrap();
        }
        let index = SearchIndex::open(dir.path()).unwrap();
        assert_eq!(index.search(1, "persistent", 10).unwrap().len(), 1);
    }
}
