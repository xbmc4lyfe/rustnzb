//! Database operations for newsgroup browsing.

use std::collections::HashMap;

use rusqlite::params;

use crate::db::Database;
use crate::error::NzbError;
use crate::models::{GroupRow, HeaderRow, ThreadArticle, ThreadSummary};

impl Database {
    // ---- Groups ----

    pub fn group_upsert_batch(&self, groups: &[(String, u64, u64)]) -> Result<u64, NzbError> {
        let tx = self.conn.unchecked_transaction()?;
        let mut count = 0u64;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO groups (name, article_count, first_article, last_article)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(name) DO UPDATE SET
                    article_count = excluded.article_count,
                    first_article = excluded.first_article,
                    last_article = excluded.last_article,
                    last_updated = datetime('now')",
            )?;
            for (name, high, low) in groups {
                let article_count = high.saturating_sub(*low) as i64;
                stmt.execute(params![name, article_count, *low as i64, *high as i64])?;
                count += 1;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    pub fn group_list(
        &self,
        subscribed_only: bool,
        search: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<GroupRow>, NzbError> {
        let mut sql = String::from(
            "SELECT g.id, g.name, g.description, g.subscribed, g.article_count,
             g.first_article, g.last_article, g.last_scanned, g.last_updated, g.created_at,
             (SELECT COUNT(*) FROM headers h WHERE h.group_id = g.id AND h.read = 0) as unread_count
             FROM groups g WHERE 1=1",
        );
        if subscribed_only {
            sql.push_str(" AND g.subscribed = 1");
        }
        if let Some(s) = search {
            sql.push_str(&format!(" AND g.name LIKE '%{}%'", s.replace('\'', "''")));
        }
        sql.push_str(&format!(" ORDER BY g.name LIMIT {limit} OFFSET {offset}"));

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt
            .query_map([], |row| {
                Ok(GroupRow {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    subscribed: row.get::<_, i32>(3)? != 0,
                    article_count: row.get(4)?,
                    first_article: row.get(5)?,
                    last_article: row.get(6)?,
                    last_scanned: row.get(7)?,
                    last_updated: row.get(8)?,
                    created_at: row.get::<_, Option<String>>(9)?.unwrap_or_default(),
                    unread_count: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn group_get(&self, id: i64) -> Result<Option<GroupRow>, NzbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, description, subscribed, article_count,
             first_article, last_article, last_scanned, last_updated, created_at,
             (SELECT COUNT(*) FROM headers h WHERE h.group_id = groups.id AND h.read = 0)
             FROM groups WHERE id = ?1",
        )?;
        let result = stmt.query_row(params![id], |row| {
            Ok(GroupRow {
                id: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                subscribed: row.get::<_, i32>(3)? != 0,
                article_count: row.get(4)?,
                first_article: row.get(5)?,
                last_article: row.get(6)?,
                last_scanned: row.get(7)?,
                last_updated: row.get(8)?,
                created_at: row.get::<_, Option<String>>(9)?.unwrap_or_default(),
                unread_count: row.get(10)?,
            })
        });
        match result {
            Ok(g) => Ok(Some(g)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(NzbError::Database(e)),
        }
    }

    pub fn group_count(
        &self,
        subscribed_only: bool,
        search: Option<&str>,
    ) -> Result<i64, NzbError> {
        let mut sql = String::from("SELECT COUNT(*) FROM groups WHERE 1=1");
        if subscribed_only {
            sql.push_str(" AND subscribed = 1");
        }
        if let Some(s) = search {
            sql.push_str(&format!(" AND name LIKE '%{}%'", s.replace('\'', "''")));
        }
        let count: i64 = self.conn.query_row(&sql, [], |row| row.get(0))?;
        Ok(count)
    }

    pub fn group_set_subscribed(&self, id: i64, subscribed: bool) -> Result<(), NzbError> {
        self.conn.execute(
            "UPDATE groups SET subscribed = ?2 WHERE id = ?1",
            params![id, subscribed as i32],
        )?;
        Ok(())
    }

    /// Record how far a group has been scanned, and on which server.
    ///
    /// Article numbers are per-server, so the watermark is only meaningful
    /// together with the server it was measured on; see
    /// [`Database::group_scan_server`].
    pub fn group_update_watermark(
        &self,
        id: i64,
        last_scanned: i64,
        server_id: &str,
    ) -> Result<(), NzbError> {
        self.conn.execute(
            "UPDATE groups SET last_scanned = ?2, scan_server_id = ?3, last_updated = datetime('now')
             WHERE id = ?1",
            params![id, last_scanned, server_id],
        )?;
        Ok(())
    }

    /// The server the group's `last_scanned` watermark belongs to, if any.
    pub fn group_scan_server(&self, id: i64) -> Result<Option<String>, NzbError> {
        let server = self
            .conn
            .query_row(
                "SELECT scan_server_id FROM groups WHERE id = ?1",
                params![id],
                |row| row.get::<_, Option<String>>(0),
            )
            .map_err(NzbError::Database);
        match server {
            Ok(server) => Ok(server),
            Err(NzbError::Database(rusqlite::Error::QueryReturnedNoRows)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    // ---- Headers ----

    pub fn header_insert_batch(
        &self,
        group_id: i64,
        entries: &[nzb_nntp::XoverEntry],
    ) -> Result<u64, NzbError> {
        let tx = self.conn.unchecked_transaction()?;
        let mut count = 0u64;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR IGNORE INTO headers (group_id, article_num, subject, author, date, message_id, references_, bytes, lines)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for e in entries {
                // `OR IGNORE` against the unique (group_id, message_id) index:
                // headers already stored are skipped, not duplicated.
                count += stmt.execute(params![
                    group_id,
                    e.article_num as i64,
                    e.subject,
                    e.from,
                    e.date,
                    e.message_id,
                    e.references,
                    e.bytes as i64,
                    e.lines as i64,
                ])? as u64;
            }
        }
        tx.commit()?;
        Ok(count)
    }

    /// Delete all but the `keep` newest headers (by article number) of a
    /// group. `keep == 0` means unlimited. Returns the number deleted.
    pub fn header_prune_group(&self, group_id: i64, keep: usize) -> Result<u64, NzbError> {
        if keep == 0 {
            return Ok(0);
        }
        let keep = i64::try_from(keep).unwrap_or(i64::MAX);
        let deleted = self.conn.execute(
            "DELETE FROM headers WHERE id IN (
                SELECT id FROM headers WHERE group_id = ?1
                 ORDER BY article_num DESC, id DESC
                 LIMIT -1 OFFSET ?2)",
            params![group_id, keep],
        )?;
        Ok(deleted as u64)
    }

    /// Delete every stored header of a group and reset its scan watermark, so
    /// the next fetch starts from scratch. Returns the number deleted.
    pub fn header_clear_group(&self, group_id: i64) -> Result<u64, NzbError> {
        let tx = self.conn.unchecked_transaction()?;
        let deleted = tx.execute("DELETE FROM headers WHERE group_id = ?1", params![group_id])?;
        tx.execute(
            "UPDATE groups SET last_scanned = 0, scan_server_id = NULL WHERE id = ?1",
            params![group_id],
        )?;
        tx.commit()?;
        Ok(deleted as u64)
    }

    pub fn header_list(
        &self,
        group_id: i64,
        search: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<HeaderRow>, NzbError> {
        let (sql, use_fts) = if let Some(s) = search {
            let safe = s.replace(['"', '\''], "").trim().to_string();
            if safe.is_empty() {
                (format!(
                    "SELECT id, group_id, article_num, subject, author, date, message_id, references_, bytes, lines, read, downloaded_at
                     FROM headers WHERE group_id = ?1 ORDER BY article_num DESC LIMIT {limit} OFFSET {offset}"
                ), false)
            } else {
                (format!(
                    "SELECT h.id, h.group_id, h.article_num, h.subject, h.author, h.date, h.message_id, h.references_, h.bytes, h.lines, h.read, h.downloaded_at
                     FROM headers h INNER JOIN headers_fts f ON h.id = f.rowid
                     WHERE h.group_id = ?1 AND headers_fts MATCH '\"{safe}\"'
                     ORDER BY rank LIMIT {limit} OFFSET {offset}"
                ), true)
            }
        } else {
            (format!(
                "SELECT id, group_id, article_num, subject, author, date, message_id, references_, bytes, lines, read, downloaded_at
                 FROM headers WHERE group_id = ?1 ORDER BY article_num DESC LIMIT {limit} OFFSET {offset}"
            ), false)
        };

        let map_row = |row: &rusqlite::Row| -> rusqlite::Result<HeaderRow> {
            Ok(HeaderRow {
                id: row.get(0)?,
                group_id: row.get(1)?,
                article_num: row.get(2)?,
                subject: row.get(3)?,
                author: row.get(4)?,
                date: row.get(5)?,
                message_id: row.get(6)?,
                references_: row.get(7)?,
                bytes: row.get(8)?,
                lines: row.get(9)?,
                read: row.get::<_, i32>(10)? != 0,
                downloaded_at: row.get::<_, Option<String>>(11)?.unwrap_or_default(),
            })
        };

        let result = self
            .conn
            .prepare(&sql)
            .and_then(|mut stmt| stmt.query_map(params![group_id], map_row)?.collect());

        match result {
            Ok(rows) => Ok(rows),
            Err(_) if use_fts => {
                let s = search.unwrap_or("");
                let fallback = format!(
                    "SELECT id, group_id, article_num, subject, author, date, message_id, references_, bytes, lines, read, downloaded_at
                     FROM headers WHERE group_id = ?1 AND (subject LIKE '%{0}%' OR author LIKE '%{0}%')
                     ORDER BY article_num DESC LIMIT {1} OFFSET {2}",
                    s.replace('\'', "''"),
                    limit,
                    offset
                );
                let mut stmt = self.conn.prepare(&fallback)?;
                let rows = stmt
                    .query_map(params![group_id], map_row)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            }
            Err(e) => Err(NzbError::Database(e)),
        }
    }

    pub fn header_count(&self, group_id: i64, search: Option<&str>) -> Result<i64, NzbError> {
        let sql = if let Some(s) = search {
            let safe = s.replace(['"', '\''], "").trim().to_string();
            if safe.is_empty() {
                "SELECT COUNT(*) FROM headers WHERE group_id = ?1".to_string()
            } else {
                format!(
                    "SELECT COUNT(*) FROM headers h INNER JOIN headers_fts f ON h.id = f.rowid
                     WHERE h.group_id = ?1 AND headers_fts MATCH '\"{safe}\"'"
                )
            }
        } else {
            "SELECT COUNT(*) FROM headers WHERE group_id = ?1".to_string()
        };

        let count: i64 = self
            .conn
            .query_row(&sql, params![group_id], |row| row.get(0))
            .unwrap_or(0);
        Ok(count)
    }

    pub fn header_get_by_message_id(
        &self,
        message_id: &str,
    ) -> Result<Option<HeaderRow>, NzbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, group_id, article_num, subject, author, date, message_id, references_, bytes, lines, read, downloaded_at
             FROM headers WHERE message_id = ?1 LIMIT 1",
        )?;
        let result = stmt.query_row(params![message_id], |row| {
            Ok(HeaderRow {
                id: row.get(0)?,
                group_id: row.get(1)?,
                article_num: row.get(2)?,
                subject: row.get(3)?,
                author: row.get(4)?,
                date: row.get(5)?,
                message_id: row.get(6)?,
                references_: row.get(7)?,
                bytes: row.get(8)?,
                lines: row.get(9)?,
                read: row.get::<_, i32>(10)? != 0,
                downloaded_at: row.get::<_, Option<String>>(11)?.unwrap_or_default(),
            })
        });
        match result {
            Ok(h) => Ok(Some(h)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(NzbError::Database(e)),
        }
    }

    pub fn header_mark_read(&self, header_id: i64) -> Result<(), NzbError> {
        self.conn.execute(
            "UPDATE headers SET read = 1 WHERE id = ?1",
            params![header_id],
        )?;
        Ok(())
    }

    pub fn header_mark_all_read(&self, group_id: i64) -> Result<u64, NzbError> {
        let changes = self.conn.execute(
            "UPDATE headers SET read = 1 WHERE group_id = ?1 AND read = 0",
            params![group_id],
        )?;
        Ok(changes as u64)
    }

    pub fn header_unread_count(&self, group_id: i64) -> Result<i64, NzbError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM headers WHERE group_id = ?1 AND read = 0",
            params![group_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    // ---- Threading ----

    pub fn header_list_threads(
        &self,
        group_id: i64,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<ThreadSummary>, i64), NzbError> {
        let all = self.header_list(group_id, None, 100_000, 0)?;

        let mut msg_to_root: HashMap<String, String> = HashMap::new();
        let mut root_threads: HashMap<String, Vec<&HeaderRow>> = HashMap::new();

        for h in &all {
            let root_id = if h.references_.is_empty() {
                h.message_id.clone()
            } else {
                let first_ref = h
                    .references_
                    .split_whitespace()
                    .next()
                    .unwrap_or(&h.message_id);
                msg_to_root
                    .get(first_ref)
                    .cloned()
                    .unwrap_or_else(|| first_ref.to_string())
            };
            msg_to_root.insert(h.message_id.clone(), root_id.clone());
            root_threads.entry(root_id).or_default().push(h);
        }

        let mut summaries: Vec<ThreadSummary> = root_threads
            .iter()
            .map(|(root_id, articles)| {
                let root = articles
                    .iter()
                    .find(|a| a.message_id == *root_id)
                    .unwrap_or(&articles[0]);
                let last = articles.iter().max_by_key(|a| &a.date).unwrap_or(root);
                let mut subject = root.subject.as_str();
                while let Some(rest) = subject
                    .strip_prefix("Re: ")
                    .or_else(|| subject.strip_prefix("RE: "))
                {
                    subject = rest;
                }
                ThreadSummary {
                    root_message_id: root_id.clone(),
                    subject: subject.to_string(),
                    author: root.author.clone(),
                    date: root.date.clone(),
                    last_reply_date: last.date.clone(),
                    reply_count: (articles.len() as i64) - 1,
                    unread_count: articles.iter().filter(|a| !a.read).count() as i64,
                }
            })
            .collect();

        summaries.sort_by(|a, b| b.last_reply_date.cmp(&a.last_reply_date));
        let total = summaries.len() as i64;
        let page: Vec<ThreadSummary> = summaries.into_iter().skip(offset).take(limit).collect();
        Ok((page, total))
    }

    pub fn header_get_thread(
        &self,
        group_id: i64,
        root_message_id: &str,
    ) -> Result<Vec<ThreadArticle>, NzbError> {
        let all = self.header_list(group_id, None, 100_000, 0)?;

        let mut msg_to_root: HashMap<String, String> = HashMap::new();
        for h in &all {
            let root_id = if h.references_.is_empty() {
                h.message_id.clone()
            } else {
                let first_ref = h
                    .references_
                    .split_whitespace()
                    .next()
                    .unwrap_or(&h.message_id);
                msg_to_root
                    .get(first_ref)
                    .cloned()
                    .unwrap_or_else(|| first_ref.to_string())
            };
            msg_to_root.insert(h.message_id.clone(), root_id);
        }

        let result: Vec<ThreadArticle> = all
            .into_iter()
            .filter(|h| {
                msg_to_root
                    .get(&h.message_id)
                    .is_some_and(|r| r == root_message_id)
            })
            .map(|h| {
                let depth = if h.references_.is_empty() {
                    0
                } else {
                    h.references_.split_whitespace().count() as i32
                };
                ThreadArticle { header: h, depth }
            })
            .collect();

        Ok(result)
    }
}

#[cfg(all(test, feature = "groups-db"))]
mod tests {
    use super::*;
    use nzb_nntp::XoverEntry;

    #[test]
    fn groups_headers_and_threads_persist_with_read_state() {
        let db = Database::open_memory().unwrap();
        db.group_upsert_batch(&[("alt.binaries.test".into(), 30, 10)])
            .unwrap();
        let group = db.group_list(false, None, 10, 0).unwrap().pop().unwrap();
        db.group_set_subscribed(group.id, true).unwrap();
        db.header_insert_batch(
            group.id,
            &[
                XoverEntry {
                    article_num: 10,
                    subject: "Release".into(),
                    from: "poster".into(),
                    date: "2026-01-01".into(),
                    message_id: "root@test".into(),
                    references: "".into(),
                    bytes: 42,
                    lines: 1,
                },
                XoverEntry {
                    article_num: 11,
                    subject: "Re: Release".into(),
                    from: "reply".into(),
                    date: "2026-01-02".into(),
                    message_id: "reply@test".into(),
                    references: "root@test".into(),
                    bytes: 84,
                    lines: 2,
                },
            ],
        )
        .unwrap();

        assert_eq!(db.header_unread_count(group.id).unwrap(), 2);
        let headers = db.header_list(group.id, Some("Release"), 10, 0).unwrap();
        assert_eq!(headers.len(), 2);
        db.header_mark_read(headers[0].id).unwrap();
        assert_eq!(db.header_unread_count(group.id).unwrap(), 1);
        let (threads, total) = db.header_list_threads(group.id, 10, 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(threads[0].root_message_id, "root@test");
        assert_eq!(threads[0].reply_count, 1);
        assert_eq!(threads[0].unread_count, 1);
        assert_eq!(db.group_get(group.id).unwrap().unwrap().unread_count, 1);
    }

    fn entry(article_num: u64, message_id: &str) -> XoverEntry {
        XoverEntry {
            article_num,
            subject: format!("Subject {article_num}"),
            from: "poster".into(),
            date: "2026-01-01".into(),
            message_id: message_id.into(),
            references: "".into(),
            bytes: 1,
            lines: 1,
        }
    }

    fn seeded_group(db: &Database) -> i64 {
        db.group_upsert_batch(&[("alt.binaries.test".into(), 30, 10)])
            .unwrap();
        db.group_list(false, None, 10, 0).unwrap().pop().unwrap().id
    }

    /// BUG-105: two overlapping fetches of one group (or a re-fetch) must not
    /// store every header twice — that doubled thread, unread and FTS counts.
    #[test]
    fn inserting_the_same_headers_twice_does_not_duplicate_them() {
        let db = Database::open_memory().unwrap();
        let group_id = seeded_group(&db);
        let batch = [entry(10, "<a@test>"), entry(11, "<b@test>")];

        assert_eq!(db.header_insert_batch(group_id, &batch).unwrap(), 2);
        assert_eq!(
            db.header_insert_batch(group_id, &batch).unwrap(),
            0,
            "re-inserting existing headers reports nothing stored"
        );

        assert_eq!(db.header_count(group_id, None).unwrap(), 2);
        assert_eq!(db.header_unread_count(group_id).unwrap(), 2);
        assert_eq!(db.header_count(group_id, Some("Subject")).unwrap(), 2);
        let (_, threads) = db.header_list_threads(group_id, 10, 0).unwrap();
        assert_eq!(threads, 2);
    }

    /// BUG-105: databases that already hold duplicate headers are de-duplicated
    /// by the migration that adds the unique index, keeping read state.
    #[test]
    fn migration_removes_existing_duplicate_headers_and_keeps_read_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("queue.db");
        let group_id = {
            let db = Database::open(&path).unwrap();
            seeded_group(&db)
        };

        // Recreate the pre-fix state: no unique index, duplicated rows (one
        // copy read), schema version before the de-duplicating migration.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("DROP INDEX IF EXISTS idx_headers_group_msgid;")
            .unwrap();
        for read in [0, 1, 0] {
            conn.execute(
                "INSERT INTO headers (group_id, article_num, subject, author, date, message_id, read)
                 VALUES (?1, 10, 'Dup', 'poster', '2026-01-01', '<dup@test>', ?2)",
                params![group_id, read],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO headers (group_id, article_num, subject, author, date, message_id)
             VALUES (?1, 11, 'Single', 'poster', '2026-01-01', '<single@test>')",
            params![group_id],
        )
        .unwrap();
        conn.execute_batch(
            "DELETE FROM schema_version; INSERT INTO schema_version (version) VALUES (13);",
        )
        .unwrap();
        drop(conn);

        let db = Database::open(&path).unwrap();
        assert_eq!(db.header_count(group_id, None).unwrap(), 2);
        assert_eq!(
            db.header_count(group_id, Some("Dup")).unwrap(),
            1,
            "FTS rows of removed duplicates are removed too"
        );
        assert_eq!(db.header_unread_count(group_id).unwrap(), 1);
        let dup = db.header_get_by_message_id("<dup@test>").unwrap().unwrap();
        assert!(
            dup.read,
            "a duplicate that was read keeps the survivor read"
        );
        assert_eq!(
            db.header_insert_batch(group_id, &[entry(10, "<dup@test>")])
                .unwrap(),
            0,
            "the unique index now rejects the duplicate"
        );
    }

    /// BUG-105: headers are pruned to the configured per-group maximum, oldest
    /// article numbers first.
    #[test]
    fn prune_keeps_only_the_newest_headers_of_a_group() {
        let db = Database::open_memory().unwrap();
        let group_id = seeded_group(&db);
        let batch: Vec<_> = (1..=5).map(|n| entry(n, &format!("<{n}@test>"))).collect();
        db.header_insert_batch(group_id, &batch).unwrap();

        assert_eq!(
            db.header_prune_group(group_id, 0).unwrap(),
            0,
            "0 = keep all"
        );
        assert_eq!(db.header_prune_group(group_id, 3).unwrap(), 2);
        let kept: Vec<i64> = db
            .header_list(group_id, None, 10, 0)
            .unwrap()
            .into_iter()
            .map(|h| h.article_num)
            .collect();
        assert_eq!(kept, vec![5, 4, 3]);
        assert_eq!(db.header_count(group_id, Some("Subject")).unwrap(), 3);
    }

    /// BUG-105: clearing a group's headers deletes them and resets the scan
    /// watermark so the next fetch starts over.
    #[test]
    fn clearing_a_group_deletes_headers_and_resets_the_watermark() {
        let db = Database::open_memory().unwrap();
        let group_id = seeded_group(&db);
        db.header_insert_batch(group_id, &[entry(10, "<a@test>")])
            .unwrap();
        db.group_update_watermark(group_id, 10, "server-a").unwrap();

        assert_eq!(db.header_clear_group(group_id).unwrap(), 1);
        assert_eq!(db.header_count(group_id, None).unwrap(), 0);
        let group = db.group_get(group_id).unwrap().unwrap();
        assert_eq!(group.last_scanned, 0);
        assert_eq!(db.group_scan_server(group_id).unwrap(), None);
    }

    /// BUG-107: the watermark records which server it was measured against.
    #[test]
    fn watermark_remembers_the_server_it_belongs_to() {
        let db = Database::open_memory().unwrap();
        let group_id = seeded_group(&db);
        assert_eq!(db.group_scan_server(group_id).unwrap(), None);
        db.group_update_watermark(group_id, 42, "server-a").unwrap();
        assert_eq!(
            db.group_scan_server(group_id).unwrap().as_deref(),
            Some("server-a")
        );
        assert_eq!(db.group_get(group_id).unwrap().unwrap().last_scanned, 42);
    }
}
