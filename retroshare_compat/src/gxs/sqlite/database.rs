use std::path::PathBuf;

use log::{debug, trace, warn};
use rusqlite::{params, Connection, Result};

use crate::{
    basics::{GxsGroupId, GxsMessageId},
    gxs::sqlite::{
        types::{GxsDatabaseRelease, GxsGrpDataSql, GxsGrpMetaSql, GxsMsgMetaSql},
        FromSqlRs,
    },
};

use super::types::{GxsGroup, GxsMsgDataSql};

const TABLE_RELEASE: &str = "DATABASE_RELEASE";
const TABLE_GROUPS: &str = "GROUPS";
const TABLE_MESSAGES: &str = "MESSAGES";

// generic
pub(super) const KEY_NXS_DATA: &str = "nxsData";
pub(super) const KEY_NXS_DATA_LEN: &str = "nxsDataLen";
pub(super) const KEY_NXS_IDENTITY: &str = "identity";
pub(super) const KEY_GRP_ID: &str = "grpId";
pub(super) const KEY_ORIG_GRP_ID: &str = "origGrpId";
pub(super) const KEY_PARENT_GRP_ID: &str = "parentGrpId";
pub(super) const KEY_SIGN_SET: &str = "signSet";
pub(super) const KEY_TIME_STAMP: &str = "timeStamp";
pub(super) const KEY_NXS_FLAGS: &str = "flags";
pub(super) const KEY_NXS_META: &str = "meta";
pub(super) const KEY_NXS_SERV_STRING: &str = "serv_str";
pub(super) const KEY_NXS_HASH: &str = "hash";
pub(super) const KEY_RECV_TS: &str = "recv_time_stamp";

// These are legacy fields, that are not used anymore.
// Here for the sake of documentation.
#[allow(dead_code)]
const KEY_NXS_FILE_OLD: &str = "nxsFile";
#[allow(dead_code)]
const KEY_NXS_FILE_OFFSET_OLD: &str = "fileOffset";
#[allow(dead_code)]
const KEY_NXS_FILE_LEN_OLD: &str = "nxsFileLen";

// grp table columns
pub(super) const KEY_KEY_SET: &str = "keySet";
pub(super) const KEY_GRP_NAME: &str = "grpName";
pub(super) const KEY_GRP_SIGN_FLAGS: &str = "signFlags";
pub(super) const KEY_GRP_CIRCLE_ID: &str = "circleId";
pub(super) const KEY_GRP_CIRCLE_TYPE: &str = "circleType";
pub(super) const KEY_GRP_INTERNAL_CIRCLE: &str = "internalCircle";
pub(super) const KEY_GRP_ORIGINATOR: &str = "originator";
pub(super) const KEY_GRP_AUTHEN_FLAGS: &str = "authenFlags";

// grp local
pub(super) const KEY_GRP_SUBCR_FLAG: &str = "subscribeFlag";
pub(super) const KEY_GRP_POP: &str = "popularity";
pub(super) const KEY_MSG_COUNT: &str = "msgCount";
pub(super) const KEY_GRP_STATUS: &str = "grpStatus";
pub(super) const KEY_GRP_LAST_POST: &str = "lastPost";
pub(super) const KEY_GRP_REP_CUTOFF: &str = "rep_cutoff";

// msg table columns
pub(super) const KEY_MSG_ID: &str = "msgId";
pub(super) const KEY_ORIG_MSG_ID: &str = "origMsgId";
pub(super) const KEY_MSG_PARENT_ID: &str = "parentId";
pub(super) const KEY_MSG_THREAD_ID: &str = "threadId";
pub(super) const KEY_MSG_NAME: &str = "msgName";

// msg local
pub(super) const KEY_MSG_STATUS: &str = "msgStatus";
pub(super) const KEY_CHILD_TS: &str = "childTs";

// database release columns
pub(super) const KEY_DATABASE_RELEASE_ID: &str = "id";
pub(super) const KEY_DATABASE_RELEASE: &str = "release";

const RELEASE_ID_VALUE: u32 = 1;
const RELEASE_VERSION: u32 = 1;

#[derive(Debug)]
pub struct GxsDatabase {
    db: Connection,
}

impl GxsDatabase {
    pub fn new_file(path: PathBuf, passwd: &str) -> Result<Self> {
        let new = !path.exists();

        let db = Connection::open(path)?;
        if !passwd.is_empty() {
            db.pragma_update(None, "key", passwd)?;
        }

        let db = GxsDatabase { db };
        if new {
            db.create_tables()?;
        } else {
            db.verify_version()?;
        }

        Ok(db)
    }

    pub fn new_mem(passwd: &str) -> Result<Self> {
        let db = Connection::open_in_memory()?;
        if !passwd.is_empty() {
            db.pragma_update(None, "key", passwd)?;
        }

        let db = GxsDatabase { db };
        // mem table is always new
        db.create_tables()?;

        Ok(db)
    }

    fn create_tables(&self) -> Result<()> {
        let create_table = |name: &str, columns: &Vec<(&str, &str)>| -> Result<usize> {
            let stm = String::from("CREATE TABLE ")
                + name
                + "("
                + &columns
                    .iter()
                    .map(|(field, ty)| field.to_string() + " " + ty)
                    .collect::<Vec<_>>()
                    .join(",")
                + ");";
            debug!("creating tables: {stm}");

            self.db.execute(&stm, [])
        };

        // release table
        let columns = vec![
            (KEY_DATABASE_RELEASE_ID, "INT PRIMARY KEY"),
            (KEY_DATABASE_RELEASE, "INT"),
        ];
        create_table(TABLE_RELEASE, &columns)?;

        // messages table
        let columns = vec![
            (KEY_MSG_ID, "TEXT PRIMARY KEY"),
            (KEY_GRP_ID, "TEXT"),
            (KEY_NXS_FLAGS, "INT"),
            (KEY_ORIG_MSG_ID, "TEXT"),
            (KEY_TIME_STAMP, "INT"),
            (KEY_NXS_IDENTITY, "TEXT"),
            (KEY_SIGN_SET, "BLOB"),
            (KEY_NXS_DATA, "BLOB"),
            (KEY_NXS_DATA_LEN, "INT"),
            (KEY_MSG_STATUS, "INT"),
            (KEY_CHILD_TS, "INT"),
            (KEY_NXS_META, "BLOB"),
            (KEY_MSG_THREAD_ID, "TEXT"),
            (KEY_MSG_PARENT_ID, "TEXT"),
            (KEY_MSG_NAME, "TEXT"),
            (KEY_NXS_SERV_STRING, "TEXT"),
            (KEY_NXS_HASH, "TEXT"),
            (KEY_RECV_TS, "INT"),
        ];
        create_table(TABLE_MESSAGES, &columns)?;

        // groups table
        let columns = vec![
            (KEY_GRP_ID, "TEXT PRIMARY KEY"),
            (KEY_TIME_STAMP, "INT"),
            (KEY_NXS_DATA, "BLOB"),
            (KEY_NXS_DATA_LEN, "INT"),
            (KEY_KEY_SET, "BLOB"),
            (KEY_NXS_META, "BLOB"),
            (KEY_GRP_NAME, "TEXT"),
            (KEY_GRP_LAST_POST, "INT"),
            (KEY_GRP_POP, "INT"),
            (KEY_MSG_COUNT, "INT"),
            (KEY_GRP_SUBCR_FLAG, "INT"),
            (KEY_GRP_STATUS, "INT"),
            (KEY_NXS_IDENTITY, "TEXT"),
            (KEY_ORIG_GRP_ID, "TEXT"),
            (KEY_NXS_SERV_STRING, "TEXT"),
            (KEY_NXS_FLAGS, "INT"),
            (KEY_GRP_AUTHEN_FLAGS, "INT"),
            (KEY_GRP_SIGN_FLAGS, "INT"),
            (KEY_GRP_CIRCLE_ID, "TEXT"),
            (KEY_GRP_CIRCLE_TYPE, "INT"),
            (KEY_GRP_INTERNAL_CIRCLE, "TEXT"),
            (KEY_GRP_ORIGINATOR, "TEXT"),
            (KEY_NXS_HASH, "TEXT"),
            (KEY_RECV_TS, "INT"),
            (KEY_PARENT_GRP_ID, "TEXT"),
            (KEY_GRP_REP_CUTOFF, "INT"),
            (KEY_SIGN_SET, "BLOB"),
        ];
        create_table(TABLE_GROUPS, &columns)?;

        // mDb->execSQL("CREATE TRIGGER " + GRP_LAST_POST_UPDATE_TRIGGER +
        //    " INSERT ON " + MSG_TABLE_NAME +
        //    std::string(" BEGIN ") +
        //    " UPDATE " + GRP_TABLE_NAME + " SET " + KEY_GRP_LAST_POST + "= new."
        //    + KEY_RECV_TS + " WHERE " + KEY_GRP_ID + "=new." + KEY_GRP_ID + ";"
        //    + std::string("END;"));
        let stm = String::from("CREATE TRIGGER LAST_POST_UPDATE INSERT ON ")
            + TABLE_MESSAGES
            + " BEGIN UPDATE "
            + TABLE_GROUPS
            + " SET "
            + KEY_GRP_LAST_POST
            + "= new."
            + KEY_RECV_TS
            + " WHERE "
            + KEY_GRP_ID
            + "=new."
            + KEY_GRP_ID
            + "; END;";
        debug!("creating trigger: {stm}");
        self.db.execute(&stm, [])?;

        // mDb->execSQL("CREATE INDEX " + MSG_INDEX_GRPID + " ON " + MSG_TABLE_NAME + "(" + KEY_GRP_ID +  ");");
        let stm = String::from("CREATE INDEX INDEX_MESSAGES_GRPID ON ")
            + TABLE_MESSAGES
            + "("
            + KEY_GRP_ID
            + ");";
        debug!("creating index: {stm}");
        self.db.execute(&stm, [])?;

        // Insert release, no need to upgrade
        let stm = String::from("INSERT INTO ")
            + TABLE_RELEASE
            + "("
            + KEY_DATABASE_RELEASE_ID
            + ", "
            + KEY_DATABASE_RELEASE
            + ")"
            + "VALUES (?1, ?2);";
        debug!("inserting release: {stm}");
        self.db.execute(&stm, [RELEASE_ID_VALUE, RELEASE_VERSION])?;

        Ok(())
    }

    fn verify_version(&self) -> Result<()> {
        let stm = String::from("SELECT ")
            + KEY_DATABASE_RELEASE_ID
            + ", "
            + KEY_DATABASE_RELEASE
            + " FROM "
            + TABLE_RELEASE
            + " WHERE "
            + TABLE_RELEASE
            + "."
            + KEY_DATABASE_RELEASE_ID
            + "=?;";
        debug!("verify query {stm}");

        let res = self
            .db
            .prepare(&stm)?
            .query_map([&RELEASE_ID_VALUE.to_string()], |row| {
                GxsDatabaseRelease::from_row(row)
            })?
            .next()
            .ok_or_else(|| panic!("unsupported database version (or no version found)"))
            .unwrap();
        if let Ok(release_info) = res {
            debug!("{release_info:?}");
            assert_eq!(release_info.id, 1); // sql will probably not be broken

            if release_info.release != RELEASE_VERSION {
                panic!(
                    "unsupported database version {}, only {RELEASE_VERSION} is supported",
                    release_info.release
                );
            }
        } else {
            panic!("unsupported database version: no version found");
        }

        Ok(())
    }

    // old code

    pub fn get_grp_meta_all(&self) -> Result<Vec<GxsGrpMetaSql>> {
        let stm = String::from("SELECT ")
            + &GxsGrpMetaSql::get_columns()
                .into_iter()
                .map(|(s, _)| s)
                .collect::<Vec<_>>()
                .join(",")
            + " FROM "
            + TABLE_GROUPS;
        debug!(
            "querying {stm} on {:?}",
            self.db.path().unwrap().file_name()
        );
        let mut stm = self.db.prepare(&stm)?;
        let entries = stm
            .query_map([], |row| GxsGrpMetaSql::from_row(row))?
            .filter_map(|e| match e {
                Ok(e) => Some(e),
                Err(e) => {
                    warn!("{e:?}");
                    None
                }
            })
            .collect();
        Ok(entries)
    }

    pub fn get_msg_meta_all(&self) -> Result<Vec<GxsMsgMetaSql>> {
        let stm = String::from("SELECT ")
            + &GxsMsgMetaSql::get_columns()
                .into_iter()
                .map(|(s, _)| s)
                .collect::<Vec<_>>()
                .join(",")
            + " FROM "
            + TABLE_MESSAGES;
        debug!(
            "querying {stm} on {:?}",
            self.db.path().unwrap().file_name()
        );
        let mut stm = self.db.prepare(&stm)?;
        let entries = stm
            .query_map([], |row| GxsMsgMetaSql::from_row(row))?
            .filter_map(|e| match e {
                Ok(e) => Some(e),
                Err(e) => {
                    warn!("{e:?}");
                    None
                }
            })
            .collect();
        Ok(entries)
    }

    // new code

    // msg vs group
    // meta vs data

    fn query_by_group_id<T>(&self, table: &str, group_id: &GxsGroupId) -> Result<Vec<T>>
    where
        T: FromSqlRs,
    {
        // TODO is it always useful to match based on group id?
        // Messages have more than one entry per group id!

        let stm = String::from("SELECT ")
            + &T::get_columns()
                .into_iter()
                .map(|(s, _)| s)
                .collect::<Vec<_>>()
                .join(",")
            + " FROM "
            + table
            + " WHERE "
            + table
            + ".grpId=(?);";
        debug!(
            "querying {stm} on {:?}",
            self.db.path().unwrap().file_name()
        );
        let mut entries = vec![];

        let mut stm = self.db.prepare_cached(&stm)?;
        let res = stm
            .query_map(params!(group_id.to_string()), |row| T::from_row(row))?
            .find_map(|e| match e {
                Ok(e) => Some(e),
                Err(e) => {
                    warn!("{e:?}");
                    None
                }
            });
        if let Some(entry) = res {
            entries.push(entry);
        } else {
            trace!("no entry found for {group_id}");
        }

        Ok(entries)
    }

    pub fn get_group_ids(&self) -> Result<Vec<GxsGroupId>> {
        let stm = String::from("SELECT ") + KEY_GRP_ID + " FROM " + TABLE_GROUPS;
        debug!(
            "querying {stm} on {:?}",
            self.db.path().unwrap().file_name()
        );
        let mut stm = self.db.prepare(&stm)?;
        let entries = stm
            .query_map([], |row| row.get(0))?
            .filter_map(|e| match e {
                Ok(e) => Some(e),
                Err(e) => {
                    warn!("{e:?}");
                    None
                }
            })
            .collect();
        Ok(entries)
    }

    pub fn get_grp_meta(&self, group_id: &GxsGroupId) -> Result<Option<GxsGroup>> {
        let sql: Vec<GxsGrpMetaSql> = self.query_by_group_id(TABLE_GROUPS, group_id)?;

        if sql.is_empty() {
            return Ok(None);
        }

        // we read the group table where the group id is the primary key
        assert!(sql.len() == 1);

        let sql = sql.into_iter().nth(0).unwrap();

        Ok(Some(sql.into()))
    }

    pub fn get_grp_data(&self, group_meta: &mut GxsGroup) -> Result<()> {
        let sql = self
            .query_by_group_id(TABLE_GROUPS, &group_meta.group_id)?
            .into_iter()
            .nth(0)
            // unwrap, there must be an entry for the given group id
            .unwrap();
        group_meta.set_blobs(sql);
        Ok(())
    }

    pub fn get_msg_ids(&self) -> Result<Vec<GxsMessageId>> {
        let stm = String::from("SELECT ") + KEY_MSG_ID + " FROM " + TABLE_MESSAGES;
        debug!(
            "querying {stm} on {:?}",
            self.db.path().unwrap().file_name()
        );
        let mut stm = self.db.prepare(&stm)?;
        let entries = stm
            .query_map([], |row| row.get(0))?
            .filter_map(|e| match e {
                Ok(e) => Some(e),
                Err(e) => {
                    warn!("{e:?}");
                    None
                }
            })
            .collect();
        Ok(entries)
    }

    // TODO
    pub fn get_msg_ids_by_grp_id(&self, _group_id: &GxsGroupId) {}

    // TODO use msg id +  second function for by group id
    pub fn get_msg_meta(&self, group_id: &GxsGroupId) -> Result<Vec<GxsMsgMetaSql>> {
        // TODO
        self.query_by_group_id(TABLE_MESSAGES, group_id)
    }

    // TODO should be by msg id
    pub fn get_msg_data(&self, group_id: &GxsGroupId) -> Result<Vec<GxsMsgDataSql>> {
        // TODO
        self.query_by_group_id(TABLE_MESSAGES, group_id)
    }

    pub fn insert_group(&self, group: &GxsGroup) -> Result<()> {
        // TODO? can this be improved into one statement?

        // crash early
        let blobs = group.get_blobs();
        
        // store meta
        let fields = &GxsGrpMetaSql::get_columns();
        // "OR REPLACE": the same group can arrive twice (e.g. asked from two friends or
        // in two overlapping requests); a plain INSERT failed on the unique group id and
        // the caller's unwrap() crashed the whole GXS service
        let stm = String::from("INSERT OR REPLACE INTO ")
            + TABLE_GROUPS
            + " ("
            + &fields
                .iter()
                .map(|(s, _)| s.to_owned())
                .collect::<Vec<_>>()
                .join(",")
            + ") "
            + "VALUES ("
            + &fields
                .iter()
                .map(|(_, s)| s.to_owned())
                .collect::<Vec<_>>()
                .join(",")
            + ");";
        debug!("inserting (meta) {stm}");
        self.db.execute(&stm, group.to_dyn_sql_row().as_slice())?;

        // store data
        assert_eq!(
            GxsGrpDataSql::get_columns()
                .iter()
                .map(|(s, _)| s)
                .collect::<Vec<_>>(),
            vec![KEY_GRP_ID, KEY_NXS_DATA, KEY_NXS_DATA_LEN, KEY_NXS_META]
        );
        let stm = String::from("UPDATE ")
            + TABLE_GROUPS
            + " SET "
            + KEY_NXS_DATA
            + "=(?2),"
            + KEY_NXS_DATA_LEN
            + "=(?3),"
            + KEY_NXS_META
            + "=(?4)"
            + " WHERE "
            + TABLE_GROUPS
            + "."
            + KEY_GRP_ID
            + "=(?1)";
        debug!("inserting (data) {stm}");
        self.db.execute(&stm, blobs.to_row().as_slice())?;

        Ok(())
    }

    pub fn insert_message(
        &self,
        // group: &GxsMsgMetaSql,
        // meta_blob: &Blob,
        // nxs_blob: &Blob,
    ) -> Result<()> {
        // TODO
        // MUST use msgId!!
        unimplemented!()
    }

    // --- messages (posts), simple raw access used for forums ---

    /// Stores a received message (ids as lower case hex like the rest of the table).
    pub fn insert_message_raw(&self, msg: &StoredMsg) -> Result<()> {
        let stm = String::from("INSERT OR REPLACE INTO ")
            + TABLE_MESSAGES
            + " (msgId, grpId, threadId, parentId, origMsgId, identity, msgName, timeStamp, \
               nxsData, nxsDataLen, meta, recv_time_stamp, msgStatus, flags) \
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";
        self.db.execute(
            &stm,
            params![
                msg.msg_id,
                msg.group_id,
                msg.thread_id,
                msg.parent_id,
                msg.orig_msg_id,
                msg.author_id,
                msg.name,
                msg.publish_ts,
                msg.data,
                msg.data.len() as i64,
                msg.meta,
                msg.recv_ts,
                msg.status,
                msg.flags,
            ],
        )?;
        Ok(())
    }

    pub fn has_message(&self, msg_id: &str) -> Result<bool> {
        let stm = String::from("SELECT COUNT(*) FROM ") + TABLE_MESSAGES + " WHERE msgId=(?1)";
        let n: i64 = self.db.query_row(&stm, params![msg_id], |r| r.get(0))?;
        Ok(n > 0)
    }

    pub fn get_messages_raw(&self, group_id: &str) -> Result<Vec<StoredMsg>> {
        let stm = String::from(
            "SELECT msgId, grpId, threadId, parentId, origMsgId, identity, msgName, timeStamp, \
             nxsData, meta, recv_time_stamp, msgStatus, flags FROM ",
        ) + TABLE_MESSAGES
            + " WHERE grpId=(?1) ORDER BY timeStamp";
        let mut stm = self.db.prepare(&stm)?;
        let rows = stm.query_map(params![group_id], |r| {
            Ok(StoredMsg {
                msg_id: r.get(0)?,
                group_id: r.get(1)?,
                thread_id: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                parent_id: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                orig_msg_id: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                author_id: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                name: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
                publish_ts: r.get::<_, Option<i64>>(7)?.unwrap_or_default(),
                data: r.get::<_, Option<Vec<u8>>>(8)?.unwrap_or_default(),
                meta: r.get::<_, Option<Vec<u8>>>(9)?.unwrap_or_default(),
                recv_ts: r.get::<_, Option<i64>>(10)?.unwrap_or_default(),
                status: r.get::<_, Option<i64>>(11)?.unwrap_or_default(),
                flags: r.get::<_, Option<i64>>(12)?.unwrap_or_default(),
            })
        })?;
        rows.collect()
    }

    /// Sets and clears bits of a message's status (rustyshare: 0x01 = signature
    /// verified, 0x04 = unread like GXS_MSG_STATUS_GUI_UNREAD).
    pub fn set_message_status_bits(&self, msg_id: &str, set: i64, clear: i64) -> Result<()> {
        let stm = String::from("UPDATE ")
            + TABLE_MESSAGES
            + " SET msgStatus=((IFNULL(msgStatus,0) | (?2)) & ~(?3)) WHERE msgId=(?1)";
        self.db.execute(&stm, params![msg_id, set, clear])?;
        Ok(())
    }

    /// Unread verified messages per group: status has 0x01 (verified) and 0x04 (unread).
    pub fn unread_counts(&self) -> Result<Vec<(String, i64)>> {
        let stm = String::from("SELECT grpId, COUNT(*) FROM ")
            + TABLE_MESSAGES
            + " WHERE (IFNULL(msgStatus,0) & 5) = 5 GROUP BY grpId";
        let mut stm = self.db.prepare(&stm)?;
        let rows = stm.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        rows.collect()
    }

    pub fn set_message_status(&self, msg_id: &str, status: i64) -> Result<()> {
        let stm = String::from("UPDATE ") + TABLE_MESSAGES + " SET msgStatus=(?2) WHERE msgId=(?1)";
        self.db.execute(&stm, params![msg_id, status])?;
        Ok(())
    }

    pub fn delete_message(&self, msg_id: &str) -> Result<()> {
        let stm = String::from("DELETE FROM ") + TABLE_MESSAGES + " WHERE msgId=(?1)";
        self.db.execute(&stm, params![msg_id])?;
        Ok(())
    }

    /// Sets a group's subscribe flags (GXS_SERV::GROUP_SUBSCRIBE_*).
    pub fn set_group_subscribe_flags(&self, group_id: &str, flags: u32) -> Result<()> {
        let stm = String::from("UPDATE ") + TABLE_GROUPS + " SET " + KEY_GRP_SUBCR_FLAG + "=(?2) WHERE grpId=(?1)";
        self.db.execute(&stm, params![group_id, flags])?;
        Ok(())
    }
}

/// A GXS message (e.g. a forum post) as stored in the MESSAGES table.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct StoredMsg {
    pub msg_id: String,
    pub group_id: String,
    pub thread_id: String,
    pub parent_id: String,
    pub orig_msg_id: String,
    pub author_id: String,
    pub name: String,
    pub publish_ts: i64,
    #[serde(skip)]
    pub data: Vec<u8>,
    #[serde(skip)]
    pub meta: Vec<u8>,
    pub recv_ts: i64,
    /// rustyshare: 0 = signature not checked yet, 1 = verified
    pub status: i64,
    pub flags: i64,
}
