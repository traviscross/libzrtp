/*
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>

#include "zrtp_b64_encode.h"
#include "zrtp_b64_decode.h"

#include "zrtp_cache_db_backend.h"

#ifdef TRANSACTIONS
static const char *beginTransactionSql  = "BEGIN TRANSACTION;";
static const char *commitTransactionSql = "COMMIT;";
#endif

/*
 * The database backend uses the following definitions if it implements the localZid storage.
 */

/* The type field in zrtpIdOwn stores the following values */
static const int32_t localZidStandard         = 1; /* this local ZID is not tied to a specific account */
static const int32_t localZidWithAccount      = 2;

/* Default data for account info if none specified */
static const char *defaultAccountString = "_STANDARD_";


/* *****************************************************************************
 * The SQLite master table.
 *
 * Used to check if we have valid ZRTP cache tables.
 */
static char *lookupTables = "SELECT name FROM sqlite_master WHERE type='table' AND name='zrtpIdOwn';";


/* *****************************************************************************
 * SQL statements and structures to process the zrtpIdOwn table.
 */
/* SQLite doesn't care about the VARCHAR length. */
static char *createZrtpIdOwn = "CREATE TABLE zrtpIdOwn(localZid CHAR(18), type INTEGER, accountInfo VARCHAR(1000));";

static char *lookupZrtpIdOwn = "SELECT localZid FROM zrtpIdOwn WHERE type = ?1 AND accountInfo = ?2;";
static char *insertZrtpIdOwn = "INSERT INTO zrtpIdOwn (localZid, type, accountInfo) VALUES (?1, ?2, ?3);";


/* *****************************************************************************
 * SQL statements to process the remoteId table.
 */
static char *dropZrtpIdRemote =      "DROP TABLE zrtpIdRemote;";
static char *selectZrtpIdRemoteAll = 
    "SELECT remoteZid, flags,"
    "rs1, strftime('%s', rs1LastUsed, 'unixepoch'), strftime('%s', rs1TimeToLive, 'unixepoch'),"
    "rs2, strftime('%s', rs2LastUsed, 'unixepoch'), strftime('%s', rs2TimeToLive, 'unixepoch'),"
    "mitmKey "
    "from zrtpIdRemote WHERE remoteZid=?1 AND localZid=?2;";

static char *insertZrtpIdRemote =
    "INSERT INTO zrtpIdRemote "
        "(remoteZid, flags,"
        "rs1, rs1LastUsed, rs1TimeToLive,"
        "rs2, rs2LastUsed, rs2TimeToLive,"
        "mitmKey, localZid)"
      "VALUES"
        "(?1, ?2,"
        "?3, strftime('%s', ?4, 'unixepoch'), strftime('%s', ?5, 'unixepoch'),"
        "?6, strftime('%s', ?7, 'unixepoch'), strftime('%s', ?8, 'unixepoch'),"
        "?9, ?10);";

static char *updateZrtpIdRemote = 
    "UPDATE zrtpIdRemote SET "
    "flags=?2,"
    "rs1=?3, rs1LastUsed=strftime('%s', ?4, 'unixepoch'), rs1TimeToLive=strftime('%s', ?5, 'unixepoch'),"
    "rs2=?6, rs2LastUsed=strftime('%s', ?7, 'unixepoch'), rs2TimeToLive=strftime('%s', ?8, 'unixepoch'),"
    "mitmKey=?9 "
    "WHERE remoteZid=?1 AND localZid=?10;";

static char *createZrtpIdRemote = 
    "CREATE TABLE zrtpIdRemote "
    "(remoteZid CHAR(16), flags INTEGER,"
    "rs1 BLOB(32), rs1LastUsed TIMESTAMP, rs1TimeToLive TIMESTAMP," 
    "rs2 BLOB(32), rs2LastUsed TIMESTAMP, rs2TimeToLive TIMESTAMP,"
    "mitmKey BLOB(32), localZid CHAR(16));";

/* *****************************************************************************
 * A few helping macros. 
 * These macros require some names/patterns in the methods that use these 
 * macros:
 * 
 * ERRMSG requires:
 * - a variable with name "db" is the pointer to sqlite3
 * - a char* with name "errString" points to a buffer of at least SQL_CACHE_ERR_BUFF_SIZE chars
 *
 * SQLITE_CHK requires:
 * - a cleanup label, the macro goes to that label in case of error
 * - an integer (int) variable with name "rc" that stores return codes from sqlite
 * - ERRMSG
 */
#define ERRMSG  {if (errString) snprintf(errString, DB_CACHE_ERR_BUFF_SIZE, \
                                         "SQLite3 error: %s, line: %d, error message: %s\n", __FILE__, __LINE__, sqlite3_errmsg(db));}
#define SQLITE_CHK(func) {                                              \
        rc = (func);                                                    \
        if(rc != SQLITE_OK) {                                           \
            ERRMSG;                                                     \
            goto cleanup;                                               \
        }                                                               \
    }

static int b64Encode(const uint8_t *binData, int32_t binLength, char *b64Data, int32_t b64Length)
{
    base64_encodestate _state;
    int codelength;

    base64_init_encodestate(&_state, 0);
    codelength = base64_encode_block(binData, binLength, b64Data, &_state);
    codelength += base64_encode_blockend(b64Data+codelength, &_state);

    return codelength;
}

static int b64Decode(const char *b64Data, int32_t b64length, uint8_t *binData, int32_t binLength)
{
    base64_decodestate _state;
    int codelength;

    base64_init_decodestate(&_state);
    codelength = base64_decode_block(b64Data, b64length, binData, &_state);
    return codelength;
}

#ifdef TRANSACTIONS
static int beginTransaction(sqlite3 *db, char* errString)
{
    sqlite3_stmt *stmt;
    int rc;

    SQLITE_CHK(sqlite3_prepare_v2(db, beginTransactionSql, strlen(beginTransactionSql)+1, &stmt, NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        ERRMSG;
        return rc;
    }
    return SQLITE_OK;

 cleanup:
    sqlite3_finalize(stmt);
    return rc;
}

static int commitTransaction(sqlite3 *db, char* errString)
{
    sqlite3_stmt *stmt;
    int rc;

    SQLITE_CHK(sqlite3_prepare_v2(db, commitTransactionSql, strlen(commitTransactionSql)+1, &stmt, NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        ERRMSG;
        return rc;
    }
    return SQLITE_OK;

 cleanup:
    sqlite3_finalize(stmt);
    return rc;
}
#endif

/**
 * Create ZRTP cache tables in database.
 *
 * openCache calls this function if it cannot find the table zrtpId_own. This indicates
 * that no ZRTP cache tables are available in the database.
 */
static int createTables(sqlite3 *db, char* errString)
{
    sqlite3_stmt * stmt;
    int rc;

    /* no ZRTP cache tables were found - create them, first the OwnId table */
    SQLITE_CHK(sqlite3_prepare_v2(db, createZrtpIdOwn, strlen(createZrtpIdOwn)+1, &stmt, NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        ERRMSG;
        return rc;
    }

    /* Now the zrtpIdRemote table. */
    /* First drop it, just to be on the save side
     * Ignore errors, there is nothing to drop on empty DB. If ZrtpIdOwn was deleted using DB
     * admin command then we need to drop the remote id table also to start from a clean state.
     */
    rc = sqlite3_prepare_v2(db, dropZrtpIdRemote, strlen(dropZrtpIdRemote)+1, &stmt, NULL);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    SQLITE_CHK(sqlite3_prepare_v2(db, createZrtpIdRemote, strlen(createZrtpIdRemote)+1, &stmt, NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        ERRMSG;
        return rc;
    }
    return 0;

 cleanup:
    sqlite3_finalize(stmt);
    return rc;
}

static int insertRemoteZidRecord(void *vdb, const uint8_t *remoteZid, const uint8_t *localZid, 
                                 const remoteZidRecord_t *remZid, char* errString)
{
    sqlite3 *db = (sqlite3*)vdb;
    sqlite3_stmt *stmt;
    int rc = 0;

    char b64RemoteZid[IDENTIFIER_LEN*2] = {0};
    char b64LocalZid[IDENTIFIER_LEN*2] = {0};

    /* Get B64 code for remoteZid first */
    b64Encode(remoteZid, IDENTIFIER_LEN, b64RemoteZid, IDENTIFIER_LEN*2);

    /* Get B64 code for localZid now */
    b64Encode(localZid, IDENTIFIER_LEN, b64LocalZid, IDENTIFIER_LEN*2);

    SQLITE_CHK(sqlite3_prepare_v2(db, insertZrtpIdRemote, strlen(insertZrtpIdRemote)+1, &stmt, NULL));

    /* For *_bind_* methods: column index starts with 1 (one), not zero */
    SQLITE_CHK(sqlite3_bind_text(stmt,   1, b64RemoteZid, strlen(b64RemoteZid), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_int(stmt,    2, remZid->flags));
    SQLITE_CHK(sqlite3_bind_blob(stmt,   3, remZid->rs1, RS_LENGTH, SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_int64(stmt,  4, remZid->rs1LastUse));
    SQLITE_CHK(sqlite3_bind_int64(stmt,  5, remZid->rs1Ttl));
    SQLITE_CHK(sqlite3_bind_blob(stmt,   6, remZid->rs2, RS_LENGTH, SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_int64(stmt,  7, remZid->rs2LastUse));
    SQLITE_CHK(sqlite3_bind_int64(stmt,  8, remZid->rs2Ttl));
    SQLITE_CHK(sqlite3_bind_blob(stmt,   9, remZid->mitmKey, RS_LENGTH, SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt,  10, b64LocalZid, strlen(b64LocalZid), SQLITE_STATIC));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        ERRMSG;
        return rc;
    }
    return SQLITE_OK;

 cleanup:
    sqlite3_finalize(stmt);
    return rc;

}

static int updateRemoteZidRecord(void *vdb, const uint8_t *remoteZid, const uint8_t *localZid, 
                                 const remoteZidRecord_t *remZid, char* errString)
{
    sqlite3 *db = (sqlite3*)vdb;
    sqlite3_stmt *stmt;
    int rc;

    char b64RemoteZid[IDENTIFIER_LEN*2] = {0};
    char b64LocalZid[IDENTIFIER_LEN*2] = {0};

    /* Get B64 code for remoteZid first */
    b64Encode(remoteZid, IDENTIFIER_LEN, b64RemoteZid, IDENTIFIER_LEN*2);

    /* Get B64 code for localZid now */
    b64Encode(localZid, IDENTIFIER_LEN, b64LocalZid, IDENTIFIER_LEN*2);

    SQLITE_CHK(sqlite3_prepare_v2(db, updateZrtpIdRemote, strlen(updateZrtpIdRemote)+1, &stmt, NULL));

    /* For *_bind_* methods: column index starts with 1 (one), not zero */
    SQLITE_CHK(sqlite3_bind_text(stmt,   1, b64RemoteZid, strlen(b64RemoteZid), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_int(stmt,    2, remZid->flags));
    SQLITE_CHK(sqlite3_bind_blob(stmt,   3, remZid->rs1, RS_LENGTH, SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_int64(stmt,  4, remZid->rs1LastUse));
    SQLITE_CHK(sqlite3_bind_int64(stmt,  5, remZid->rs1Ttl));
    SQLITE_CHK(sqlite3_bind_blob(stmt,   6, remZid->rs2, RS_LENGTH, SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_int64(stmt,  7, remZid->rs2LastUse));
    SQLITE_CHK(sqlite3_bind_int64(stmt,  8, remZid->rs2Ttl));
    SQLITE_CHK(sqlite3_bind_blob(stmt,   9, remZid->mitmKey, RS_LENGTH, SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt,  10, b64LocalZid, strlen(b64LocalZid), SQLITE_STATIC));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        ERRMSG;
        return rc;
    }
    return SQLITE_OK;

 cleanup:
    sqlite3_finalize(stmt);
    return rc;
}

static int readRemoteZidRecord(void *vdb, const uint8_t *remoteZid, const uint8_t *localZid, 
                               remoteZidRecord_t *remZid, char* errString)
{
    sqlite3 *db = (sqlite3*)vdb;
    sqlite3_stmt *stmt;
    int rc;
    int found = 0;

    char b64RemoteZid[IDENTIFIER_LEN*2] = {0};
    char b64LocalZid[IDENTIFIER_LEN*2] = {0};

    /* Get B64 code for remoteZid first */
    b64Encode(remoteZid, IDENTIFIER_LEN, b64RemoteZid, IDENTIFIER_LEN*2);

    /* Get B64 code for localZid now */
    b64Encode(localZid, IDENTIFIER_LEN, b64LocalZid, IDENTIFIER_LEN*2);

    SQLITE_CHK(sqlite3_prepare_v2(db, selectZrtpIdRemoteAll, strlen(selectZrtpIdRemoteAll)+1, &stmt, NULL));
    SQLITE_CHK(sqlite3_bind_text(stmt, 1, b64RemoteZid, strlen(b64RemoteZid), SQLITE_STATIC));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, b64LocalZid, strlen(b64LocalZid), SQLITE_STATIC));

    /* Getting data from result set: column index starts with 0 (zero), not one */
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        remZid->flags =         sqlite3_column_int(stmt,   1);
        memcpy(remZid->rs1,     sqlite3_column_blob(stmt,  2), RS_LENGTH); 
        remZid->rs1LastUse =    sqlite3_column_int64(stmt, 3);
        remZid->rs1Ttl =        sqlite3_column_int64(stmt, 4);
        memcpy(remZid->rs2,     sqlite3_column_blob(stmt,  5), RS_LENGTH); 
        remZid->rs2LastUse =    sqlite3_column_int64(stmt, 6);
        remZid->rs2Ttl =        sqlite3_column_int64(stmt, 7);
        memcpy(remZid->mitmKey, sqlite3_column_blob(stmt,  8), RS_LENGTH); 
        found++;
    }
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        ERRMSG;
        return rc;
    }
    if (found == 0) {
        remZid->flags = 0;
    }
    else if (found > 1) {
        if (errString) 
            snprintf(errString, DB_CACHE_ERR_BUFF_SIZE, "ZRTP cache inconsistent. More than one remote ZID found: %d\n", found);
        return 1;
    }
    return SQLITE_OK;

 cleanup:
    sqlite3_finalize(stmt);
    return rc;
}


static int readLocalZid(void *vdb, uint8_t *localZid, const char *accountInfo, char *errString)
{
    sqlite3 *db = (sqlite3*)vdb;
    sqlite3_stmt *stmt;
    char *zidBase64Text;
    int rc = 0;
    int found = 0;
    int type = localZidWithAccount;

    if (accountInfo == NULL || !strcmp(accountInfo, defaultAccountString)) {
        accountInfo = defaultAccountString;
        type = localZidStandard;
    }

    /* Find a localZid record for this combination */
    SQLITE_CHK(sqlite3_prepare_v2(db, lookupZrtpIdOwn, strlen(lookupZrtpIdOwn)+1, &stmt, NULL));

    SQLITE_CHK(sqlite3_bind_int(stmt,  1, type));
    SQLITE_CHK(sqlite3_bind_text(stmt, 2, accountInfo, strlen(accountInfo), SQLITE_STATIC));

    /* Loop over result set and count it. However, use only the localZid of first row */
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (found == 0) {
            zidBase64Text = (char *)sqlite3_column_text(stmt, 0);
            b64Decode(zidBase64Text, strlen(zidBase64Text), localZid, IDENTIFIER_LEN);
        }
        found++;
    }
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        ERRMSG;
        return rc;
    }
    /* No matching record found, create new local ZID for this combination and store in DB */
    if (found == 0) {
        int32_t *ptmp = (int32_t*)localZid;
        char b64zid[IDENTIFIER_LEN+IDENTIFIER_LEN] = {0};
        int b64len = 0;

        /* create a 12 byte random value, convert to base 64, insert in zrtpIdOwn table */
        time_t now = time(NULL);
        srandom(now);
        *ptmp++ = random();
        *ptmp++ = random();
        *ptmp = random();
        b64len = b64Encode(localZid, IDENTIFIER_LEN, b64zid, IDENTIFIER_LEN+IDENTIFIER_LEN);

        SQLITE_CHK(sqlite3_prepare_v2(db, insertZrtpIdOwn, strlen(insertZrtpIdOwn)+1, &stmt, NULL));

        SQLITE_CHK(sqlite3_bind_text(stmt, 1, b64zid, b64len, SQLITE_STATIC));
        SQLITE_CHK(sqlite3_bind_int(stmt,  2, type));
        SQLITE_CHK(sqlite3_bind_text(stmt, 3, accountInfo, strlen(accountInfo), SQLITE_STATIC));

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            ERRMSG;
            return rc;
        }
    }
    else if (found > 1) {
        if (errString) 
            snprintf(errString, DB_CACHE_ERR_BUFF_SIZE,
                     "ZRTP cache inconsistent. Found %d matching local ZID for account: %s\n", found, accountInfo);
        rc = 1;
    }
    return SQLITE_OK;

 cleanup:
    sqlite3_finalize(stmt);
    return rc;
}

/*
 * SQLite use the following table structure to manage some internal data
 *
 * CREATE TABLE sqlite_master (
 *   type TEXT,
 *   name TEXT,
 *   tbl_name TEXT,
 *    rootpage INTEGER,
 *    sql TEXT
 * );
 */

static int openCache(char* name, void **vpdb, char *errString)
{
    sqlite3_stmt *stmt;
    int found = 0;
    sqlite3 **pdb = (sqlite3**)vpdb;
    sqlite3 *db;

    int rc = sqlite3_open_v2(name, pdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    db = *pdb;
    if (rc) {
        ERRMSG;
        return(rc);
    }

    /* check if ZRTP cache tables are already available, look if zrtpIdOwn is available */
    SQLITE_CHK(sqlite3_prepare_v2(db, lookupTables, strlen(lookupTables)+1, &stmt, NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_ROW) {
        found++;
    }
    else if (rc != SQLITE_DONE) {
        ERRMSG;
        return rc;
    }
    /* If table zrtpOwnId not found then we have an empty cache DB */
    if (found == 0) {
        rc = createTables(db, errString);
        if (rc)
            return rc;
    }
    return SQLITE_OK;

 cleanup:
    sqlite3_finalize(stmt);
    return rc;
}

static int closeCache(void *vdb)
{
    sqlite3 *db = (sqlite3*)vdb;
    sqlite3_close(db);
    return SQLITE_OK;
}

void getDbCacheOps(dbCacheOps_t *ops)
{
    ops->openCache = openCache;
    ops->closeCache = closeCache;
    ops->readLocalZid = readLocalZid;
    ops->readRemoteZidRecord = readRemoteZidRecord;
    ops->updateRemoteZidRecord = updateRemoteZidRecord;
    ops->insertRemoteZidRecord = insertRemoteZidRecord;
}

