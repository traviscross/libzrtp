/*
 *
 */

#include <stdio.h>  /* for file operations*/
#include <string.h> /* for strlen() and other string operations*/
#include <stdint.h>
#include <time.h>


#include "zrtp_string.h"
#include "zrtp.h"

#include "zrtp_cache_db.h"
#include "zrtp_cache_db_backend.h"

#define _ZTU_ "zrtp DB cache"

/**  ZRTP file-based cache */
struct zrtp_cache_db_t {
    zrtp_cache_t    super_;                     /**! ZRTP cache super class. @warning must be the first field. */
    zrtp_string16_t localZid;                   /**! local ZID */
    zrtp_cache_db_config_t    config;           /**! copy of initialization config */
    zrtp_global_t   *zrtp;                      /**! zrtp context */
    void *db;
    dbCacheOps_t ops;                           /**! The DB backend operations  */
    /*  zrtp_mutex_t    *cache_protector;           **! mutex to protect operations with cache elemnts list */
};

/*
 * Starting sequence / pattern of every DB cache method.
 * - cast the generic pointer to the specific DB type pointer
 * - initialize standard pointers that are we (usually) always use
 */
#define ZRTP_DB_CACHE_START                                         \
    zrtp_cache_db_t *cacheDb = (zrtp_cache_db_t *)cache;            \
    void *db = cacheDb->db;                                         \
    const uint8_t *localZid = (uint8_t*)cacheDb->localZid.buffer;   \
    const uint8_t *remoteZid = (uint8_t*)rZid->buffer;              \
    char errString[DB_CACHE_ERR_BUFF_SIZE]


#define ZRTP_CACHE_CHECK_ZID(zid)         \
    if (zid->length != IDENTIFIER_LEN)  { \
        return zrtp_status_bad_param;     \
    }

/******************************************************************************
 * libzrtp DB cache interface implementation
 */

static zrtp_status_t dbCachePutRs1(zrtp_cache_t *cache, const zrtp_stringn_t* rZid, zrtp_shared_secret_t *rss)
{
    ZRTP_DB_CACHE_START;
    int rc;
    remoteZidRecord_t remZid;
    uint8_t *newRs1 = (uint8_t*)rss->value.buffer;
    char zidstr[IDENTIFIER_LEN * 2 + 2];

    ZRTP_CACHE_CHECK_ZID(rZid);

    ZRTP_LOG(3,(_ZTU_,"\tdbCachePutRs1() remote ZID: %s\n", hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));

    memset(&remZid, 0, sizeof(remoteZidRecord_t));
    rc = cacheDb->ops.readRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCachePutRs1:readRemoteZidRecord() error: %s", errString));
        return zrtp_status_fail;
    }
    if (zrtpIdIsRs1Valid(&remZid)) {
        /* shift RS1 data into RS2 position */
        memcpy(remZid.rs2, remZid.rs1, RS_LENGTH);
        remZid.rs2LastUse = remZid.rs1LastUse;
        remZid.rs2Ttl = remZid.rs1Ttl;
        zrtpIdSetRs2Valid(&remZid);
    }
    /* Setup the new RS1 information */
    memcpy(remZid.rs1, newRs1, RS_LENGTH);
    remZid.rs1LastUse = rss->lastused_at;
    remZid.rs1Ttl = rss->ttl;

    zrtpIdSetRs1Valid(&remZid);

    /* If no valid record was found then this is a new record. */
    if (!zrtpIdIsValid(&remZid)) {
        zrtpIdSetValid(&remZid);
        remZid.secureSince = (int64_t)time(NULL);
        rc = cacheDb->ops.insertRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);
    }
    else
        rc = cacheDb->ops.updateRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCachePutRs1:insert()/update() error: %s", errString));
        return zrtp_status_fail;
    }
    return zrtp_status_ok;
}

static zrtp_status_t dbCachePutMitm(zrtp_cache_t *cache, const zrtp_stringn_t* rZid, zrtp_shared_secret_t *rss)
{
    ZRTP_DB_CACHE_START;
    int rc;
    remoteZidRecord_t remZid;
    uint8_t *mitm = (uint8_t*)rss->value.buffer;
    char zidstr[IDENTIFIER_LEN * 2 + 2];

    ZRTP_CACHE_CHECK_ZID(rZid);

    ZRTP_LOG(3,(_ZTU_,"\tdbCachePutMitm() remote ZID: %s\n", hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));

    memset(&remZid, 0, sizeof(remoteZidRecord_t));
    rc = cacheDb->ops.readRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCachePutMitm:readRemoteZidRecord() error: %s", errString));
        return zrtp_status_fail;
    }
    /* copy the MitM information */
    memcpy(remZid.mitmKey, mitm, RS_LENGTH);
    zrtpIdSetMITMKeyAvailable(&remZid);
    remZid.mitmLastUse = rss->lastused_at; /* set mitm last used. Is this info used in ZRTP? */

    /* If no valid record was found then this is a new record. */
    if (!zrtpIdIsValid(&remZid)) {
        zrtpIdSetValid(&remZid);
        remZid.secureSince = (int64_t)time(NULL);
        rc = cacheDb->ops.insertRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);
    }
    else
        rc = cacheDb->ops.updateRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCachePutMitm:updateRemoteZidRecord() error: %s", errString));
        return zrtp_status_fail;
    }
    return zrtp_status_ok;
}

static zrtp_status_t dbCacheGetRs(zrtp_cache_t *cache, const zrtp_stringn_t* rZid, zrtp_shared_secret_t *rss, int rs2Requested)
{
    ZRTP_DB_CACHE_START;
    int rc;
    remoteZidRecord_t remZid;
    uint8_t *rs12 = (uint8_t*)rss->value.buffer;
    char zidstr[IDENTIFIER_LEN * 2 + 2];

    ZRTP_CACHE_CHECK_ZID(rZid);

    ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetRs() remote ZID: %s\n", hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));

    memset(&remZid, 0, sizeof(remoteZidRecord_t));
    rc = cacheDb->ops.readRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetRs:readRemoteZidRecord() error: %s", errString));
        return zrtp_status_fail;
    }
    if (!zrtpIdIsValid(&remZid)) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetRs: No remote ZID record for ZID: %s\n",
                    hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));
        return zrtp_status_fail;
    }

    /* Check validity of entries first */
    if (!zrtpIdIsRs1Valid(&remZid) || (rs2Requested && !zrtpIdIsRs2Valid(&remZid))) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetRs() - requested RS not found, RS2 requested: %s.\n", rs2Requested ? "yes" : "no"));
        return zrtp_status_fail;
    }
    if (rs2Requested && zrtpIdIsRs2Valid(&remZid)) {
        memcpy(rs12, remZid.rs2, RS_LENGTH);
        rss->lastused_at = remZid.rs2LastUse;
        rss->ttl = remZid.rs2Ttl;
    }
    else {
        memcpy(rs12, remZid.rs1, RS_LENGTH);
        rss->lastused_at = remZid.rs1LastUse;
        rss->ttl = remZid.rs1Ttl;
    }
    rss->value.length = RS_LENGTH;
    return zrtp_status_ok;
}

static zrtp_status_t dbCacheGetMitm(zrtp_cache_t *cache, const zrtp_stringn_t* rZid, zrtp_shared_secret_t *rss)
{
    ZRTP_DB_CACHE_START;
    int rc;
    remoteZidRecord_t remZid;
    uint8_t *mitm = (uint8_t*)rss->value.buffer;
    char zidstr[IDENTIFIER_LEN * 2 + 2];

    ZRTP_CACHE_CHECK_ZID(rZid);

    ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetMitm() remote ZID: %s\n", hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));

    memset(&remZid, 0, sizeof(remoteZidRecord_t));
    rc = cacheDb->ops.readRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetMitm:readRemoteZidRecord() error: %s", errString));
        return zrtp_status_fail;
    }
    if (!zrtpIdIsValid(&remZid)) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetMitm: No remote ZID record for ZID: %s\n",
                    hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));
        return zrtp_status_fail;
    }

    /* Check validity of entries first */
    if (!zrtpIdIsMITMKeyAvailable(&remZid)) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetRs() - requested MitM key not found.\n"));
        return zrtp_status_fail;
    }
    memcpy(mitm, remZid.mitmKey, RS_LENGTH);
    rss->lastused_at = remZid.mitmLastUse;
    rss->value.length = RS_LENGTH;

    return zrtp_status_ok;
}

static zrtp_status_t dbCacheSetVerified(zrtp_cache_t *cache, const zrtp_stringn_t* rZid, uint32_t verified)
{
    ZRTP_DB_CACHE_START;
    int rc;
    remoteZidRecord_t remZid;
    char zidstr[IDENTIFIER_LEN * 2 + 2];

    ZRTP_CACHE_CHECK_ZID(rZid);

    ZRTP_LOG(3,(_ZTU_,"\tdbCacheSetVerified() remote ZID: %s\n", hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));

    memset(&remZid, 0, sizeof(remoteZidRecord_t));
    rc = cacheDb->ops.readRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheSetVerified:readRemoteZidRecord() error: %s", errString));
        return zrtp_status_fail;
    }
    if (!zrtpIdIsValid(&remZid)) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheSetVerified: No remote ZID record for ZID: %s\n",
                    hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));
        return zrtp_status_fail;
    }
    if (verified)
        zrtpIdSetSasVerified(&remZid);
    else
        zrtpIdResetSasVerified(&remZid);

    rc = cacheDb->ops.updateRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheSetVerified:updateRemoteZidRecord() error: %s", errString));
        return zrtp_status_fail;
    }
    return zrtp_status_ok;
}

zrtp_status_t dbCacheGetVerified(zrtp_cache_t *cache, const zrtp_stringn_t* rZid, uint32_t* verified)
{
    ZRTP_DB_CACHE_START;
    int rc;
    remoteZidRecord_t remZid;
    char zidstr[IDENTIFIER_LEN * 2 + 2];

    ZRTP_CACHE_CHECK_ZID(rZid);

    ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetVerified() remote ZID: %s\n", hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));

    memset(&remZid, 0, sizeof(remoteZidRecord_t));
    rc = cacheDb->ops.readRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetVerified:readRemoteZidRecord() error: %s", errString));
        return zrtp_status_fail;
    }
    if (!zrtpIdIsValid(&remZid)) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetVerified: No remote ZID record for ZID: %s\n",
                    hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));
        return zrtp_status_fail;
    }
    *verified = zrtpIdIsSasVerified(&remZid);
    return zrtp_status_ok;
}



/******************************************************************************
 * ZRTP cache extended functions
 */

static zrtp_status_t dbCacheGetSince(zrtp_cache_t *cache, const zrtp_stringn_t* rZid, uint32_t* since)
{
    ZRTP_DB_CACHE_START;
    int rc;
    remoteZidRecord_t remZid;
    char zidstr[IDENTIFIER_LEN * 2 + 2];

    ZRTP_CACHE_CHECK_ZID(rZid);

    ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetSince() remote ZID: %s\n", hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));

    memset(&remZid, 0, sizeof(remoteZidRecord_t));
    rc = cacheDb->ops.readRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetSince:readRemoteZidRecord() error: %s", errString));
        return zrtp_status_fail;
    }
    if (!zrtpIdIsValid(&remZid)) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetSince: No remote ZID record for ZID: %s\n",
                    hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));
        return zrtp_status_fail;
    }
    *since = remZid.secureSince;
    return zrtp_status_ok;
}


static zrtp_status_t dbCacheResetSince(zrtp_cache_t *cache, const zrtp_stringn_t* rZid)
{
    ZRTP_DB_CACHE_START;
    int rc;
    remoteZidRecord_t remZid;
    char zidstr[IDENTIFIER_LEN * 2 + 2];

    ZRTP_CACHE_CHECK_ZID(rZid);

    ZRTP_LOG(3,(_ZTU_,"\tdbCacheResetSince() remote ZID: %s\n", hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));

    memset(&remZid, 0, sizeof(remoteZidRecord_t));
    rc = cacheDb->ops.readRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheResetSince:readRemoteZidRecord() error: %s", errString));
        return zrtp_status_fail;
    }
    if (!zrtpIdIsValid(&remZid)) {
        ZRTP_LOG(3,(_ZTU_,"\tdbdbCacheResetSince: No remote ZID record for ZID: %s\n",
                    hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));
        return zrtp_status_fail;
    }
    remZid.secureSince = (int64_t)time(NULL);
    rc = cacheDb->ops.updateRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheResetSince:updateRemoteZidRecord() error: %s", errString));
        return zrtp_status_fail;
    }
    return zrtp_status_ok;
}


static zrtp_status_t dbCacheGetName(zrtp_cache_t *cache, const zrtp_stringn_t* rZid, zrtp_stringn_t* name)
{

    ZRTP_DB_CACHE_START;
    int rc;
    zidNameRecord_t zidName;
    char zidstr[IDENTIFIER_LEN * 2 + 2];

    ZRTP_CACHE_CHECK_ZID(rZid);

    ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetName() remote ZID: %s\n", hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));

    zidName.flags = 0;
    zidName.name = name->buffer;
    zidName.nameLength = name->max_length;
    rc = cacheDb->ops.readZidNameRecord(db, remoteZid, localZid, NULL, &zidName , errString);
    name->length = zidName.nameLength;      /* set correct length in zrtp_string type */
 
    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetName:readZidName() error: %s", errString));
        return zrtp_status_fail;
    }
    if ((zidName.flags & Valid) != Valid) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetName: No ZID name record for ZID: %s\n",
                    hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));
        return zrtp_status_fail;
    }

    return zrtp_status_ok;
}


static zrtp_status_t dbCachePutName(zrtp_cache_t *cache, const zrtp_stringn_t* rZid, const zrtp_stringn_t* name)
{

    ZRTP_DB_CACHE_START;
    int rc;
    zidNameRecord_t zidName;
    char zidstr[IDENTIFIER_LEN * 2 + 2];

    ZRTP_CACHE_CHECK_ZID(rZid);

    ZRTP_LOG(3,(_ZTU_,"\tdbCachePutName() remote ZID: %s\n", hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));

    zidName.flags = 0;
    zidName.name = (char*)name->buffer;
    zidName.nameLength = name->max_length;
    rc = cacheDb->ops.readZidNameRecord(db, remoteZid, localZid, NULL, &zidName , errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetName:readZidName() error: %s", errString));
        return zrtp_status_fail;
    }
    /* If no valid record was found then this is a new record. */
    if ((zidName.flags & Valid) != Valid) {
        zidName.flags = Valid;
        rc = cacheDb->ops.insertZidNameRecord(db, remoteZid, localZid, NULL, &zidName, errString);
    }
    else
        rc = cacheDb->ops.updateZidNameRecord(db, remoteZid, localZid, NULL, &zidName, errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCachePutName:updateZidName() error: %s", errString));
        return zrtp_status_fail;
    }
    return zrtp_status_ok;
}


static zrtp_status_t dbCacheSetPreshCounter(zrtp_cache_t *cache, const zrtp_stringn_t* rZid, uint32_t counter)
{
    ZRTP_DB_CACHE_START;
    int rc;
    remoteZidRecord_t remZid;
    char zidstr[IDENTIFIER_LEN * 2 + 2];

    ZRTP_CACHE_CHECK_ZID(rZid);

    ZRTP_LOG(3,(_ZTU_,"\tdbCacheSetPreshCounter() remote ZID: %s\n", hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));

    memset(&remZid, 0, sizeof(remoteZidRecord_t));
    rc = cacheDb->ops.readRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheSetPreshCounter:readRemoteZidRecord() error: %s", errString));
        return zrtp_status_fail;
    }
    if (!zrtpIdIsValid(&remZid)) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheSetPreshCounter: No remote ZID record for ZID: %s\n",
                    hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));
        return zrtp_status_fail;
    }
    remZid.preshCounter = counter;
    rc = cacheDb->ops.updateRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheResetSince:updateRemoteZidRecord() error: %s", errString));
        return zrtp_status_fail;
    }
    return zrtp_status_ok;
}


zrtp_status_t dbCacheGetPreshCounter(zrtp_cache_t *cache, const zrtp_stringn_t* rZid, uint32_t* counter)
{
    ZRTP_DB_CACHE_START;
    int rc;
    remoteZidRecord_t remZid;
    char zidstr[IDENTIFIER_LEN * 2 + 2];

    ZRTP_CACHE_CHECK_ZID(rZid);

    ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetPreshCounter() remote ZID: %s\n", hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));

    memset(&remZid, 0, sizeof(remoteZidRecord_t));
    rc = cacheDb->ops.readRemoteZidRecord(db, remoteZid, localZid, &remZid, errString);

    if (rc) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetPreshCounter:readRemoteZidRecord() error: %s", errString));
        return zrtp_status_fail;
    }
    if (!zrtpIdIsValid(&remZid)) {
        ZRTP_LOG(3,(_ZTU_,"\tdbCacheGetPreshCounter: No remote ZID record for ZID: %s\n",
                    hex2str(rZid->buffer, rZid->length, zidstr, sizeof(zidstr))));
        return zrtp_status_fail;
    }
    *counter = remZid.preshCounter;
    return zrtp_status_ok;
}

/******************************************************************************
 * Public API
 */

zrtp_status_t zrtp_cache_db_create(zrtp_stringn_t *localZid, zrtp_cache_db_config_t *config, zrtp_cache_db_t **cache)
{
    zrtp_cache_db_t *newCache;
    char errString[DB_CACHE_ERR_BUFF_SIZE];
    void *db;

    newCache = zrtp_sys_alloc(sizeof(zrtp_cache_db_t));
    zrtp_memset(newCache, 0, sizeof(zrtp_cache_db_t));

    newCache->super_.op.put =          dbCachePutRs1;
    newCache->super_.op.put_mitm =     dbCachePutMitm;
    newCache->super_.op.get =          dbCacheGetRs;
    newCache->super_.op.get_mitm =     dbCacheGetMitm;
    newCache->super_.op.set_verified = dbCacheSetVerified;
    newCache->super_.op.get_verified = dbCacheGetVerified;

    newCache->super_.op_ext.get_name =           dbCacheGetName;
    newCache->super_.op_ext.put_name =           dbCachePutName;
    newCache->super_.op_ext.get_secure_since =   dbCacheGetSince;
    newCache->super_.op_ext.reset_secure_since = dbCacheResetSince;
    newCache->super_.op_ext.get_presh_counter =  dbCacheGetPreshCounter;
    newCache->super_.op_ext.set_presh_counter =  dbCacheSetPreshCounter;

    getDbCacheOps(&newCache->ops);

    zrtp_memcpy(&newCache->config, config, sizeof(zrtp_cache_db_config_t));

    /*
     *  If we can connect to this datasource, run the test program
     */
    if (newCache->ops.openCache(config->cache_path, &newCache->db, errString) != 0) {
        ZRTP_LOG(3,(_ZTU_,"\tzrtp_cache_db_create:openCache() error: %s", errString));
        return zrtp_status_fail;
    }
    ZSTR_SET_EMPTY(newCache->localZid);
    db = newCache->db;
    if (localZid != NULL) {
         zrtp_zstrcpy(ZSTR_GV(newCache->localZid), localZid);
    }
    else {
        if (newCache->ops.readLocalZid(db, (uint8_t*)newCache->localZid.buffer, NULL, errString) != 0) {
            ZRTP_LOG(3,(_ZTU_,"\tzrtp_cache_db_create:readLocalZid() error: %s", errString));
            return zrtp_status_fail;
        }
    }
    *cache = newCache;
    return zrtp_status_ok;
}

zrtp_status_t zrtp_cache_db_destroy(zrtp_cache_t *cache) {

    zrtp_cache_db_t *cacheDb = (zrtp_cache_db_t *)cache;
    void *db = cacheDb->db;

    if (!cache)
        return zrtp_status_bad_param;

    /*
     *  End the connection
     */
    cacheDb->ops.closeCache(db);

    return zrtp_status_ok;
}

