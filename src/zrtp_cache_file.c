/*
 * libZRTP SDK library, implements the ZRTP secure VoIP protocol.
 * Copyright (c) 2006-2012 Philip R. Zimmermann.  All rights reserved.
 * Contact: http://philzimmermann.com
 * For licensing and other legal details, see the file zrtp_legal.c.
 *
 * Viktor Krykun <v.krikun at zfoneproject.com>
 */

#include "zrtp_cache_file.h"
#include "zrtp_list.h"
#include "zrtp_string.h"
#include "zrtp.h" /* for zid definition */


#include <stdio.h>	/* for file operations*/
#include <string.h> /* for strlen() and other string operations*/


#define _ZTU_ "zrtp cache"

/**  ZRTP file-based cache */
struct zrtp_cache_file_t {
	zrtp_cache_t	super_;						/**! ZRTP cache super class. @warning must be the first field. */
	zrtp_string16_t	local_zid;					/**! local ZID */
	zrtp_cache_file_config_t	config;			/**! copy of initialization config */
	zrtp_global_t	*zrtp;						/**! zrtp context */
	mlist_t 		cache_head;					/**! head of mian cache list */
	uint32_t		cache_elems_counter;		/**! global counter of zrtp cache entries create by this cache  */
	mlist_t 		mitmcache_head;				/**! PBX cache entries list */
	uint32_t		mitmcache_elems_counter;	/**! global counter of MiTM cache entries create by this cache  */
	uint8_t 		needs_rewriting;
	zrtp_mutex_t 	*cache_protector;			/**! mutex to protect operations with cache elemnts list */
};

/**
 * @brief Cache element identifier type
 * Elements of this type link cache data with a pair of ZIDs.
 * (constructed as: [ZID1][ZID2], where ZID1 - ZID with greater binary value)
 * This type is used to identify cache elements in the built-in implementation.
 */
typedef uint8_t zrtp_cache_entry_id_t[24];

/**
 * @brief Secret cache element structure
 * This structure is used to store cache data in the built-in implementation
 * of the caching system.
 */
typedef struct
{
	zrtp_cache_entry_id_t    	id;		/** Cache element identifier */
	zrtp_string64_t    	curr_cache;		/** Current cache value */
	zrtp_string64_t    	prev_cache;		/** Prev cache value */
	uint32_t           	verified;		/** Verified flag for the cache value */
	uint32_t		   	lastused_at;	/** Last usage time-stamp in seconds */
	uint32_t			ttl;			/** Cache TTL since lastused_at in seconds */
	uint32_t           	secure_since;	/** Secure since date in seconds. Utility field. Don't required by libzrtp. */
	char				name[ZFONE_CACHE_NAME_LENGTH]; /** name of the user associated with this cache entry */
	uint32_t           	name_length;	/** cache name lengths */
	uint32_t			presh_counter;	/** number of Preshared streams made since last DH exchange */
	uint32_t			_index;			/** cache element index in the cache file */
	uint32_t			_is_dirty;		/** dirty flag means the entry has unsaved changes */
	mlist_t            	_mlist;
} zrtp_cache_entry_t;


#define ZRTP_MITMCACHE_ELEM_LENGTH ( sizeof(zrtp_cache_entry_id_t) + sizeof(zrtp_string64_t) )
#define ZRTP_CACHE_ELEM_LENGTH ( sizeof(zrtp_cache_entry_t) - sizeof(mlist_t) - (sizeof(uint32_t)*2) )


#define ZRTP_CACHE_CHECK_ZID(zid) \
	if (zid->length != sizeof(zrtp_zid_t)) \
	{ \
		return zrtp_status_bad_param; \
	}

/** Create cache ID like a pair of ZIDs. ZID with lowest value at the beginning */
static void zrtp_cache_create_id(const zrtp_stringn_t* first_ZID,
		const zrtp_stringn_t* second_ZID,
		zrtp_cache_entry_id_t id);

/** Searching for cache element by cache ID */
static zrtp_cache_entry_t* get_elem(zrtp_cache_file_t *cache_file, const zrtp_cache_entry_id_t id, uint8_t is_mitm);

static void zrtp_cache_entry_make_cross(zrtp_cache_entry_t* from, zrtp_cache_entry_t* to, uint8_t is_upload);

/** Opens zrtp cache file and upload all entries  */
static zrtp_status_t zrtp_cache_read_from_file(zrtp_cache_file_t *cache_file);

/** Flush dirty (modified) cache entries to the file */
static zrtp_status_t zrtp_cache_store_to_file(zrtp_cache_file_t *cache_file);


/******************************************************************************
 * libzrtp cache interface implementation
 */

static zrtp_status_t cache_put(zrtp_cache_file_t *cache_file,
		const zrtp_stringn_t* remote_zid,
		zrtp_shared_secret_t *rss,
		uint8_t is_mitm )
{
    zrtp_cache_entry_t* new_elem = 0;
	zrtp_cache_entry_id_t	id;

	ZRTP_CACHE_CHECK_ZID(remote_zid);
	zrtp_cache_create_id(ZSTR_GV(cache_file->local_zid), remote_zid, id);

	{
	char zidstr[24+1];
	ZRTP_LOG(3,(_ZTU_,"\tcache_put() remote ZID %s MiTM=%s\n",
			hex2str(remote_zid->buffer, remote_zid->length, zidstr, sizeof(zidstr)),
			is_mitm?"YES":"NO"));
	}

	zrtp_mutex_lock(cache_file->cache_protector);
	do {
		new_elem = get_elem(cache_file, id, is_mitm);
		if (!new_elem)
		{
			/* If cache doesn't exist - create new one */
			if (!( new_elem = (zrtp_cache_entry_t*) zrtp_sys_alloc(sizeof(zrtp_cache_entry_t)) ))	{
				break;
			}

			zrtp_memset(new_elem, 0, sizeof(zrtp_cache_entry_t));
			ZSTR_SET_EMPTY(new_elem->curr_cache);
			ZSTR_SET_EMPTY(new_elem->prev_cache);

			new_elem->secure_since = (uint32_t)(zrtp_time_now()/1000);

			mlist_add_tail(is_mitm ? &cache_file->mitmcache_head : &cache_file->cache_head, &new_elem->_mlist);
			zrtp_memcpy(new_elem->id, id, sizeof(zrtp_cache_entry_id_t));

			if (is_mitm) {
				new_elem->_index = cache_file->mitmcache_elems_counter++;
			} else {
				new_elem->_index = cache_file->cache_elems_counter++;
			}

			ZRTP_LOG(3,(_ZTU_,"\tcache_put() can't find element in the cache - create a new entry index=%u.\n", new_elem->_index));
		}
		else {
			ZRTP_LOG(3,(_ZTU_,"\tcache_put() Just update existing value.\n"));
		}

		/* Save current cache value as previous one and new as a current */
		if (!is_mitm) {
			if (new_elem->curr_cache.length > 0) {
				zrtp_zstrcpy(ZSTR_GV(new_elem->prev_cache), ZSTR_GV(new_elem->curr_cache));
			}
		}

		zrtp_zstrcpy(ZSTR_GV(new_elem->curr_cache), ZSTR_GV(rss->value));
		new_elem->lastused_at	= rss->lastused_at;
		if (!is_mitm) {
			new_elem->ttl		= rss->ttl;
		}

		new_elem->_is_dirty = 1;
		if (is_mitm) {
			cache_file->needs_rewriting = 1;
		}
	} while (0);

	if (cache_file->config.cache_auto_store) zrtp_cache_store_to_file(cache_file);

	zrtp_mutex_unlock(cache_file->cache_protector);

    return (new_elem) ? zrtp_status_ok : zrtp_status_fail;
}

static zrtp_status_t zrtp_file_cache_put(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		zrtp_shared_secret_t *rss) {
	zrtp_cache_file_t *cache_file = (zrtp_cache_file_t *)cache;
	return cache_put(cache_file, remote_zid, rss, 0);
}

static zrtp_status_t zrtp_file_cache_put_mitm(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		zrtp_shared_secret_t *rss) {
	zrtp_cache_file_t *cache_file = (zrtp_cache_file_t *)cache;
	return cache_put(cache_file, remote_zid, rss, 1);
}


static zrtp_status_t cache_get(zrtp_cache_file_t *cache_file,
		const zrtp_stringn_t* remote_zid,
		zrtp_shared_secret_t *rss,
		int prev_requested,
		uint8_t is_mitm)
{
    zrtp_cache_entry_t* curr = 0;
	zrtp_cache_entry_id_t	id;
	zrtp_status_t s = zrtp_status_ok;

	{
	char zidstr[24+1];
	ZRTP_LOG(3,(_ZTU_,"\tache_get(): remote ZID %s MiTM=%s\n",
			hex2str(remote_zid->buffer, remote_zid->length, zidstr, sizeof(zidstr)),
			is_mitm?"YES":"NO"));
	}

	ZRTP_CACHE_CHECK_ZID(remote_zid);
	zrtp_cache_create_id(ZSTR_GV(cache_file->local_zid), remote_zid, id);

	zrtp_mutex_lock(cache_file->cache_protector);
    do {
		curr = get_elem(cache_file, id, is_mitm);
		if (!curr || (!curr->prev_cache.length && prev_requested)) {
			s = zrtp_status_fail;
			ZRTP_LOG(3,(_ZTU_,"\tache_get() - not found.\n"));
			break;
		}

		zrtp_zstrcpy( ZSTR_GV(rss->value),
					  prev_requested ? ZSTR_GV(curr->prev_cache) : ZSTR_GV(curr->curr_cache));

		rss->lastused_at = curr->lastused_at;
		if (!is_mitm) {
			rss->ttl = curr->ttl;
		}
	} while (0);
	zrtp_mutex_unlock(cache_file->cache_protector);

    return s;
}

static zrtp_status_t zrtp_file_cache_get(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		zrtp_shared_secret_t *rss,
		int prev_requested)
{
	zrtp_cache_file_t *cache_file = (zrtp_cache_file_t *)cache;
	return cache_get(cache_file, remote_zid, rss, prev_requested, 0);
}

zrtp_status_t zrtp_file_cache_get_mitm(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		zrtp_shared_secret_t *rss)
{
	zrtp_cache_file_t *cache_file = (zrtp_cache_file_t *)cache;
	return cache_get(cache_file, remote_zid, rss, 0, 1);
}


static zrtp_status_t zrtp_file_cache_set_verified(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		uint32_t verified)
{
	zrtp_cache_file_t *cache_file = (zrtp_cache_file_t *)cache;
	zrtp_cache_entry_id_t	id;
	zrtp_cache_entry_t* new_elem = NULL;

	ZRTP_CACHE_CHECK_ZID(remote_zid);
	zrtp_cache_create_id(ZSTR_GV(cache_file->local_zid), remote_zid, id);

	zrtp_mutex_lock(cache_file->cache_protector);
	new_elem = get_elem(cache_file, id, 0);
	if (new_elem) {
		new_elem->verified = verified;

		new_elem->_is_dirty = 1;
		if (cache_file->config.cache_auto_store) zrtp_cache_store_to_file(cache_file);
	}

	zrtp_mutex_unlock(cache_file->cache_protector);

	return (new_elem) ? zrtp_status_ok : zrtp_status_fail;
}

zrtp_status_t zrtp_file_cache_get_verified(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		uint32_t* verified)

{
	zrtp_cache_file_t *cache_file = (zrtp_cache_file_t *)cache;
	zrtp_cache_entry_id_t	id;
	zrtp_cache_entry_t* elem = NULL;

	ZRTP_CACHE_CHECK_ZID(remote_zid);
	zrtp_cache_create_id(ZSTR_GV(cache_file->local_zid), remote_zid, id);

	zrtp_mutex_lock(cache_file->cache_protector);
	elem = get_elem(cache_file, id, 0);
	if (elem) {
		*verified = elem->verified;
	}
	zrtp_mutex_unlock(cache_file->cache_protector);

	return (elem) ? zrtp_status_ok : zrtp_status_fail;
}


/******************************************************************************
 * ZRTP cache extended functions
 */

#define ZRTP_FILE_CACHE_UTIL_START \
	zrtp_cache_file_t *cache_file = (zrtp_cache_file_t *)cache; \
	zrtp_cache_entry_t* new_elem = 0; \
	zrtp_cache_entry_id_t	id; \
	\
	ZRTP_CACHE_CHECK_ZID(remote_zid); \
	zrtp_cache_create_id(ZSTR_GV(cache_file->local_zid), remote_zid, id);

static zrtp_status_t zrtp_file_cache_get_since(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		uint32_t* since)
{
	ZRTP_FILE_CACHE_UTIL_START;

	zrtp_mutex_lock(cache_file->cache_protector);
	new_elem = get_elem(cache_file, id, 0);
	if (new_elem) {
		*since = new_elem->secure_since;
	}
	zrtp_mutex_unlock(cache_file->cache_protector);

	return (new_elem) ? zrtp_status_ok : zrtp_status_fail;
}

static zrtp_status_t zrtp_file_cache_reset_since(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid)
{
	ZRTP_FILE_CACHE_UTIL_START;

	zrtp_mutex_lock(cache_file->cache_protector);
	new_elem = get_elem(cache_file, id, 0);
	if (new_elem) {
		new_elem->secure_since = (uint32_t)(zrtp_time_now()/1000);
		new_elem->_is_dirty = 1;
	}

	if (cache_file->config.cache_auto_store) zrtp_cache_store_to_file(cache_file);

	zrtp_mutex_unlock(cache_file->cache_protector);

	return (new_elem) ? zrtp_status_ok : zrtp_status_fail;
}

static zrtp_status_t zrtp_file_cache_get_name(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		zrtp_stringn_t* name)
{
	zrtp_status_t s = zrtp_status_fail;

	ZRTP_FILE_CACHE_UTIL_START;

	zrtp_mutex_lock(cache_file->cache_protector);
	do {
		new_elem = get_elem(cache_file, id, 0);
		if (!new_elem) {
			s = zrtp_status_fail;
			break;
		}

		name->length = new_elem->name_length;
		zrtp_memcpy(name->buffer, new_elem->name, name->length);
		s = zrtp_status_ok;
	} while (0);
	zrtp_mutex_unlock(cache_file->cache_protector);

	return s;
}

static zrtp_status_t zrtp_file_cache_put_name(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		const zrtp_stringn_t* name)
{
	zrtp_status_t s = zrtp_status_ok;

	ZRTP_FILE_CACHE_UTIL_START;

	zrtp_mutex_lock(cache_file->cache_protector);
	do {
		new_elem = get_elem(cache_file, id, 0);
		if (!new_elem) {
			s = zrtp_status_fail;
			break;
		}

		/* Update regular cache name*/
		new_elem->name_length = ZRTP_MIN(name->length, ZFONE_CACHE_NAME_LENGTH-1);
		zrtp_memset(new_elem->name, 0, sizeof(new_elem->name));
		zrtp_memcpy(new_elem->name, name->buffer, new_elem->name_length);

		new_elem->_is_dirty = 1;
	} while (0);

	if (cache_file->config.cache_auto_store) zrtp_cache_store_to_file(cache_file);

	zrtp_mutex_unlock(cache_file->cache_protector);

	return s;
}

static zrtp_status_t zrtp_file_cache_set_presh_counter(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		uint32_t counter)
{
	ZRTP_FILE_CACHE_UTIL_START;

	zrtp_mutex_lock(cache_file->cache_protector);
	new_elem = get_elem(cache_file, id, 0);
	if (new_elem) {
		new_elem->presh_counter = counter;

		new_elem->_is_dirty = 1;
	}

	if (cache_file->config.cache_auto_store) zrtp_cache_store_to_file(cache_file);

	zrtp_mutex_unlock(cache_file->cache_protector);

	return (new_elem) ? zrtp_status_ok : zrtp_status_fail;
}

zrtp_status_t zrtp_file_cache_get_presh_counter(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		uint32_t* counter)
{
	ZRTP_FILE_CACHE_UTIL_START;

	zrtp_mutex_lock(cache_file->cache_protector);
	new_elem = get_elem(cache_file, id, 0);
	if (new_elem) {
		*counter = new_elem->presh_counter;
	}
	zrtp_mutex_unlock(cache_file->cache_protector);

	return (new_elem) ? zrtp_status_ok : zrtp_status_fail;
}



/******************************************************************************
 * Public API
 */

zrtp_status_t zrtp_cache_file_create(zrtp_stringn_t *local_zid,
		zrtp_cache_file_config_t *config,
		zrtp_cache_file_t **cache) {

	zrtp_status_t s;
	zrtp_cache_file_t *new_cache;

	new_cache = zrtp_sys_alloc(sizeof(zrtp_cache_file_t));
	zrtp_memset(new_cache, 0, sizeof(zrtp_cache_file_t));

	new_cache->super_.type = ZRTP_CACHE_FILE;
	new_cache->super_.op.get = &zrtp_file_cache_get;
	new_cache->super_.op.get_mitm = &zrtp_file_cache_get_mitm;
	new_cache->super_.op.put = &zrtp_file_cache_put;
	new_cache->super_.op.put_mitm = &zrtp_file_cache_put_mitm;
	new_cache->super_.op.get_verified = &zrtp_file_cache_get_verified;
	new_cache->super_.op.set_verified = &zrtp_file_cache_set_verified;

	new_cache->super_.op_ext.get_name = &zrtp_file_cache_get_name;
	new_cache->super_.op_ext.put_name = &zrtp_file_cache_put_name;
	new_cache->super_.op_ext.get_secure_since = &zrtp_file_cache_get_since;
	new_cache->super_.op_ext.reset_secure_since = &zrtp_file_cache_reset_since;
	new_cache->super_.op_ext.get_presh_counter = &zrtp_file_cache_get_presh_counter;
	new_cache->super_.op_ext.set_presh_counter = &zrtp_file_cache_set_presh_counter;

	zrtp_memcpy(&new_cache->config, config, sizeof(zrtp_cache_file_config_t));
	zrtp_zstrcpy(ZSTR_GV(new_cache->local_zid), local_zid);

	do {
		s = zrtp_mutex_init(&new_cache->cache_protector);
		if (zrtp_status_ok != s) {
			break;
		}

		init_mlist(&new_cache->cache_head);
		init_mlist(&new_cache->mitmcache_head);

		/* let's upload cache entries form the file */
		s = zrtp_cache_read_from_file(new_cache);
		if (zrtp_status_ok != s) {
			break;
		}

		s = zrtp_status_ok;
	} while (0);

	if (zrtp_status_ok != s) {
		if (new_cache) {
			if (new_cache->cache_protector)
				zrtp_mutex_destroy(new_cache->cache_protector);

			zrtp_sys_free(new_cache);
		}
	} else {
		*cache = new_cache;
	}

	return s;
}

zrtp_status_t zrtp_cache_file_destroy(zrtp_cache_file_t *cache) {
	mlist_t *node = NULL, *tmp = NULL;

	if (!cache)
		return zrtp_status_bad_param;

	zrtp_mutex_lock(cache->cache_protector);

	/* If automatic cache flushing enabled we don't need to store it in a disk as it should be already in sync. */
	if (!cache->config.cache_auto_store) {
		zrtp_cache_store_to_file(cache);
	}

	mlist_for_each_safe(node, tmp, &cache->cache_head) {
		zrtp_sys_free(mlist_get_struct(zrtp_cache_entry_t, _mlist, node));
	}
	mlist_for_each_safe(node, tmp, &cache->mitmcache_head) {
		zrtp_sys_free(mlist_get_struct(zrtp_cache_entry_t, _mlist, node));
	}

	zrtp_mutex_unlock(cache->cache_protector);

	zrtp_mutex_destroy(cache->cache_protector);

	zrtp_sys_free(cache);

	return zrtp_status_ok;
}

/******************************************************************************
 * File storage operations
 */

#define ZRTP_INT_CACHE_BREAK(s, status) \
{ \
	if (!s) s = status; \
	break; \
}

static zrtp_status_t zrtp_cache_read_from_file(zrtp_cache_file_t *cache)
{
	FILE* 	cache_file = 0;
	zrtp_cache_entry_t* new_elem = 0;
	zrtp_status_t s = zrtp_status_ok;
	uint32_t cache_elems_count = 0;
	uint32_t mitmcache_elems_count = 0;
	uint32_t i = 0;
	unsigned is_unsupported = 0;

	ZRTP_LOG(3,(_ZTU_,"\tLoad ZRTP cache from <%s>...\n", cache->config.cache_path));

	cache->cache_elems_counter = 0;
	cache->mitmcache_elems_counter = 0;
	cache->needs_rewriting = 0;

    /* Try to open existing file. If there is no cache file - start with empty cache */
#if (ZRTP_PLATFORM == ZP_WIN32)
    if (0 != fopen_s(&cache_file, cache->config.cache_path, "rb")) {
		return zrtp_status_ok;
    }
#else
    if (0 == (cache_file = fopen(cache->config.cache_path , "rb"))) {
		ZRTP_LOG(3,(_ZTU_,"\tCan't open file for reading.\n"));
		return zrtp_status_ok;
	}
#endif
	/*
	 * Check for the cache file version number. Current version of libzrtp doesn't support
	 * backward compatibility in zrtp cache file structure, so we just remove the old cache file.
	 *
	 * Version field format: $ZRTP_DEF_CACHE_VERSION_STR$ZRTP_DEF_CACHE_VERSION_VAL
	 */
	do {
		char version_buff[256];
		zrtp_memset(version_buff, 0, sizeof(version_buff));

		if (fread(version_buff, strlen(ZRTP_DEF_CACHE_VERSION_STR)+strlen(ZRTP_DEF_CACHE_VERSION_VAL), 1, cache_file) <= 0) {
			ZRTP_LOG(2,(_ZTU_,"\tCache Error: Can't get ZRTP cache version string: file is too small.\n"));
			is_unsupported = 1;
			break;
		}

		if (0 != zrtp_memcmp(version_buff, ZRTP_DEF_CACHE_VERSION_STR, strlen(ZRTP_DEF_CACHE_VERSION_STR))) {
			ZRTP_LOG(2,(_ZTU_,"\tCache Error: malformed cache file: can't find ZRTP Version tag.\n"));
			is_unsupported = 1;
			break;
		}

		ZRTP_LOG(3,(_ZTU_,"\tZRTP cache file has version=%s\n", version_buff+strlen(ZRTP_DEF_CACHE_VERSION_STR)));

		if (0 != zrtp_memcmp(version_buff+strlen(ZRTP_DEF_CACHE_VERSION_STR), ZRTP_DEF_CACHE_VERSION_VAL, strlen(ZRTP_DEF_CACHE_VERSION_VAL))) {
			ZRTP_LOG(2,(_ZTU_,"\tCache Error: Unsupported ZRTP cache version.\n"));
			is_unsupported = 1;
			break;
		}
	} while (0);

	if (is_unsupported) {
		ZRTP_LOG(2,(_ZTU_,"\tCache Error: Unsupported version of ZRTP cache file detected - white-out the cache.\n"));
		fclose(cache_file);
		return zrtp_status_ok;
	}

	/*
	 *  Load MitM caches: first 32 bits is a MiTM secrets counter. Read it and then
	 *  upload appropriate number of MitM secrets.
	 */
	do {
		cache_elems_count = 0;
		if (fread(&mitmcache_elems_count, 4, 1, cache_file) <= 0) {
			ZRTP_INT_CACHE_BREAK(s, zrtp_status_read_fail);
		}
		mitmcache_elems_count = zrtp_ntoh32(mitmcache_elems_count);

		for (i=0; i<mitmcache_elems_count; i++)
		{
			new_elem = (zrtp_cache_entry_t*) zrtp_sys_alloc(sizeof(zrtp_cache_entry_t));
			if (!new_elem) {
				ZRTP_INT_CACHE_BREAK(s, zrtp_status_alloc_fail);
			}

			if (fread(new_elem, ZRTP_MITMCACHE_ELEM_LENGTH, 1, cache_file) <= 0) {
				ZRTP_LOG(3,(_ZTU_,"\tERROR! MiTM cache element read fail (id=%u).\n", i));

				zrtp_sys_free(new_elem);
				ZRTP_INT_CACHE_BREAK(s, zrtp_status_read_fail);
			}

			zrtp_cache_entry_make_cross(NULL, new_elem, 1);

			new_elem->_index =  cache->mitmcache_elems_counter++;
			new_elem->_is_dirty = 0;

			mlist_add_tail(&cache->mitmcache_head, &new_elem->_mlist);
		}

		if (i != mitmcache_elems_count)
			ZRTP_INT_CACHE_BREAK(s, zrtp_status_read_fail);
	} while(0);
	if (s != zrtp_status_ok) {
		fclose(cache_file);
		return s;
	}

	ZRTP_LOG(3,(_ZTU_,"\tAll %u MiTM Cache entries have been uploaded.\n", cache->mitmcache_elems_counter));

	/*
	 * Load regular caches: first 32 bits is a secrets counter. Read it and then
	 * upload appropriate number of regular secrets.
	 */
	cache_elems_count = 0;
	if (fread(&cache_elems_count, 4, 1, cache_file) <= 0) {
		fclose(cache_file);
		return zrtp_status_read_fail;
	}
	cache_elems_count = zrtp_ntoh32(cache_elems_count);

	for (i=0; i<cache_elems_count; i++)
	{
		new_elem = (zrtp_cache_entry_t*) zrtp_sys_alloc(sizeof(zrtp_cache_entry_t));
		if (!new_elem) {
			ZRTP_INT_CACHE_BREAK(s, zrtp_status_alloc_fail);
		}

		if (fread(new_elem, ZRTP_CACHE_ELEM_LENGTH, 1, cache_file) <= 0) {
			ZRTP_LOG(3,(_ZTU_,"\tERROR! RS cache element read fail (id=%u).\n", i));
			zrtp_sys_free(new_elem);
			ZRTP_INT_CACHE_BREAK(s, zrtp_status_read_fail);
		}

		zrtp_cache_entry_make_cross(NULL, new_elem, 1);

		new_elem->_index = cache->cache_elems_counter++;
		new_elem->_is_dirty = 0;

		mlist_add_tail(&cache->cache_head, &new_elem->_mlist);
	}
	if (i != cache_elems_count) {
		s = zrtp_status_read_fail;
	}

    if (0 != fclose(cache_file)) {
		return zrtp_status_fail;
    }

	ZRTP_LOG(3,(_ZTU_,"\tAll of %u RS Cache entries have been uploaded.\n", cache->cache_elems_counter));

	return s;
}


#define ZRTP_DOWN_CACHE_RETURN(s, f, c) \
{\
	if (zrtp_status_ok != s) \
		ZRTP_LOG(3,(_ZTU_,"\tERROR! Unable to writing to ZRTP cache file.\n")); \
	if (f) \
		fclose(f);\
	return s;\
};

static zrtp_status_t flush_elem_(zrtp_cache_file_t *cache, zrtp_cache_entry_t *elem, FILE *cache_file, unsigned is_mitm) {
	zrtp_cache_entry_t tmp_elem;
	uint32_t pos;

	/*
	 * Let's calculate cache element position in the file
	 */

	/* Skip the header */
	pos = 0;
	pos += strlen(ZRTP_DEF_CACHE_VERSION_STR)+strlen(ZRTP_DEF_CACHE_VERSION_VAL); /* Skip cache version string */
	pos += sizeof(uint32_t); /* Skip MiTM secretes count. */

	//printf("flush_elem_(): \t pos=%u (Header, MiTM Count).\n", pos);

	if (is_mitm) {
		/* position within MiTM secrets block. */
		pos += (elem->_index * ZRTP_MITMCACHE_ELEM_LENGTH);
		//printf("flush_elem_(): \t pos=%u (Header, MiTM Count + %u MiTM Secrets).\n", pos, elem->_index);
	} else {
		/* Skip MiTM Secrets block */
		pos += (cache->mitmcache_elems_counter * ZRTP_MITMCACHE_ELEM_LENGTH);

		pos += sizeof(uint32_t); /* Skip RS elements count. */

		pos += (elem->_index * ZRTP_CACHE_ELEM_LENGTH); /* Skip previous RS elements */

		//printf("flush_elem_(): \t pos=%u (Header, MiTM Count + ALL %u Secrets, RS counter and %u prev. RS).\n", pos, cache->mitmcache_elems_counter, elem->_index);
	}

	fseek(cache_file, pos, SEEK_SET);

	/* Prepare element for storing, convert all fields to the network byte-order. */
	zrtp_cache_entry_make_cross(elem, &tmp_elem, 0);

	//printf("flush_elem_(): write to offset=%lu\n", ftell(cache_file));

	/* Flush the element. */
	if (fwrite(&tmp_elem, (is_mitm ? ZRTP_MITMCACHE_ELEM_LENGTH : ZRTP_CACHE_ELEM_LENGTH), 1, cache_file) != 1) {
		//printf("flush_elem_(): ERROR!!! write failed!\n");
		return zrtp_status_write_fail;
	} else {
		elem->_is_dirty = 0;
		//printf("flush_elem_(): OK! %lu bytes were written\n", (is_mitm ? ZRTP_MITMCACHE_ELEM_LENGTH : ZRTP_CACHE_ELEM_LENGTH));
		return zrtp_status_ok;
	}
}

static zrtp_status_t zrtp_cache_store_to_file(zrtp_cache_file_t *cache)
{
	FILE* cache_file = 0;
	mlist_t *node = 0;
	uint32_t count = 0, dirty_count=0;
	uint32_t pos = 0;

	ZRTP_LOG(3,(_ZTU_,"\tStoring ZRTP cache to <%s>...\n",  cache->config.cache_path));

    /* Open/create file for writing */
#if (ZRTP_PLATFORM == ZP_WIN32)
    if (g_needs_rewriting || 0 != fopen_s(&cache_file, cache->config.cache_path, "r+")) {
		if (0 != fopen_s(&cache_file, cache->config.cache_path, "w+")) {
			ZRTP_LOG(2,(_ZTU_,"\tERROR! unable to open ZRTP cache file <%s>.\n", cache->config.cache_path));
			ZRTP_DOWN_CACHE_RETURN(zrtp_status_open_fail, cache_file, cache);
		}
    }
#else
	if (cache->needs_rewriting || !(cache_file = fopen(cache->config.cache_path, "r+"))) {
		cache_file = fopen(cache->config.cache_path, "w+");
		if (!cache_file) {
			ZRTP_LOG(2,(_ZTU_,"\tERROR! unable to open ZRTP cache file <%s>.\n", cache->config.cache_path));
			ZRTP_DOWN_CACHE_RETURN(zrtp_status_open_fail, cache_file, cache);
		}
	}
#endif

	fseek(cache_file, 0, SEEK_SET);

	/* Store version string first. Format: &ZRTP_DEF_CACHE_VERSION_STR&ZRTP_DEF_CACHE_VERSION_VAL */
	if (1 != fwrite(ZRTP_DEF_CACHE_VERSION_STR, strlen(ZRTP_DEF_CACHE_VERSION_STR), 1, cache_file)) {
		ZRTP_LOG(2,(_ZTU_,"\tERROR! unable to write header to the cache file\n"));
		ZRTP_DOWN_CACHE_RETURN(zrtp_status_write_fail, cache_file, cache);
	}
	if (1 != fwrite(ZRTP_DEF_CACHE_VERSION_VAL, strlen(ZRTP_DEF_CACHE_VERSION_VAL), 1, cache_file)) {
		ZRTP_LOG(2,(_ZTU_,"\tERROR! unable to write header to the cache file\n"));
		ZRTP_DOWN_CACHE_RETURN(zrtp_status_write_fail, cache_file, cache);
	}

    /*
	 * Store PBX secrets first. Format: <secrets count>, <secrets' data>
	 *
	 * NOTE!!! It's IMPORTANT to store PBX secrets before the Regular secrets!!!
	 */
	pos = ftell(cache_file);

	count = 0; dirty_count = 0;
	fwrite(&count, sizeof(count), 1, cache_file);

	mlist_for_each(node, &cache->mitmcache_head) {
		zrtp_cache_entry_t* elem = mlist_get_struct(zrtp_cache_entry_t, _mlist, node);
		/* Store dirty values only. */
		if (cache->needs_rewriting || elem->_is_dirty) {
			//printf("zrtp_cache_store_to_file: Store MiTM elem index=%u.\n", elem->_index);
			dirty_count++;
			if (zrtp_status_ok != flush_elem_(cache, elem, cache_file, 1)) {
				ZRTP_DOWN_CACHE_RETURN(zrtp_status_write_fail, cache_file, cache);
			}
		} else {
			//printf("zrtp_cache_store_to_file: Skip MiTM elem index=%u, not modified.\n", elem->_index);
		}
	}

	fseek(cache_file, pos, SEEK_SET);

	count = zrtp_hton32(cache->mitmcache_elems_counter);
	if (fwrite(&count, sizeof(count), 1, cache_file) != 1) {
		ZRTP_DOWN_CACHE_RETURN(zrtp_status_write_fail, cache_file, cache);
	}

	if (dirty_count > 0)
		ZRTP_LOG(3,(_ZTU_,"\t%u out of %u MiTM cache entries have been flushed successfully.\n", dirty_count, zrtp_ntoh32(count)));

	/*
	 * Store regular secrets. Format: <secrets count>, <secrets' data>
	 */

	/* Seek to the beginning of the Regular secrets block */
	pos = strlen(ZRTP_DEF_CACHE_VERSION_STR)+strlen(ZRTP_DEF_CACHE_VERSION_VAL);
	pos += sizeof(uint32_t); /* Skip MiTM secrets count. */
	pos += (cache->mitmcache_elems_counter * ZRTP_MITMCACHE_ELEM_LENGTH); /* Skip MiTM Secrets block */

	fseek(cache_file, pos, SEEK_SET);

	count = 0; dirty_count=0;
	fwrite(&count, sizeof(count), 1, cache_file);

	mlist_for_each(node, &cache->cache_head) {
		zrtp_cache_entry_t* elem = mlist_get_struct(zrtp_cache_entry_t, _mlist, node);

		/* Store dirty values only. */
		if (cache->needs_rewriting || elem->_is_dirty) {
			//printf("zrtp_cache_user_down: Store RS elem index=%u.\n", elem->_index);
			dirty_count++;
			if (zrtp_status_ok != flush_elem_(cache, elem, cache_file, 0)) {
				ZRTP_DOWN_CACHE_RETURN(zrtp_status_write_fail, cache_file, cache);
			}
		}
 		else {
 			//printf("zrtp_cache_user_down: Skip RS elem index=%u, not modified.\n", elem->_index);
		 }
	}

	fseek(cache_file, pos, SEEK_SET);

	count = zrtp_hton32(cache->cache_elems_counter);
	if (fwrite(&count, sizeof(count), 1, cache_file) != 1) {
		ZRTP_DOWN_CACHE_RETURN(zrtp_status_write_fail, cache_file, cache);
	}

	if (dirty_count > 0)
		ZRTP_LOG(3,(_ZTU_,"\t%u out of %u regular cache entries have been flushed successfully.\n", dirty_count, zrtp_ntoh32(count)));

	cache->needs_rewriting = 0;

	ZRTP_DOWN_CACHE_RETURN(zrtp_status_ok, cache_file, cache);
	return zrtp_status_ok;
}


/******************************************************************************
 * Helpers
 *
 */
static void zrtp_cache_create_id(const zrtp_stringn_t* first_ZID,
		const zrtp_stringn_t* second_ZID,
		zrtp_cache_entry_id_t id )
{
	if (0 < zrtp_memcmp(first_ZID->buffer, second_ZID->buffer, sizeof(zrtp_zid_t))) {
		const zrtp_stringn_t* tmp_ZID = first_ZID;
		first_ZID = second_ZID;
		second_ZID = tmp_ZID;
	}

	zrtp_memcpy(id, first_ZID->buffer, sizeof(zrtp_zid_t));
	zrtp_memcpy((char*)id+sizeof(zrtp_zid_t), second_ZID->buffer, sizeof(zrtp_zid_t));
}

static zrtp_cache_entry_t* get_elem(zrtp_cache_file_t *cache_file,
		const zrtp_cache_entry_id_t id,
		uint8_t is_mitm)
{
	mlist_t* node = NULL;
	mlist_t* head = is_mitm ? &cache_file->mitmcache_head : &cache_file->cache_head;
	mlist_for_each(node, head) {
		zrtp_cache_entry_t* elem = mlist_get_struct(zrtp_cache_entry_t, _mlist, node);
		if (!zrtp_memcmp(elem->id, id, sizeof(zrtp_cache_entry_id_t))) {
			return elem;
		}
   }

   return NULL;
}

static void zrtp_cache_entry_make_cross(zrtp_cache_entry_t* from, zrtp_cache_entry_t* to, uint8_t is_upload)
{
	if (!to)
		return;

	if (from)
		zrtp_memcpy(to, from, sizeof(zrtp_cache_entry_t));

	if (is_upload) {
		to->verified 	= zrtp_ntoh32(to->verified);
		to->secure_since= zrtp_ntoh32(to->secure_since);
		to->lastused_at = zrtp_ntoh32(to->lastused_at);
		to->ttl			= zrtp_ntoh32(to->ttl);
		to->name_length	= zrtp_ntoh32(to->name_length);
		to->curr_cache.length = zrtp_ntoh16(to->curr_cache.length);
		to->prev_cache.length = zrtp_ntoh16(to->prev_cache.length);
		to->presh_counter	= zrtp_ntoh32(to->presh_counter);
	} else {
		to->verified	= zrtp_hton32(to->verified);
		to->secure_since= zrtp_hton32(to->secure_since);
		to->lastused_at = zrtp_hton32(to->lastused_at);
		to->ttl			= zrtp_hton32(to->ttl);
		to->name_length	= zrtp_hton32(to->name_length);
		to->curr_cache.length = zrtp_hton16(to->curr_cache.length);
		to->prev_cache.length = zrtp_hton16(to->prev_cache.length);
		to->presh_counter	= zrtp_hton32(to->presh_counter);
	}
}

