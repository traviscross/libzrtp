/*
 * libZRTP SDK library, implements the ZRTP secure VoIP protocol.
 * Copyright (c) 2006-2009 Philip R. Zimmermann.  All rights reserved.
 * Contact: http://philzimmermann.com
 * For licensing and other legal details, see the file zrtp_legal.c.
 *
 * Viktor Krykun <v.krikun at zfoneproject.com>
 */

/**
 * \file zrtp_cache_file.h
 * \brief file-based zrtp cache implementation
 */

#ifndef __ZRTP_CACHE_FILE_H__
#define __ZRTP_CACHE_FILE_H__

#include "zrtp_config.h"
#include "zrtp_base.h"
#include "zrtp_string.h"
#include "zrtp_error.h"

#include "zrtp_cache.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#define ZRTP_DEF_CACHE_VERSION_STR	"libZRTP cache version="
#define ZRTP_DEF_CACHE_VERSION_VAL	"1.0"

#define ZRTP_CACHE_FILE_DEF_PATH	"./zrtp_def_cache_path.dat"

#define ZRTP_CACHE_STRLEN			256

typedef struct zrtp_cache_file_t zrtp_cache_file_t;

typedef struct {
	/**
	 * Path to ZRTP cache file. If file doesn't exist it will be created.
	 * Default is ZRTP_CACHE_FILE_DEF_PATH.
	 */
	char 	cache_path[256];

	/**
	 * @brief Flush the cache automatically
	 * Set to 1 if you want libzrtp to flush the cache to the persistent storage
	 * right after it was modified. If cache_autho_store is 0, libzrtp will flush
	 * the cache on going down only and the app is responsible for storing the
	 * cache in unexpected situations. Enabled by default.
	 *
	 * @sa zrtp_def_cache_store()
	 */
	unsigned				cache_auto_store;
} zrtp_cache_file_config_t;

zrtp_status_t zrtp_cache_file_create(zrtp_stringn_t *local_zid,
		zrtp_cache_file_config_t *config,
		zrtp_cache_file_t **cache);

zrtp_status_t zrtp_cache_file_destroy(zrtp_cache_file_t *cache);

#if defined(__cplusplus)
}
#endif

#endif /*__ZRTP_CACHE_FILE_H__*/
