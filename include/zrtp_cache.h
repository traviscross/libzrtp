/*
 * libZRTP SDK library, implements the ZRTP secure VoIP protocol.
 * Copyright (c) 2006-2009 Philip R. Zimmermann.  All rights reserved.
 * Contact: http://philzimmermann.com
 * For licensing and other legal details, see the file zrtp_legal.c.
 *
 * Viktor Krykun <v.krikun at zfoneproject.com>
 */

/**
 * \file zrtp_cache.h
 * \brief libzrtp zrtp cache interface
 */

#ifndef __ZRTP_CACHE_H__
#define __ZRTP_CACHE_H__

#include "zrtp_config.h"
#include "zrtp_base.h"
#include "zrtp_string.h"
#include "zrtp_error.h"

#if defined(__cplusplus)
extern "C"
{
#endif

/** ZRTP cache forward declaration */
typedef struct zrtp_cache_t zrtp_cache_t;

/** Defines types of zrtp caches libzrtp supports out of the box */
typedef enum {
	ZRTP_CACHE_FILE = 0,	/** File-based ZRTP cache implementation */
	ZRTP_CACHE_SQLITE,		/** SQLite based cache backend \sa zrtp_cache_set() */
	ZRTP_CACHE_CUSTOM		/** user-provided ZRTP cache \sa zrtp_cache_set() */
} zrtp_cache_type_t;


/**
 * \brief Shared secret structure
 * \ingroup zrtp_iface_cache
 *
 * This structure stores ZRTP shared secret values used in the protocol.
 */
struct zrtp_shared_secret_t
{
    /** \brief ZRTP secret value */
    zrtp_string64_t			value;

	/**
	 * \brief last usage time-stamp in seconds.
	 *
	 * Library updates this value on generation of the new value based on previous one.
	 */
	uint32_t				lastused_at;

	/**
	 * \brief TTL value in seconds.
	 *
	 * Available for reading after the Hello exchange. Updated on switching to Secure state.
	 */
	uint32_t				ttl;

	/**
     * \brief Loaded secret flag.
     *
     * When the flag is set (= 1), the secret has been loaded from the cache. Otherwise the secret
     * has been generated.
     * \warning For internal use only. Don't modify this flag in the application.
     */
    uint8_t					_cachedflag;
};

/**
 * \brief Defines minimal and required set of ZRTP cache operations
 */
typedef struct {
	/**
	 * \brief Add/Update cache value
	 *
	 * Interface function for entering the retained secret to the cache. \c put function should
	 * guarantee permanent storage in the cache. The implementation algorithm is the following:
	 *  - if the entry associated with a given pair of ZIDs does not exist, the value should be
	 *    stored in cache.
	 *  - if the entry already exists, the current secret value becomes stored as the previous one.
	 *    The new value becomes stored as the current one. Besides rss->value a timestamp
	 *    (rss->lastused_at) and cache TTL(rss->ttl)  should be updated.
	 *
	 * \param one_zid - ZID of one side;
	 * \param remote_zid - ZID of the other side;
	 * \param rss - a structure storing the value of the secret that needs to be saved.
	 * \return
	 * - zrtp_status_ok if operation is successful;
	 * - some error code from \ref zrtp_status_t in case of error.
	 * \sa zrtp_callback_cache_t#on_get
	 */
	zrtp_status_t (*put)(zrtp_cache_t *cache,
			const zrtp_stringn_t* remote_zid,
			zrtp_shared_secret_t *rss);

	/**
	 * \brief Return secret cache associated with specified pair of ZIDs.
	 *
	 * This function should return the secret associated with the specified pair of ZIDs. In
	 * addition to the secret value, TTL (rss->ttl) and cache timestamp (rss->lastused_at) value
	 * should be also returned.
	 *
	 * \param one_zid - one side's ZID;
	 * \param remote_zid - the other side's ZID;
	 * \param prev_requested - if this parameter value is 1, the function should return the previous
	 *    secret's value. If this parameter value is 0, the function should return the current
	 *    secret's value;
	 * \param rss - structure that needs to be filled in.
	 * \return
	 *  - zrtp_status_ok - if operation is successful;
	 *  - zrtp_status_fail - if the secret cannot be found;
	 *  - some error code from zrtp_status_t if an error occurred.
	 * \sa zrtp_callback_cache_t#on_put
	 */
	zrtp_status_t (*get)(zrtp_cache_t *cache,
			const zrtp_stringn_t* remote_zid,
			zrtp_shared_secret_t *rss,
			int prev_requested);

	/**
	 * \brief Set/clear cache verification flag
	 *
	 * This function should set the secret verification flag associated with a pair of ZIDs.
	 * \warning
	 *   For internal use only. To change the verification flag from the user space use the
	 *   zrtp_verified_set() function.
	 *
	 * \param one_zid - first ZID for cache identification;
	 * \param remote_zid - second ZID for cache identification;
	 * \param verified - verification flag (value can be 0 or 1).
	 * \return
	 *  - zrtp_status_ok if flag is successfully modified;
	 *  - zrtp_status_fail if the secret cannot be found;
	 *  - some other error code from \ref zrtp_status_t if another error occurred.
	 */
	zrtp_status_t (*set_verified)(zrtp_cache_t *cache,
			const zrtp_stringn_t* remote_zid,
			uint32_t verified);

	/**
	 * \brief Return cache verification flag
	 *
	 * This function return the secret verification flag associated with a pair of ZIDs.
	 *
	 * \param one_zid - first ZID for cache identification;
	 * \param remote_zid - second ZID for cache identification;
	 * \param verified - verification flag to be filled in
	 * \return
	 *  - zrtp_status_ok if flag is successfully returned;
	 *  - zrtp_status_fail if the secret cannot be found;
	 *  - some other error code from \ref zrtp_status_t if another error occurred.
	 */
	zrtp_status_t (*get_verified)(zrtp_cache_t *cache,
			const zrtp_stringn_t* remote_zid,
			uint32_t* verified);

	/**
	 *  \brief Add/Update cache value for MiTM endpoint
	 *
	 * This function is analogy to zrtp_callback_cache_t#on_put but for MiTM endpoint.
	 * \todo Add more detail description
	 * \sa zrtp_callback_cache_t#on_put zrtp_callback_cache_t#on_get_mitm
	 */
	zrtp_status_t (*put_mitm)(zrtp_cache_t *cache,
			const zrtp_stringn_t* remote_zid,
			zrtp_shared_secret_t *rss);

	/**
	 * \brief Return secret cache for MiTM endpoint
	 *
	 * This function is analogy to zrtp_callback_cache_t#on_get but for MiTM endpoint.
	 * \todo Add more detail description
	 * \sa zrtp_callback_cache_t#on_get zrtp_callback_cache_t#on_put_mitm
	 */
	zrtp_status_t (*get_mitm)(zrtp_cache_t *cache,
			const zrtp_stringn_t* remote_zid,
			zrtp_shared_secret_t *rss);
} zrtp_cache_op_t;


#define ZFONE_CACHE_NAME_LENGTH    256

/**
 * Set of utility operations with ZRTP cache. These API is not part of the RFC
 * but might be handy for some applications. Operations are optional for custom
 * ZRTP cache implementation.
 */
typedef struct {
	zrtp_status_t (*get_secure_since)(zrtp_cache_t *cache,
			const zrtp_stringn_t* remote_zid,
			uint32_t* since);

	zrtp_status_t (*reset_secure_since)(zrtp_cache_t *cache,
			const zrtp_stringn_t* remote_zid);

	zrtp_status_t (*set_presh_counter)(zrtp_cache_t *cache,
			const zrtp_stringn_t* remote_zid,
			uint32_t counter);

	zrtp_status_t (*get_presh_counter)(zrtp_cache_t *cache,
			const zrtp_stringn_t* remote_zid,
			uint32_t* counter);

	zrtp_status_t (*get_name)(zrtp_cache_t *cache,
			const zrtp_stringn_t* remote_zid,
			zrtp_stringn_t* name);

	zrtp_status_t (*put_name)(zrtp_cache_t *cache,
			const zrtp_stringn_t* remote_zid,
			const zrtp_stringn_t* name);
} zrtp_cache_op_ext_t;

/**
 *  \brief ZRTP cache "super class"
 *
 * Use this structure as a starting point to create new zrtp cache implementations e.g.
 * struct zrtp_cache_my {
 *      zrtp_cache_t super;
 *      // your implementation specific stuff go here
 * };
 *
 * @warning: zrtp_cache_t <b> must </b> be the first field in you cache definition
 */
struct zrtp_cache_t {
	zrtp_cache_type_t	type;		/** Cache type */
	zrtp_cache_op_t		 op;		/** Basic ZRTP cache operations, must be implemented. */
	zrtp_cache_op_ext_t	 op_ext;	/** Additional ZRTP cache operations. Optional for implementation. */
};


zrtp_status_t zrtp_cache_put(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		zrtp_shared_secret_t *rss);

zrtp_status_t zrtp_cache_put_mitm(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		zrtp_shared_secret_t *rss);

zrtp_status_t zrtp_cache_get(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		zrtp_shared_secret_t *rss,
		int prev_requested);

zrtp_status_t zrtp_cache_get_mitm(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		zrtp_shared_secret_t *rss);

zrtp_status_t zrtp_cache_set_verified(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		uint32_t verified);

zrtp_status_t zrtp_cache_get_verified(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		uint32_t* verified);



zrtp_status_t zrtp_cache_get_secure_since(zrtp_cache_t *cache,
			const zrtp_stringn_t* remote_zid,
			uint32_t* since);

zrtp_status_t zrtp_cache_reset_secure_since(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid);

zrtp_status_t zrtp_cache_set_presh_counter(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		uint32_t counter);

zrtp_status_t zrtp_cache_get_presh_counter(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		uint32_t* counter);

zrtp_status_t zrtp_cache_get_name(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		zrtp_stringn_t* name);

zrtp_status_t zrtp_cache_put_name(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		const zrtp_stringn_t* name);

/**
 * Another version of zrtp_cache_get_name() to get peer ZRTP cache name my session.
 *
 * \param session	- zrtp session which remote's name should be retrieved from the cache
 * \param name		- output name buffer
 * \return zrtp_status_ok in case of success or one of zrtp_status_t error codes in case of failure
 */
zrtp_status_t zrtp_cache_get_name2(zrtp_session_t *session, zrtp_stringn_t* name);

/**
 * Another version of zrtp_cache_set_name() to assign name to ZRTP endpoint
 *
 * \param session	- zrtp session which remote endpoint name should be set
 * \param name		- endpoint name
 * \return zrtp_status_ok in case of success or one of zrtp_status_t error codes in case of failure
 */
zrtp_status_t zrtp_cache_put_name2(zrtp_session_t *session, const zrtp_stringn_t* name);

#if defined(__cplusplus)
}
#endif

#endif /*__ZRTP_CACHE_H__*/
