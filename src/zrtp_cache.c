/*
 * libZRTP SDK library, implements the ZRTP secure VoIP protocol.
 * Copyright (c) 2006-2012 Philip R. Zimmermann.  All rights reserved.
 * Contact: http://philzimmermann.com
 * For licensing and other legal details, see the file zrtp_legal.c.
 *
 * Viktor Krykun <v.krikun at zfoneproject.com>
 */

#include "zrtp_types.h"
#include "zrtp_cache.h"

zrtp_status_t zrtp_cache_put(zrtp_cache_t *cache, const zrtp_stringn_t* remote_zid, zrtp_shared_secret_t *rss) {
	if (cache && remote_zid && rss) {
		return cache->op.put(cache, remote_zid, rss);
	} else {
		return zrtp_status_bad_param;
	}
}

zrtp_status_t zrtp_cache_put_mitm(zrtp_cache_t *cache, const zrtp_stringn_t* remote_zid, zrtp_shared_secret_t *rss) {
	if (cache && remote_zid && rss) {
		return cache->op.put_mitm(cache, remote_zid, rss);
	} else {
		return zrtp_status_bad_param;
	}
}

zrtp_status_t zrtp_cache_get(zrtp_cache_t *cache, const zrtp_stringn_t* remote_zid, zrtp_shared_secret_t *rss,
		int prev_requested) {
	if (cache && remote_zid && rss) {
		return cache->op.get(cache, remote_zid, rss, prev_requested);
	} else {
		return zrtp_status_bad_param;
	}
}

zrtp_status_t zrtp_cache_get_mitm(zrtp_cache_t *cache, const zrtp_stringn_t* remote_zid, zrtp_shared_secret_t *rss) {
	if (cache && remote_zid && rss) {
		return cache->op.get_mitm(cache, remote_zid, rss);
	} else {
		return zrtp_status_bad_param;
	}
}

zrtp_status_t zrtp_cache_set_verified(zrtp_cache_t *cache, const zrtp_stringn_t* remote_zid, uint32_t verified) {
	if (cache && remote_zid) {
		return cache->op.set_verified(cache, remote_zid, verified);
	} else {
		return zrtp_status_bad_param;
	}
}

zrtp_status_t zrtp_cache_get_verified(zrtp_cache_t *cache, const zrtp_stringn_t* remote_zid, uint32_t* verified) {
	if (cache && remote_zid) {
		return cache->op.get_verified(cache, remote_zid, verified);
	} else {
		return zrtp_status_bad_param;
	}
}

zrtp_status_t zrtp_cache_set_presh_counter(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		uint32_t counter) {
	if (cache && remote_zid) {
		if (cache->op_ext.set_presh_counter)
			return cache->op_ext.set_presh_counter(cache, remote_zid, counter);
		else
			return zrtp_status_notavailable;
	} else {
		return zrtp_status_bad_param;
	}
}

zrtp_status_t zrtp_cache_get_presh_counter(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		uint32_t* counter) {
	if (cache && remote_zid && counter) {
		if (cache->op_ext.get_presh_counter)
			return cache->op_ext.get_presh_counter(cache, remote_zid, counter);
		else
			return zrtp_status_notavailable;
	} else {
		return zrtp_status_bad_param;
	}
}

zrtp_status_t zrtp_cache_get_secure_since(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		uint32_t* since) {
	if (cache && remote_zid && since) {
		if (cache->op_ext.get_secure_since)
			return cache->op_ext.get_secure_since(cache, remote_zid, since);
		else
			return zrtp_status_notavailable;
	} else {
		return zrtp_status_bad_param;
	}
}

zrtp_status_t zrtp_cache_reset_secure_since(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid) {
	if (cache && remote_zid) {
		if (cache->op_ext.reset_secure_since)
			return cache->op_ext.reset_secure_since(cache, remote_zid);
		else
			return zrtp_status_notavailable;
	} else {
		return zrtp_status_bad_param;
	}
}

zrtp_status_t zrtp_cache_get_name(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		zrtp_stringn_t* name) {
	if (cache && remote_zid && name) {
		if (cache->op_ext.get_name)
			return cache->op_ext.get_name(cache, remote_zid, name);
		else
			return zrtp_status_notavailable;
	} else {
		return zrtp_status_bad_param;
	}
}

zrtp_status_t zrtp_cache_put_name(zrtp_cache_t *cache,
		const zrtp_stringn_t* remote_zid,
		const zrtp_stringn_t* name) {
	if (cache && remote_zid && name) {
		if (cache->op_ext.put_name)
			return cache->op_ext.put_name(cache, remote_zid, name);
		else
			return zrtp_status_notavailable;
	} else {
		return zrtp_status_bad_param;
	}
}

zrtp_status_t zrtp_cache_get_name2(zrtp_session_t *session, zrtp_stringn_t* name) {
	if (session && session->zrtp && session->zrtp->cache) {
		return zrtp_cache_get_name(session->zrtp->cache, ZSTR_GV(session->peer_zid), name);
	} else {
		return zrtp_status_bad_param;
	}
}

zrtp_status_t zrtp_cache_put_name2(zrtp_session_t *session, const zrtp_stringn_t* name) {
	if (session && session->zrtp && session->zrtp->cache) {
		return zrtp_cache_put_name(session->zrtp->cache, ZSTR_GV(session->peer_zid), name);
	} else {
		return zrtp_status_bad_param;
	}
}
