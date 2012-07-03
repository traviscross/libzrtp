
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "zrtp.h"
#include "zrtp_sdes.h"

/*
 * Test Data and tests
 */

/* parsing the following string shall return a parse error */
static char *minimumLong =
    "1 AES_CM_128_HMAC_SHA1_8045AES_CM_128_HMAC_SHA1_8045AES_CM_128_HMAC_SHA1_8045"
    "AES_CM_128_HMAC_SHA1_8045AES_CM_128_HMAC_SHA1_8045 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz";

static char *minimum =         "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz";
static char *withLifetime =    "1 AES_CM_128_HMAC_SHA1_32 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20";
static char *withLifetimeMki = "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4";

static char *minimumSp =
    "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz "
    "FEC_ORDER=FEC_SRTP KDR=20";

static char *withLifetimeSp =
    "1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20 "
    "FEC_ORDER=FEC_SRTP KDR=20";

static char *withLifetimeMkiSp =
    "1 AES_CM_128_HMAC_SHA1_32 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4 "
    "FEC_ORDER=FEC_SRTP KDR=20";


static zrtp_global_t *zrtp;

static void setup() {
    zrtp_status_t s;
    zrtp_config_t zrtp_config;

    zrtp_config_defaults(&zrtp_config);

    s = zrtp_init(&zrtp_config, &zrtp);
}

int
main (int argc, char **argv)
{
    int64_t tag = 0;
    sdesSuites suite;
    int i;
    char cryptoString[200];
    size_t length = 200;

    zrtp_srtp_profile_t profile;

    setup();

    createSdesProfile(zrtp, AES_CM_128_HMAC_SHA1_80, cryptoString, &length, 2, &profile);
    printf("crypto string: %s, len: %ld, %ld\n", cryptoString, length, strlen(cryptoString));

    length = 200;
    createSdesProfile(zrtp, AES_CM_128_HMAC_SHA1_32, cryptoString, &length, 1, &profile);
    printf("crypto string: %s, len: %ld, %ld\n", cryptoString, length, strlen(cryptoString));

    i = parseCreateSdesProfile(zrtp, minimum, strlen(minimum), &profile, &suite, &tag);
    printf("parse return: %d, suite: %d, tag: %ld\n", i, suite, tag);
    if (i == zrtp_status_ok) {
        printf("cipher name, srtp: %.4s, srtcp: %.4s\n", profile.rtp_policy.cipher->base.type, profile.rtcp_policy.cipher->base.type);
        printf("cipher keylength, srtp: %d, srtcp: %d\n", profile.rtp_policy.cipher_key_len, profile.rtcp_policy.cipher_key_len);
        printf("authentication, srtp: %.4s, srtcp: %.4s\n", profile.rtp_policy.auth_tag_len->base.type, profile.rtcp_policy.auth_tag_len->base.type);
        printf("authentication keylength, srtp: %d, srtcp: %d\n", profile.rtp_policy.auth_key_len, profile.rtcp_policy.auth_key_len);
        printf("cipher name key derivation: %.4s\n", profile.dk_cipher->base.type);
        printf("hmac name, srtp: %.4s, srtcp: %.4s\n", profile.rtp_policy.hash->base.type, profile.rtcp_policy.hash->base.type);
    }

    /* i shall be zrtp_status_fail */
    i = parseCreateSdesProfile(zrtp, minimumLong, strlen(minimumLong), &profile, &suite, &tag);
    printf("parse return: %d, suite: %d, tag: %ld\n", i, suite, tag);

    i = parseCreateSdesProfile(zrtp, withLifetime, strlen(withLifetime), &profile, &suite, &tag);
    printf("parse return: %d, suite: %d, tag: %ld\n", i, suite, tag);

    i = parseCreateSdesProfile(zrtp, withLifetimeMkiSp, strlen(withLifetimeMkiSp), &profile, &suite, &tag);
    printf("parse return: %d, suite: %d, tag: %ld\n", i, suite, tag);

    return 0;
}
