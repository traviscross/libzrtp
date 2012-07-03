/*
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "zrtp.h"
#include "zrtp_b64_decode.h"
#include "zrtp_b64_encode.h"
#include "zrtp_sdes.h"

#define _ZTU_ "zrtp sdes"

/*
 * These functions support 256 bit encryption algorithms.
 */
#define MAX_KEY_LEN           32
#define MAX_SALT_LEN          14

/*
 * The ABNF grammar for the crypto attribute is defined below (from RFC 4568):
 *
 *  "a=crypto:" tag 1*WSP crypto-suite 1*WSP key-params *(1*WSP session-param)
 *
 *  tag              = 1*9DIGIT
 */

/*
 * Buffer size for names and other strings inside the crypto string. The parse
 * format below restricts parsing to 99 char to provide space for the @c nul byte.
 */
#define MAX_INNER_LEN 100

/*
 * This format scans a received SDES crypto attribute string according to the
 * grammer shown above but without a "a=crypto:" prefix.
 *
 * The format string parses:
 * - %ld - the tag as decimal value
 * - %s - the crypto suite name, limited to 99 chars (see MAX_INNER_LEN)
 * - %s - the key parameters, limited to 99 chars
 * - %n - the number of parsed characters to far. The pointer to the session 
 *   parameters is: cryptoString + numParsedChars.
 */
static const char parseCrypto[] = " %lld %99s %99s %n";

static const int64_t maxTagValue = 999999999;

static const int minElementsCrypto = 3;

/*
 * The ABNF grammar for the key-param (from RFC 4568):
 *
 *  key-param        = key-method ":" key-info
 *
 * The SRTP specific definitions:
 *
 *  key-method          = srtp-key-method
 *  key-info            = srtp-key-info
 *
 *  srtp-key-method     = "inline"
 *  srtp-key-info       = key-salt ["|" lifetime] ["|" mki]
 *
 */

/*
 * This format parses the key parameter string which is never longer than 
 * 99 chars (see parse string above):
 * - the fixed string "inline:"
 * - %[A-Za-z0-9+/=] - base 64 characters of master key||master salt
 * - the fixed separator character '|'
 * - %[0-9^] - the lifetime infomration as string that contains digits and ^
 * - the fixed separator character '|'
 * - %[0-9]:%d - parses and strore MKI value and MKI length, separated by ':'
 *
 * If the key parameter string does not contain the operional fields lifetime
 * and MKI information the respective parameters are not filled.
 */
static const char parseKeyParam[] = " inline:%[A-Za-z0-9+/=]|%[0-9^]|%[0-9]:%d";

static const int minElementsKeyParam = 1;

typedef struct _suite {
    sdesSuites          suite;
    char                *name;
    int32_t             keyLength;     /* key length in bits */
    int32_t             saltLength;    /* salt lenght in bits */
    int32_t             authKeyLength; /* authentication key length in bits */
    zrtp_atl_id_t       tagLength;     /* tag type ZRTP_HS80 or ZRTP_HS32 */
    zrtp_cipher_id_t    cipher;
    zrtp_srtp_hash_id_t authentication;
    int32_t             b64length;
    uint64_t            defaultSrtpLifetime;
    uint64_t            defaultSrtcpLifetime;
} suite;

/* NOTE: the b64len of a 128 bit suite is 40, a 256bit suite uses 64 characters */
static suite knownSuites[] = {
    {AES_CM_128_HMAC_SHA1_32, "AES_CM_128_HMAC_SHA1_32", 128, 112, 160,
     ZRTP_ATL_HS32, ZRTP_CIPHER_AES128, ZRTP_SRTP_HASH_HMAC_SHA1, 40, (uint64_t)1<<48, 1<<31
    },
    {AES_CM_128_HMAC_SHA1_80, "AES_CM_128_HMAC_SHA1_80", 128, 112, 160,
     ZRTP_ATL_HS80, ZRTP_CIPHER_AES128, ZRTP_SRTP_HASH_HMAC_SHA1, 40, (uint64_t)1<<48, 1<<31
    },
    {0, NULL, 0, 0, 0, 0, 0, 0, 0}
};

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

zrtp_status_t createSdesProfile(zrtp_global_t* zrtp, const sdesSuites suite, char *cryptoString, size_t *maxLen, int64_t tag, 
                                zrtp_srtp_profile_t *profile)
{
    uint8_t keySalt[((MAX_KEY_LEN + MAX_SALT_LEN + 3)/4)*4] = {0};  /* Some buffer for random data, multiple of 4 */
    char b64keySalt[(MAX_KEY_LEN + MAX_SALT_LEN) * 2] = {'\0'};
    int32_t sidx, b64Len;

    /* Lookup crypto suite parameters */
    for (sidx = 0; knownSuites[sidx].name != NULL; sidx++) {
        if (knownSuites[sidx].suite == suite)
            break;
    }
    if (sidx >= sizeof(knownSuites)/sizeof(struct _suite)) {
        ZRTP_LOG(1, (_ZTU_,"\tcreateSdesProfile() unsupported crypto suite id: %d\n", suite));
        return zrtp_status_fail;
    }

    zrtp_randstr2(keySalt, sizeof(keySalt));

    /* fill in srtp profile */
    ZSTR_SET_EMPTY(profile->salt);
    ZSTR_SET_EMPTY(profile->key);

    profile->key.length = knownSuites[sidx].keyLength / 8;
    zrtp_memcpy(profile->key.buffer, keySalt, profile->key.length);

    profile->salt.length = knownSuites[sidx].saltLength / 8;
    zrtp_memcpy(profile->salt.buffer, keySalt+profile->key.length, profile->salt.length);

    profile->rtp_policy.cipher = zrtp_comp_find(ZRTP_CC_CIPHER, knownSuites[sidx].cipher, zrtp);
    profile->rtp_policy.cipher_key_len = knownSuites[sidx].keyLength;

    profile->rtp_policy.auth_tag_len = zrtp_comp_find(ZRTP_CC_ATL, knownSuites[sidx].tagLength, zrtp);
    profile->rtp_policy.auth_key_len  = knownSuites[sidx].authKeyLength / 8;

    profile->rtp_policy.hash = zrtp_comp_find(ZRTP_CC_HASH, knownSuites[sidx].authentication, zrtp);

    profile->dk_cipher = zrtp_comp_find(ZRTP_CC_CIPHER, knownSuites[sidx].cipher, zrtp);

    zrtp_memcpy(&profile->rtcp_policy, &profile->rtp_policy, sizeof(profile->rtcp_policy));
    if (tag == -1)
        tag = 1;

    /* Get B64 code for master key and master salt */
    b64Len = b64Encode(keySalt, (knownSuites[sidx].keyLength + knownSuites[sidx].saltLength)/8, b64keySalt, sizeof(b64keySalt));
    b64keySalt[b64Len] = '\0';
    *maxLen = snprintf(cryptoString, *maxLen, "%lld %s inline:%s", tag, knownSuites[sidx].name, b64keySalt);

    zrtp_memset(keySalt, 0, sizeof(keySalt));

    return zrtp_status_ok;
}


zrtp_status_t parseCreateSdesProfile(zrtp_global_t* zrtp, const char *cryptoStr, size_t length, zrtp_srtp_profile_t *profile,
                                     sdesSuites *suite, int64_t *tag)
{
    int elements, sidx, i;
    int charsScanned;
    int mkiLength = 0;
    char cryptoString[MAX_CRYPT_STRING_LEN+1] = {'\0'};
    uint8_t keySalt[((MAX_KEY_LEN + MAX_SALT_LEN + 3)/4)*4] = {0};

    /* Parsed strings */
    char suiteName[MAX_INNER_LEN]  = {'\0'};
    char keyParams[MAX_INNER_LEN]  = {'\0'};
    char keySaltB64[MAX_INNER_LEN] = {'\0'};
    char lifetime[MAX_INNER_LEN]   = {'\0'};
    char mkiVal[MAX_INNER_LEN]     = {'\0'};

    if (length == 0)
        length = strlen(cryptoStr);

    if (length > MAX_CRYPT_STRING_LEN) {
        ZRTP_LOG(1, (_ZTU_,"\tparseCreateSdesProfile() crypto string too long: %d, maximum: %d\n", length, MAX_CRYPT_STRING_LEN));
        return zrtp_status_fail;
    }

    /* make own copy, null terminated */
    memcpy(cryptoString, cryptoStr, length);

    *tag = -1;
    elements = sscanf(cryptoString, parseCrypto, tag, suiteName, keyParams, &charsScanned);

    /* Do we have enough elements in the string */
    if (elements < minElementsCrypto) {
        ZRTP_LOG(1, (_ZTU_,"\tparseCreateSdesProfile() to few elements in crypto string: %d, expected: %d\n", elements, minElementsCrypto));
        return zrtp_status_fail;
    }

    /* Lookup crypto suite */
    for (sidx = 0; knownSuites[sidx].name != NULL; sidx++) {
        if (!strcmp(knownSuites[sidx].name, suiteName))
            break;
    }
    if (sidx >= sizeof(knownSuites)/sizeof(struct _suite)) {
        ZRTP_LOG(1, (_ZTU_,"\tparseCreateSdesProfile() unsupported crypto suite: %s\n", suiteName));
        return zrtp_status_fail;
    }
    *suite = knownSuites[sidx].suite;

    /* Now scan the key parameters */
    elements = sscanf(keyParams, parseKeyParam, keySaltB64, lifetime, mkiVal, &mkiLength);

    /* Currently only one we only accept key||salt B64 string, no other parameters */
    if (elements != minElementsKeyParam) {
        ZRTP_LOG(1, (_ZTU_,"\tparseCreateSdesProfile() wrong number of parameters in key parameters: %d, expected: %d\n",
                     elements, minElementsKeyParam));
        return zrtp_status_fail;
    }

    /* Check if key||salt B64 string hast the correct length */
    if (strlen(keySaltB64) != knownSuites[sidx].b64length) {
        ZRTP_LOG(1, (_ZTU_,"\tparseCreateSdesProfile() B64 key||salt string length does not match: %d, expected: %d\n",
                    strlen(keySaltB64), knownSuites[sidx].b64length));
        return zrtp_status_fail;
    }

    i = b64Decode(keySaltB64, knownSuites[sidx].b64length, keySalt, (knownSuites[sidx].keyLength + knownSuites[sidx].saltLength)/8);

    /* Did the B64 decode deliver enough data for key||salt */
    if (i != (knownSuites[sidx].keyLength + knownSuites[sidx].saltLength)/8) {
        ZRTP_LOG(1, (_ZTU_,"\tparseCreateSdesProfile() B64 key||salt binary data length does not match: %d, expected: %d\n",
                    i, (knownSuites[sidx].keyLength + knownSuites[sidx].saltLength)/8));
        return zrtp_status_fail;
    }

    /* fill in srtp profile */
    ZSTR_SET_EMPTY(profile->salt);
    ZSTR_SET_EMPTY(profile->key);

    profile->key.length = knownSuites[sidx].keyLength / 8;
    zrtp_memcpy(profile->key.buffer, keySalt, profile->key.length);

    profile->salt.length = knownSuites[sidx].saltLength / 8;
    zrtp_memcpy(profile->salt.buffer, keySalt+profile->key.length, profile->salt.length);

    zrtp_memset(keySalt, 0, sizeof(keySalt));

    profile->rtp_policy.cipher = zrtp_comp_find(ZRTP_CC_CIPHER, knownSuites[sidx].cipher, zrtp);
    profile->rtp_policy.cipher_key_len = knownSuites[sidx].keyLength;

    profile->rtp_policy.auth_tag_len = zrtp_comp_find(ZRTP_CC_ATL, knownSuites[sidx].tagLength, zrtp);
    profile->rtp_policy.auth_key_len  = knownSuites[sidx].authKeyLength / 8;

    profile->rtp_policy.hash = zrtp_comp_find(ZRTP_CC_HASH, knownSuites[sidx].authentication, zrtp);

    profile->dk_cipher = zrtp_comp_find(ZRTP_CC_CIPHER, knownSuites[sidx].cipher, zrtp);

    zrtp_memcpy(&profile->rtcp_policy, &profile->rtp_policy, sizeof(profile->rtcp_policy));

    return zrtp_status_ok;
}


