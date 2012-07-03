/**
 * Maximum length of a raw crypto string.
 */
#define MAX_CRYPT_STRING_LEN 200

/**
 * Supported SDES crypto suites.
 */
typedef enum {
    AES_CM_128_HMAC_SHA1_32 = 1,
    AES_CM_128_HMAC_SHA1_80
} sdesSuites;

/**
 * Create an SRTP profile and the according SDES crypto string.
 *
 * The method creates an SRTP profile an the according SDES crypto string.
 * It selects a valid crypto suite, generates the key and salt data,
 * converts these into base 64 and returns the crypto string in raw format
 * without any signaling prefixes.
 *
 * The output string has the following format:
 * @verbatim
 * 1 AES_CM_128_HMAC_SHA1_32 inline:NzB4d1BINUAvLEw6UzF3WSJ+PSdFcGdUJShpX1Zj
 * @endverbatim
 *
 *
 * Depending on the crypto suite the overall length of the crypto string
 * is variable. For a normal AES_128_CM suite the minumum lenth is 73
 * characters, a AES_256_CM suite results in 97 characters (not counting
 * any signaling prefixes).
 *
 * @param zrtp pointer to global ZRTP data structure.
 *
 * @param suite defines which crypto suite to use. This is an @c enum
 *              defined in zrtp_sdes.h. The values are
 *              @c AES_CM_128_HMAC_SHA1_80 or @c AES_CM_128_HMAC_SHA1_32.
 *
 * @param cryptoString points to a char output buffer that receives the 
 *                     crypto  string in the raw format, without the any
 *                     signaling prefix, for example @c a=crypto: in case
 *                     of SDP signaling. The function terminates the
 *                     crypto string with a @c nul byte
 *
 * @param maxLen points to an integer. On input this integer specifies the
 *               length of the output buffer. If @c maxLen is smaller than
 *               the resulting crypto string the function returns an error 
 *               conde. On return the functions sets @c maxLen to the
 *               actual length of the resultig crypto string.
 *
 * @param tag the value of the @c tag field in the crypto string. The
 *            answerer must use this input to make sure that the tag value
 *            in the answer matches the value in the offer. See RFC 4568,
 *            section 5.1.2.
 *            If the tag value is @c -1 the function sets the tag to @c 1.
 *
 * @param profile points to a SRTP/SRTCP profile. The methods fills in
 *                information derived from the crypto string.
 *
 * @return @c zrtp_status_ok if data could be created, @c zrtp_status_fail
 *          otherwise. 
 */
zrtp_status_t createSdesProfile(zrtp_global_t* zrtp, const sdesSuites suite,
                                char *cryptoString, size_t *maxLen, int64_t tag, 
                                zrtp_srtp_profile_t *profile);


/**
 * Parse and check an offered SDES crypto string and create SRTP profile.
 *
 * The method parses an offered SDES crypto string and checks if it is
 * valid. Next it checks if the string contains a supported crypto suite
 * and if the key and salt lengths matche the selected crypto suite.
 *
 * If the checks are ok the method decodes the key string and fills in the
 * SRTP profile.
 *
 * @b NOTE: This function does not support the optional parameters lifetime,
 * MKI, and session parameters. While it can parse liftime and MKI theiy are
 * not evaluated and used. If these parameters are used in the input crypto
 * string the function return @c zrtp_status_fail.
 *
 * @param zrtp pointer to global ZRTP data structure.
 *
 * @param cryptoString points to the crypto sting in raw format,
 *                     without any signaling prefix, for example @c
 *                     a=crypto: in case of SDP signaling.
 *
 * @param length length of the crypto string to parse. If the length is
 *               give as @c zero the function uses @c strlen to compute
 *               the length.
 *
 * @param profile points to a SRTP/SRTCP profile. The methods fills in
 *                information derived from the crypto string.
 *
 * @param suite the function sets this to the @c sdesSuites enumerator of
 *              the parsed crypto suite. The answerer shall use this as
 *              input to @c createSdesProfile to make sure that it creates
 *              the same crypto suite. See RFC 4568, section 5.1.2
 *
 * @param tag the function sets this to the @c tag value of
 *            the parsed crypto string. The answerer must use this as
 *            input to @c createSdesProfile to make sure that it creates
 *            the correct tag in the crypto string. See RFC 4568,
 *            section 5.1.2
 *
 * @return @c zrtp_status_ok if checks were ok, @c zrtp_status_fail
 *          otherwise. 
 */
zrtp_status_t parseCreateSdesProfile(zrtp_global_t* zrtp, const char *cryptoString,
                                     size_t length, zrtp_srtp_profile_t *profile,
                                     sdesSuites *suite, int64_t *tag);

