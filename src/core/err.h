#ifndef DTL_CORE_ERR_H
#define DTL_CORE_ERR_H

/*
 * core/err -- error codes shared across telemetry-forge.
 *
 * Every fallible dtl_* function returns a dtl_err. DTL_OK (== 0) is success;
 * all error codes are negative-free positive enumerators so callers may write
 * `if (rc != DTL_OK)`. Use dtl_strerror() to turn a code into a stable,
 * human-readable, statically-allocated string.
 */

typedef enum dtl_err {
    DTL_OK = 0,          /* success                                            */
    DTL_ERR_TRUNCATED,   /* input ended before a full field/record was read    */
    DTL_ERR_BADMAGIC,    /* container magic bytes did not match                */
    DTL_ERR_BADVERSION,  /* format version is unknown/unsupported              */
    DTL_ERR_BADHEADER,   /* header failed validation (crc/flags)               */
    DTL_ERR_BADRECORD,   /* a record was structurally invalid                  */
    DTL_ERR_RANGE,       /* a value was outside its permitted range            */
    DTL_ERR_OOM,         /* an allocation failed                               */
    DTL_ERR_INVAL,       /* invalid argument passed by the caller              */
    DTL_ERR_IO,          /* an I/O operation failed                            */
    DTL_ERR_BADQUERY,    /* a filter query failed to lex/parse                 */

    DTL_ERR__COUNT       /* number of enumerators; not a real error code       */
} dtl_err;

/*
 * dtl_strerror -- map an error code to a constant description string.
 *
 * The returned pointer is to static storage and must not be freed or modified.
 * Unknown codes yield a fixed "unknown error" string rather than NULL, so the
 * result is always safe to pass to printf-family functions.
 */
const char *dtl_strerror(dtl_err code);

#endif /* DTL_CORE_ERR_H */
