#include "core/err.h"

const char *dtl_strerror(dtl_err code)
{
    switch (code) {
    case DTL_OK:            return "success";
    case DTL_ERR_TRUNCATED: return "input truncated";
    case DTL_ERR_BADMAGIC:  return "bad magic";
    case DTL_ERR_BADVERSION:return "unsupported version";
    case DTL_ERR_BADHEADER: return "malformed header";
    case DTL_ERR_BADRECORD: return "malformed record";
    case DTL_ERR_RANGE:     return "value out of range";
    case DTL_ERR_OOM:       return "out of memory";
    case DTL_ERR_INVAL:     return "invalid argument";
    case DTL_ERR_IO:        return "i/o error";
    case DTL_ERR_BADQUERY:  return "malformed query";
    case DTL_ERR__COUNT:    break; /* sentinel, not a real code */
    }
    return "unknown error";
}
