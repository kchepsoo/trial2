#ifndef DTL_REPORT_TIMELINE_H
#define DTL_REPORT_TIMELINE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "core/arena.h"
#include "core/err.h"

/*
 * report/timeline -- reconstruct the temporal structure of a container.
 *
 * Heartbeat records act as device-uptime checkpoints; every other record is
 * attributed to the session opened by the most recent heartbeat. The
 * timeline report shows, per session, the uptime checkpoint, the sequence
 * number, and how many records of each type were logged before the next
 * heartbeat. It also flags two anomaly classes:
 *
 *   gap     - the uptime delta between consecutive heartbeats exceeds
 *             tolerance * the expected interval (records may be missing);
 *   ordering- an uptime that decreases from one heartbeat to the next
 *             (clock reset, corrupted record, or spliced log).
 */

typedef struct dtl_timeline_session {
    uint32_t uptime_s;
    uint32_t seq;
    size_t   record_count;        /* records attributed to this session     */
    size_t   per_tag[256];
    size_t   first_record_index;  /* global ordinal of the session opener   */
} dtl_timeline_session;

typedef struct dtl_timeline {
    dtl_timeline_session *sessions; /* arena-allocated                      */
    size_t                session_count;
    size_t                session_cap;
    size_t                gap_count;
    size_t                ordering_violations;
    size_t                unattributed_records; /* before any heartbeat     */
    dtl_arena            *a;
} dtl_timeline;

typedef struct dtl_timeline_options {
    uint32_t expected_interval_s; /* nominal heartbeat period (0 = 60)      */
    uint32_t tolerance;           /* gap threshold multiplier (0 = 2)       */
} dtl_timeline_options;

/*
 * dtl_timeline_build -- build the timeline for the container at path
 * (size-capped at max_file bytes), arena-backed by a.
 */
dtl_err dtl_timeline_build(const char *path, size_t max_file,
                           const dtl_timeline_options *opts, dtl_arena *a,
                           dtl_timeline *tl);

/* dtl_timeline_print -- session table + anomaly summary. */
void dtl_timeline_print(const dtl_timeline *tl,
                        const dtl_timeline_options *opts, FILE *out);

#endif /* DTL_REPORT_TIMELINE_H */
