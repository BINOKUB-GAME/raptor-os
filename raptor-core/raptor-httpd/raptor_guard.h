/* ============================================================================
 * NOM DU SCRIPT   : raptor-httpd/raptor_guard.h
 * REVISION        : Rev 1.0 (2026-11-12)
 * PROJET          : RAPTOR-OS // RAPTOR-HTTPD v2.0
 * RESPONSABILITE  : Prototypes Rate Limiting et protection anti-Slowloris.
 * ============================================================================ */

#ifndef RAPTOR_GUARD_H
#define RAPTOR_GUARD_H

#include <time.h>
#include "raptor_ipc.h"

#define RAPTOR_GUARD_SLOTS          256
#define RAPTOR_RATE_WINDOW_SEC      10
#define RAPTOR_RATE_MAX_REQ         30
#define RAPTOR_SLOW_HEADER_MAX_SEC  10
#define RAPTOR_SLOW_STRIKE_WINDOW   60
#define RAPTOR_SLOW_MAX_STRIKES     2

int raptor_guard_is_exempt(const char *client_ip);
int raptor_guard_check_rate(const char *client_ip, const char *uri,
    struct raptor_http_alert *alert_out);
int raptor_guard_record_slowloris(const char *client_ip, const char *uri,
    struct raptor_http_alert *alert_out);

#endif
