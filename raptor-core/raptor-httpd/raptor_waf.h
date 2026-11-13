/* ============================================================================
 * NOM DU SCRIPT   : raptor-httpd/raptor_waf.h
 * REVISION        : Rev 3.0 (2026-11-12)
 * PROJET          : RAPTOR-OS // RAPTOR-HTTPD v2.0
 * RESPONSABILITE  : Prototypes inspection L7 (URI, en-tetes Cookie/Referer/UA
 *                   et corps POST/PUT avec double normalisation anti-evasion).
 * ============================================================================ */

#ifndef RAPTOR_WAF_H
#define RAPTOR_WAF_H

#include <stddef.h>
#include <stdint.h>
#include "raptor_ipc.h"

int raptor_waf_check_honeypot(const char *path, char *rule_out, size_t rule_len);
int raptor_waf_check_payload(const char *path, const char *query, char *rule_out, size_t rule_len);
int raptor_waf_check_ua(const char *ua, char *rule_out, size_t rule_len);
int raptor_waf_check_header(const char *hdr_name, const char *hdr_val,
    char *rule_out, size_t rule_len);
int raptor_waf_check_body(const uint8_t *body, size_t body_len, char *rule_out, size_t rule_len);
int raptor_waf_inspect(const char *path, const char *query, const char *ua,
    const char *cookie, const char *referer,
    const char *client_ip, struct raptor_http_alert *alert_out);
int raptor_waf_inspect_body(const char *path, const uint8_t *body, size_t body_len,
    const char *client_ip, struct raptor_http_alert *alert_out);

#endif
