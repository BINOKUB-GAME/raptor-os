/* ============================================================================
 * NOM DU SCRIPT   : raptor-httpd/raptor_guard.c
 * REVISION        : Rev 1.0 (2026-11-12)
 * PROJET          : RAPTOR-OS // RAPTOR-HTTPD v2.0
 * DESCRIPTION     : Gardien comportemental par IP (Rate Limit & Slowloris).
 * INTEGRATIONS    : Table FNV-1a 256 entrees, seuil 30 req/10s, 2 timeouts.
 * FONCTIONS       : 1.now_sec 2.hash_ip 3.get_slot 4.is_exempt 5.rate 6.slow
 * ============================================================================ */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "raptor_guard.h"

struct raptor_guard_entry {
    char ip[RAPTOR_ALERT_IP_MAX];
    time_t rate_start, slow_start, last_seen;
    unsigned int req_count, slow_strikes;
};

static struct raptor_guard_entry guard_table[RAPTOR_GUARD_SLOTS];

/* 1. Horloge monotone compatible pledge("stdio") */
static time_t
raptor_guard_now_sec(void)
{
    struct timespec ts;
    return (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) ? 0 : ts.tv_sec;
}

/* 2. Hachage FNV-1a de la chaine IP */
static size_t
raptor_guard_hash_ip(const char *ip)
{
    unsigned int h = 2166136261U;
    const unsigned char *p = (const unsigned char *)ip;

    while (*p != '\0') {
        h ^= (unsigned int)(*p++);
        h *= 16777619U;
    }
    return ((size_t)(h % RAPTOR_GUARD_SLOTS));
}

/* 3. Selection du slot IP avec recyclage apres 120 secondes */
static struct raptor_guard_entry *
raptor_guard_get_slot(const char *ip, time_t now)
{
    size_t base = raptor_guard_hash_ip(ip), step;
    struct raptor_guard_entry *oldest = NULL;

    for (step = 0; step < 8; step++) {
        struct raptor_guard_entry *e = &guard_table[(base + step) % RAPTOR_GUARD_SLOTS];
        if (e->ip[0] != '\0' && strcmp(e->ip, ip) == 0) {
            e->last_seen = now;
            return (e);
        }
        if (e->ip[0] == '\0' || (now - e->last_seen) > 120) {
            memset(e, 0, sizeof(*e));
            snprintf(e->ip, sizeof(e->ip), "%s", ip);
            e->last_seen = now;
            return (e);
        }
        if (oldest == NULL || e->last_seen < oldest->last_seen)
            oldest = e;
    }
    memset(oldest, 0, sizeof(*oldest));
    snprintf(oldest->ip, sizeof(oldest->ip), "%s", ip);
    oldest->last_seen = now;
    return (oldest);
}

/* 4. Verification exemption boucle locale */
int
raptor_guard_is_exempt(const char *client_ip)
{
    if (client_ip == NULL || *client_ip == '\0')
        return (1);
    return (strcmp(client_ip, "127.0.0.1") == 0 || strcmp(client_ip, "::1") == 0);
}

/* 5. Controle du debit HTTP (30 req / 10 secondes) */
int
raptor_guard_check_rate(const char *client_ip, const char *uri,
    struct raptor_http_alert *alert_out)
{
    struct raptor_guard_entry *e;
    time_t now;

    if (alert_out == NULL || raptor_guard_is_exempt(client_ip))
        return (0);
    now = raptor_guard_now_sec();
    e = raptor_guard_get_slot(client_ip, now);
    if (e->rate_start == 0 || (now - e->rate_start) >= RAPTOR_RATE_WINDOW_SEC) {
        e->rate_start = now;
        e->req_count = 1;
        return (0);
    }
    if (++e->req_count > RAPTOR_RATE_MAX_REQ) {
        memset(alert_out, 0, sizeof(*alert_out));
        snprintf(alert_out->client_ip, sizeof(alert_out->client_ip), "%s", client_ip);
        snprintf(alert_out->rule_id, sizeof(alert_out->rule_id), "WAF_RATE_LIMIT");
        snprintf(alert_out->uri, sizeof(alert_out->uri), "%s", uri ? uri : "/");
        alert_out->severity = 2;
        e->req_count = 0;
        return (1);
    }
    return (0);
}

/* 6. Enregistrement d'une tentative Slowloris */
int
raptor_guard_record_slowloris(const char *client_ip, const char *uri,
    struct raptor_http_alert *alert_out)
{
    struct raptor_guard_entry *e;
    time_t now;

    if (alert_out == NULL || raptor_guard_is_exempt(client_ip))
        return (0);
    now = raptor_guard_now_sec();
    e = raptor_guard_get_slot(client_ip, now);
    if (e->slow_start == 0 || (now - e->slow_start) >= RAPTOR_SLOW_STRIKE_WINDOW) {
        e->slow_start = now;
        e->slow_strikes = 1;
    } else {
        e->slow_strikes++;
    }
    if (e->slow_strikes >= RAPTOR_SLOW_MAX_STRIKES) {
        memset(alert_out, 0, sizeof(*alert_out));
        snprintf(alert_out->client_ip, sizeof(alert_out->client_ip), "%s", client_ip);
        snprintf(alert_out->rule_id, sizeof(alert_out->rule_id), "WAF_SLOWLORIS_ABUSE");
        snprintf(alert_out->uri, sizeof(alert_out->uri), "%s", uri ? uri : "/");
        alert_out->severity = 3;
        e->slow_strikes = 0;
        return (1);
    }
    return (0);
}
