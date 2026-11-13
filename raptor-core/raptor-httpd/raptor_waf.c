/* ============================================================================
 * NOM DU SCRIPT   : raptor-httpd/raptor_waf.c
 * REVISION        : Rev 3.0 (2026-11-12)
 * PROJET          : RAPTOR-OS // RAPTOR-HTTPD v2.0
 * DESCRIPTION     : Pare-feu applicatif L7 et detecteur de leurres HTTP natif.
 * INTEGRATIONS    : Double decodage URL (%25XX), inspection Cookie/Referer.
 * FONCTIONS       : 1.strcasestr 2.decode_pass 3.normalize 4.honeypot
 *                   5.payload 6.ua 7.header 8.body 9.inspect 10.inspect_body
 * ============================================================================ */

#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "raptor_waf.h"

#define RAPTOR_WAF_BODY_SCAN_MAX 4096

/* 1. Recherche de sous-chaine insensible a la casse */
static const char *
raptor_waf_strcasestr(const char *haystack, const char *needle)
{
    size_t nlen;

    if (haystack == NULL || needle == NULL || *needle == '\0')
        return (NULL);
    nlen = strlen(needle);
    for (; *haystack != '\0'; haystack++) {
        if (strncasecmp(haystack, needle, nlen) == 0)
            return (haystack);
    }
    return (NULL);
}

/* 2. Passe unitaire de decodage URL (%XX, '+' et neutre sur %00) */
static size_t
raptor_waf_decode_pass(const uint8_t *src, size_t src_len, char *dst, size_t dst_cap)
{
    size_t i = 0, j = 0;

    if (src == NULL || dst == NULL || dst_cap == 0)
        return (0);
    while (i < src_len && j + 1 < dst_cap) {
        if (src[i] == '+') {
            dst[j++] = ' ';
            i++;
        } else if (src[i] == '%' && i + 2 < src_len &&
            isxdigit(src[i + 1]) && isxdigit(src[i + 2])) {
            char hex[3] = { (char)src[i + 1], (char)src[i + 2], '\0' };
            unsigned long val = strtoul(hex, NULL, 16);
            dst[j++] = (val == 0) ? ' ' : (char)val;
            i += 3;
        } else {
            dst[j++] = (src[i] == 0) ? ' ' : (char)src[i];
            i++;
        }
    }
    dst[j] = '\0';
    return (j);
}

/* 3. Double normalisation anti-evasion (%2527 -> %27 -> ') */
static size_t
raptor_waf_normalize(const uint8_t *src, size_t src_len, char *dst, size_t dst_cap)
{
    char pass1[RAPTOR_WAF_BODY_SCAN_MAX];
    size_t len1;

    len1 = raptor_waf_decode_pass(src, src_len, pass1, sizeof(pass1));
    if (len1 == 0) {
        if (dst != NULL && dst_cap > 0)
            dst[0] = '\0';
        return (0);
    }
    return (raptor_waf_decode_pass((const uint8_t *)pass1, len1, dst, dst_cap));
}

/* 4. Verification des routes leurres HTTP */
int
raptor_waf_check_honeypot(const char *path, char *rule_out, size_t rule_len)
{
    static const struct { const char *p; const char *t; } traps[] = {
        { "/.env", "TRAP_DOTENV" }, { "/.git", "TRAP_DOTGIT" },
        { "/wp-admin", "TRAP_WP_ADMIN" }, { "/wp-login.php", "TRAP_WP_LOGIN" },
        { "/phpmyadmin", "TRAP_PHPMYADMIN" }, { "/backup.sql", "TRAP_SQL_DUMP" },
        { "/!00_raptor_vault.kdbx", "TRAP_KDBX_CANARY" }
    };
    size_t i;

    if (path == NULL)
        return (0);
    for (i = 0; i < sizeof(traps) / sizeof(traps[0]); i++) {
        if (raptor_waf_strcasestr(path, traps[i].p) != NULL) {
            snprintf(rule_out, rule_len, "%s", traps[i].t);
            return (1);
        }
    }
    return (0);
}

/* 5. Filtrage LFI, SQLi et XSS dans URI et query */
int
raptor_waf_check_payload(const char *path, const char *query, char *rule_out, size_t rule_len)
{
    static const struct { const char *s; const char *t; } sigs[] = {
        { "../", "WAF_PATH_TRAVERSAL" }, { "/etc/passwd", "WAF_ETC_PASSWD" },
        { "union select", "WAF_SQLI_UNION" }, { "' or 1=1", "WAF_SQLI_TAUTOLOGY" },
        { "' or '1'='1", "WAF_SQLI_TAUTOLOGY" },
        { "information_schema", "WAF_SQLI_SCHEMA" }, { "<script", "WAF_XSS_TAG" }
    };
    char np[RAPTOR_WAF_BODY_SCAN_MAX], nq[RAPTOR_WAF_BODY_SCAN_MAX];
    size_t i;

    np[0] = '\0';
    nq[0] = '\0';
    if (path != NULL)
        raptor_waf_normalize((const uint8_t *)path, strlen(path), np, sizeof(np));
    if (query != NULL)
        raptor_waf_normalize((const uint8_t *)query, strlen(query), nq, sizeof(nq));
    for (i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        if ((np[0] && raptor_waf_strcasestr(np, sigs[i].s)) ||
            (nq[0] && raptor_waf_strcasestr(nq, sigs[i].s))) {
            snprintf(rule_out, rule_len, "%s", sigs[i].t);
            return (1);
        }
    }
    return (0);
}

/* 6. Detection des scanners offensifs via User-Agent */
int
raptor_waf_check_ua(const char *ua, char *rule_out, size_t rule_len)
{
    static const char *sc[] = {
        "sqlmap", "nikto", "nuclei", "gobuster", "dirbuster", "wpscan", "masscan"
    };
    size_t i;

    if (ua == NULL || *ua == '\0')
        return (0);
    for (i = 0; i < sizeof(sc) / sizeof(sc[0]); i++) {
        if (raptor_waf_strcasestr(ua, sc[i]) != NULL) {
            snprintf(rule_out, rule_len, "WAF_SCANNER_UA");
            return (1);
        }
    }
    return (0);
}

/* 7. Inspection L7 des en-tetes Cookie et Referer */
int
raptor_waf_check_header(const char *hdr_name, const char *hdr_val,
    char *rule_out, size_t rule_len)
{
    static const char *hs[] = {
        "union select", "' or 1=1", "' or '1'='1", "\" or \"1\"=\"1",
        "information_schema", "sleep(", "benchmark(", "waitfor delay",
        "../", "/etc/passwd", "/bin/sh", "/bin/bash", "cmd.exe",
        "<script", "onerror=", "onload=", "javascript:", "{{7*7}}",
        "file://", "169.254.169.254"
    };
    char norm[RAPTOR_WAF_BODY_SCAN_MAX];
    size_t i;

    if (hdr_val == NULL || *hdr_val == '\0')
        return (0);
    if (raptor_waf_normalize((const uint8_t *)hdr_val, strlen(hdr_val),
        norm, sizeof(norm)) == 0)
        return (0);
    for (i = 0; i < sizeof(hs) / sizeof(hs[0]); i++) {
        if (raptor_waf_strcasestr(norm, hs[i]) != NULL) {
            snprintf(rule_out, rule_len, "WAF_%s_INJECTION",
                (hdr_name != NULL) ? hdr_name : "HEADER");
            return (1);
        }
    }
    return (0);
}

/* 8. Analyse L7 du corps POST/PUT apres double normalisation */
int
raptor_waf_check_body(const uint8_t *body, size_t body_len, char *rule_out, size_t rule_len)
{
    static const struct { const char *s; const char *t; } bs[] = {
        { "union select", "POST_SQLI_UNION" }, { "' or 1=1", "POST_SQLI_TAUTOLOGY" },
        { "' or '1'='1", "POST_SQLI_TAUTOLOGY" }, { "\" or \"1\"=\"1", "POST_SQLI_TAUTOLOGY" },
        { "information_schema", "POST_SQLI_SCHEMA" }, { "sleep(", "POST_SQLI_BLIND" },
        { "benchmark(", "POST_SQLI_BLIND" }, { "waitfor delay", "POST_SQLI_BLIND" },
        { "into outfile", "POST_SQLI_OUTFILE" }, { "<?php", "POST_WEBSHELL_PHP" },
        { "eval($_", "POST_WEBSHELL_EVAL" }, { "system($_", "POST_WEBSHELL_EXEC" },
        { "passthru(", "POST_WEBSHELL_EXEC" }, { "shell_exec(", "POST_WEBSHELL_EXEC" },
        { "/bin/sh", "POST_RCE_SHELL" }, { "/bin/bash", "POST_RCE_SHELL" },
        { "cmd.exe", "POST_RCE_WIN" }, { "powershell", "POST_RCE_WIN" },
        { "../", "POST_PATH_TRAVERSAL" }, { "/etc/passwd", "POST_ETC_PASSWD" },
        { "/etc/shadow", "POST_ETC_SHADOW" }, { "<!entity", "POST_XXE_INJECTION" },
        { "file://", "POST_SSRF_FILE" }, { "169.254.169.254", "POST_SSRF_METADATA" },
        { "<script", "POST_XSS_TAG" }, { "onerror=", "POST_XSS_EVENT" },
        { "{{7*7}}", "POST_SSTI_PROBE" }
    };
    char norm[RAPTOR_WAF_BODY_SCAN_MAX];
    size_t i;

    if (body == NULL || body_len == 0)
        return (0);
    if (raptor_waf_normalize(body, body_len, norm, sizeof(norm)) == 0)
        return (0);
    for (i = 0; i < sizeof(bs) / sizeof(bs[0]); i++) {
        if (raptor_waf_strcasestr(norm, bs[i].s) != NULL) {
            snprintf(rule_out, rule_len, "%s", bs[i].t);
            return (1);
        }
    }
    return (0);
}

/* 9. Evaluation globale de l'URI et des en-tetes */
int
raptor_waf_inspect(const char *path, const char *query, const char *ua,
    const char *cookie, const char *referer,
    const char *client_ip, struct raptor_http_alert *alert_out)
{
    char rule[RAPTOR_ALERT_RULE_MAX];

    if (alert_out == NULL)
        return (0);
    memset(alert_out, 0, sizeof(*alert_out));
    if (raptor_waf_check_honeypot(path, rule, sizeof(rule)) ||
        raptor_waf_check_payload(path, query, rule, sizeof(rule)) ||
        raptor_waf_check_ua(ua, rule, sizeof(rule)) ||
        raptor_waf_check_header("COOKIE", cookie, rule, sizeof(rule)) ||
        raptor_waf_check_header("REFERER", referer, rule, sizeof(rule))) {
        snprintf(alert_out->client_ip, sizeof(alert_out->client_ip), "%s",
            client_ip ? client_ip : "0.0.0.0");
        snprintf(alert_out->rule_id, sizeof(alert_out->rule_id), "%s", rule);
        snprintf(alert_out->uri, sizeof(alert_out->uri), "%s", path ? path : "/");
        alert_out->severity = 2;
        return (1);
    }
    return (0);
}

/* 10. Evaluation du corps d'une requete POST/PUT */
int
raptor_waf_inspect_body(const char *path, const uint8_t *body, size_t body_len,
    const char *client_ip, struct raptor_http_alert *alert_out)
{
    char rule[RAPTOR_ALERT_RULE_MAX];

    if (alert_out == NULL)
        return (0);
    memset(alert_out, 0, sizeof(*alert_out));
    if (raptor_waf_check_body(body, body_len, rule, sizeof(rule))) {
        snprintf(alert_out->client_ip, sizeof(alert_out->client_ip), "%s",
            client_ip ? client_ip : "0.0.0.0");
        snprintf(alert_out->rule_id, sizeof(alert_out->rule_id), "%s", rule);
        snprintf(alert_out->uri, sizeof(alert_out->uri), "%s", path ? path : "/");
        alert_out->severity = 3;
        return (1);
    }
    return (0);
}
