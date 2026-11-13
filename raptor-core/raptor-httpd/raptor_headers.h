/* ============================================================================
 * NOM DU SCRIPT : raptor-httpd/raptor_headers.h
 * REVISION      : Rev 1.2 (2026-11-12)
 * PROJET        : RAPTOR-OS // RAPTOR-HTTPD v2.0
 * DESCRIPTION   : Injection native des en-tetes de durcissement navigateur.
 * INTEGRATIONS  : X-Frame-Options, nosniff, Referrer, Permissions, COOP, CSP.
 * FONCTIONS     : 1. raptor_inject_sec_headers() - Ajout dans un kvtree HTTP.
 * ============================================================================ */

#ifndef RAPTOR_HEADERS_H
#define RAPTOR_HEADERS_H

#define RAPTOR_CSP_VAL \
    "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'"

/* 1. Injection des 6 en-tetes de securite dans l'arbre HTTP */
static inline int
raptor_inject_sec_headers(struct kvtree *hdrs)
{
    if (kv_add(hdrs, "X-Frame-Options", "DENY") == NULL ||
        kv_add(hdrs, "X-Content-Type-Options", "nosniff") == NULL ||
        kv_add(hdrs, "Referrer-Policy", "no-referrer") == NULL ||
        kv_add(hdrs, "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()") == NULL ||
        kv_add(hdrs, "Cross-Origin-Opener-Policy", "same-origin") == NULL ||
        kv_add(hdrs, "Content-Security-Policy", RAPTOR_CSP_VAL) == NULL)
        return (-1);
    return (0);
}

#endif
