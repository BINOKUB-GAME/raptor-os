/* ============================================================================
 * NOM DU SCRIPT : raptor-db-cgi/raptor_db_post.c
 * REVISION      : Rev 1.0 (2026-11-12)
 * PROJET        : RAPTOR-OS // PASSERELLE C-CGI POST <-> MYSQLD
 * DESCRIPTION   : Insertion securisee via requete preparee mysql_stmt_prepare.
 * INTEGRATIONS  : libmariadb (127.0.0.1:3306), slowcgi(8), pledge(2) 2 etapes.
 * FONCTIONS     : 1.post_send_json 2.post_url_decode 3.post_read_component
 *                 4.post_insert_status 5.main
 * ============================================================================ */

#include <ctype.h>
#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DB_HOST "127.0.0.1"
#define DB_USER "raptor_app"
#define DB_PASS "CHANGE_ME_RAPTOR_APP_PASS"
#define DB_NAME "raptor_db"

/* 1. Emission de la reponse HTTP JSON */
static void
post_send_json(int code, const char *status, const char *detail)
{
    if (code != 200)
        printf("Status: %d Error\r\n", code);
    printf("Content-Type: application/json\r\n\r\n");
    printf("{\"status\":\"%s\",\"engine\":\"C-CGI-POST\",\"detail\":\"%s\"}\n",
        status, detail);
}

/* 2. Decodage URL (%XX et +) vers tampon borne */
static void
post_url_decode(const char *src, char *dst, size_t dst_sz)
{
    size_t si = 0, di = 0;
    char hex[3];

    while (src[si] != '\0' && di + 1 < dst_sz) {
        if (src[si] == '+') {
            dst[di++] = ' ';
            si++;
        } else if (src[si] == '%' &&
            isxdigit((unsigned char)src[si + 1]) &&
            isxdigit((unsigned char)src[si + 2])) {
            hex[0] = src[si + 1];
            hex[1] = src[si + 2];
            hex[2] = '\0';
            dst[di++] = (char)strtol(hex, NULL, 16);
            si += 3;
        } else {
            dst[di++] = src[si++];
        }
    }
    dst[di] = '\0';
}

/* 3. Lecture du corps POST sur stdin et extraction de component */
static int
post_read_component(char *out, size_t out_sz)
{
    const char *meth = getenv("REQUEST_METHOD");
    const char *clen = getenv("CONTENT_LENGTH");
    char body[512], *p, *amp;
    long len;
    size_t n;

    if (meth == NULL || strcmp(meth, "POST") != 0 || clen == NULL)
        return (-1);
    len = strtol(clen, NULL, 10);
    if (len <= 0 || len >= (long)sizeof(body))
        return (-1);
    n = fread(body, 1, (size_t)len, stdin);
    body[n] = '\0';
    if ((p = strstr(body, "component=")) == NULL)
        return (-1);
    p += 10;
    if ((amp = strchr(p, '&')) != NULL)
        *amp = '\0';
    post_url_decode(p, out, out_sz);
    return (out[0] != '\0') ? 0 : -1;
}

/* 4. Insertion parametree via mysql_stmt_prepare() */
static int
post_insert_status(MYSQL *conn, const char *comp)
{
    MYSQL_STMT *stmt;
    MYSQL_BIND bind[1];
    const char *sql = "INSERT INTO raptor_status (component) VALUES (?)";
    unsigned long slen;
    char buf[64];

    strlcpy(buf, comp, sizeof(buf));
    slen = (unsigned long)strlen(buf);
    if ((stmt = mysql_stmt_init(conn)) == NULL)
        return (-1);
    if (mysql_stmt_prepare(stmt, sql, (unsigned long)strlen(sql)) != 0) {
        mysql_stmt_close(stmt);
        return (-1);
    }
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = buf;
    bind[0].buffer_length = sizeof(buf);
    bind[0].length = &slen;
    if (mysql_stmt_bind_param(stmt, bind) != 0 ||
        mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        return (-1);
    }
    mysql_stmt_close(stmt);
    return (0);
}

/* 5. Point d'entree CGI confine par double pledge(2) */
int
main(void)
{
    MYSQL *conn;
    char comp[64];

    if (post_read_component(comp, sizeof(comp)) < 0) {
        post_send_json(400, "error", "invalid_post_payload");
        return (1);
    }
    if ((conn = mysql_init(NULL)) == NULL) {
        post_send_json(500, "error", "mysql_init_failed");
        return (1);
    }
    if (pledge("stdio rpath inet dns", NULL) < 0 ||
        mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS,
        DB_NAME, 3306, NULL, 0) == NULL) {
        post_send_json(500, "error", "db_connect_failed");
        mysql_close(conn);
        return (1);
    }
    if (pledge("stdio", NULL) < 0 || post_insert_status(conn, comp) < 0) {
        post_send_json(500, "error", "stmt_insert_failed");
        mysql_close(conn);
        return (1);
    }
    post_send_json(200, "ok", comp);
    mysql_close(conn);
    return (0);
}
