/* ============================================================================
 * NOM DU SCRIPT : raptor-db-cgi/raptor_db_cgi.c
 * REVISION      : Rev 1.1 (2026-11-12)
 * PROJET        : RAPTOR-OS // PASSERELLE C NATIF <-> MYSQLD
 * DESCRIPTION   : Binaire CGI statique interrogeant raptor_db en lecture.
 * INTEGRATIONS  : libmariadb (127.0.0.1:3306), slowcgi(8), pledge(2) 2 etapes.
 * FONCTIONS     : 1.cgi_send_json_err 2.cgi_query_status 3.main
 * ============================================================================ */

#include <mysql.h>
#include <stdio.h>
#include <unistd.h>

#define DB_HOST "127.0.0.1"
#define DB_USER "raptor_app"
#define DB_PASS "CHANGE_ME_RAPTOR_APP_PASS"
#define DB_NAME "raptor_db"

/* 1. Reponse HTTP JSON en cas d'erreur */
static void
cgi_send_json_err(const char *msg)
{
    printf("Status: 500 Internal Server Error\r\n");
    printf("Content-Type: application/json\r\n\r\n");
    printf("{\"status\":\"error\",\"detail\":\"%s\"}\n", msg);
}

/* 2. Lecture de la table raptor_status et emission JSON */
static int
cgi_query_status(MYSQL *conn)
{
    MYSQL_RES *res;
    MYSQL_ROW row;
    int first = 1;

    if (mysql_query(conn,
        "SELECT id, component, updated_at FROM raptor_status LIMIT 5") != 0)
        return (-1);
    if ((res = mysql_store_result(conn)) == NULL)
        return (-1);
    printf("Content-Type: application/json\r\n\r\n");
    printf("{\"status\":\"ok\",\"engine\":\"C-CGI\",\"rows\":[");
    while ((row = mysql_fetch_row(res)) != NULL) {
        printf("%s{\"id\":%s,\"component\":\"%s\",\"updated_at\":\"%s\"}",
            first ? "" : ",",
            row[0] ? row[0] : "0",
            row[1] ? row[1] : "",
            row[2] ? row[2] : "");
        first = 0;
    }
    printf("]}\n");
    mysql_free_result(res);
    return (0);
}

/* 3. Point d'entree CGI sous double confinement pledge(2) */
int
main(void)
{
    MYSQL *conn;

    if ((conn = mysql_init(NULL)) == NULL) {
        cgi_send_json_err("mysql_init_failed");
        return (1);
    }
    if (pledge("stdio rpath inet dns", NULL) < 0) {
        cgi_send_json_err("pledge_stage1_failed");
        mysql_close(conn);
        return (1);
    }
    if (mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS,
        DB_NAME, 3306, NULL, 0) == NULL) {
        cgi_send_json_err("db_connect_failed");
        mysql_close(conn);
        return (1);
    }
    if (pledge("stdio", NULL) < 0) {
        cgi_send_json_err("pledge_stage2_failed");
        mysql_close(conn);
        return (1);
    }
    if (cgi_query_status(conn) < 0)
        cgi_send_json_err("query_failed");
    mysql_close(conn);
    return (0);
}
