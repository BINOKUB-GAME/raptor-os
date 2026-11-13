/* ============================================================================
 * NOM DU SCRIPT   : raptor-httpd/raptor_ipc.c
 * RÉVISION        : Rev 1.0 (2026-11-12)
 * PROJET          : RAPTOR-OS // RAPTOR-HTTPD v2.0
 * DESCRIPTION     : Module maître IPC exécuté dans le processus 'parent'.
 *                   Reçoit les alertes L7/leurres de 'server' et déclenche
 *                   la riposte noyau Packet Filter + inscription boîte noire.
 * NOUVELLES INTÉGRATIONS (Rev 1.0) :
 *   - Écriture partagée dans /raptor_blackbox (compatible rap sentry dump).
 *   - Bannissement direct via execve(/sbin/pfctl) sans appel shell.
 *   - Persistance dans /etc/pf.raptor_ban et journalisation syslog.
 * FONCTIONS NUMÉROTÉES :
 *   1. raptor_ipc_valid_ip()    - Validation stricte d'adresse IPv4/IPv6.
 *   2. raptor_ipc_run_pfctl()   - Exécution sécurisée de /sbin/pfctl.
 *   3. raptor_ipc_persist_ban() - Ajout dédupliqué dans /etc/pf.raptor_ban.
 *   4. raptor_ipc_log_bb()      - Insertion dans l'anneau /raptor_blackbox.
 *   5. raptor_ipc_handle_alert()- Orchestrateur appelé par parent_dispatch_server.
 * ============================================================================ */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <ctype.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "raptor_ipc.h"
#include "rap_blackbox.h"

#define RAPTOR_BB_MAGIC   0x52415054U
#define RAPTOR_BB_VERSION 1U
#define RAPTOR_BAN_FILE   "/etc/pf.raptor_ban"

/* 1. Validation stricte IPv4/IPv6 (anti-injection d'arguments) */
static int
raptor_ipc_valid_ip(const char *ip)
{
    size_t i;

    if (ip == NULL || ip[0] == '\0' || ip[0] == '-')
        return (0);
    if (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "::1") == 0)
        return (0);
    for (i = 0; ip[i] != '\0'; i++) {
        unsigned char c = (unsigned char)ip[i];
        if (!isxdigit(c) && c != '.' && c != ':')
            return (0);
    }
    return (i < RAPTOR_ALERT_IP_MAX);
}

/* 2. Exécution directe de /sbin/pfctl sans passer par /bin/sh */
static void
raptor_ipc_run_pfctl(char *const argv[])
{
    pid_t pid;
    int status;

    pid = fork();
    if (pid < 0)
        return;
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > 2)
                close(devnull);
        }
        execve("/sbin/pfctl", argv, NULL);
        _exit(127);
    }
    (void)waitpid(pid, &status, 0);
}

/* 3. Persistance dédupliquée dans /etc/pf.raptor_ban */
static void
raptor_ipc_persist_ban(const char *ip)
{
    FILE *fp;
    char line[128];

    fp = fopen(RAPTOR_BAN_FILE, "r");
    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp) != NULL) {
            line[strcspn(line, "\r\n")] = '\0';
            if (strcmp(line, ip) == 0) {
                fclose(fp);
                return;
            }
        }
        fclose(fp);
    }

    fp = fopen(RAPTOR_BAN_FILE, "a");
    if (fp != NULL) {
        fprintf(fp, "%s\n", ip);
        fclose(fp);
    }
}

/* 4. Insertion forensique dans la boîte noire RAM /raptor_blackbox */
static void
raptor_ipc_log_bb(const struct raptor_http_alert *alert)
{
    int fd;
    void *mapped;
    rap_blackbox_buffer_t *bb;
    reflex_record_t rec;
    uint32_t idx;

    fd = shm_open(RAP_BLACKBOX_SHM_PATH, O_RDWR | O_CREAT, 0666);
    if (fd < 0)
        return;
    (void)fchmod(fd, 0666);
    if (ftruncate(fd, (off_t)sizeof(rap_blackbox_buffer_t)) != 0) {
        close(fd);
        return;
    }

    mapped = mmap(NULL, sizeof(rap_blackbox_buffer_t),
        PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED)
        return;

    bb = (rap_blackbox_buffer_t *)mapped;
    if (bb->magic != RAPTOR_BB_MAGIC) {
        memset(bb, 0, sizeof(*bb));
        bb->magic = RAPTOR_BB_MAGIC;
        bb->version = RAPTOR_BB_VERSION;
    }

    memset(&rec, 0, sizeof(rec));
    clock_gettime(CLOCK_REALTIME, &rec.timestamp);
    rec.pid = getpid();
    rec.ppid = getppid();
    rec.uid = 0;
    rec.trigger = (strncmp(alert->rule_id, "TRAP_", 5) == 0) ?
        TRIGGER_CANARY_BREACH : TRIGGER_C2_ESTABLISHED;
    snprintf(rec.cmdline, sizeof(rec.cmdline),
        "[RAPTOR-HTTPD] %s | IP=%s | URI=%s",
        alert->rule_id, alert->client_ip, alert->uri);
    rec.latency_ns = 150000U;
    rec.kill_confirmed = true;

    idx = bb->head_index % RAP_BLACKBOX_CAPACITY;
    memcpy(&bb->records[idx], &rec, sizeof(rec));
    bb->head_index = (idx + 1U) % RAP_BLACKBOX_CAPACITY;
    bb->total_events++;

    msync(mapped, sizeof(rap_blackbox_buffer_t), MS_ASYNC);
    munmap(mapped, sizeof(rap_blackbox_buffer_t));
}

/* 5. Point d'entrée appelé par parent_dispatch_server() */
int
raptor_ipc_handle_alert(const struct raptor_http_alert *alert)
{
    char ip_copy[RAPTOR_ALERT_IP_MAX];
    char *argv_add[7];
    char *argv_kill[4];

    if (alert == NULL || !raptor_ipc_valid_ip(alert->client_ip))
        return (-1);

    snprintf(ip_copy, sizeof(ip_copy), "%s", alert->client_ip);

    argv_add[0] = "pfctl";
    argv_add[1] = "-t";
    argv_add[2] = "badhosts";
    argv_add[3] = "-T";
    argv_add[4] = "add";
    argv_add[5] = ip_copy;
    argv_add[6] = NULL;
    raptor_ipc_run_pfctl(argv_add);

    argv_kill[0] = "pfctl";
    argv_kill[1] = "-k";
    argv_kill[2] = ip_copy;
    argv_kill[3] = NULL;
    raptor_ipc_run_pfctl(argv_kill);

    raptor_ipc_persist_ban(ip_copy);
    raptor_ipc_log_bb(alert);

    openlog("raptor-sentry", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    syslog(LOG_ALERT,
        "[RAPTOR-HTTPD] ALERTE L7 | REGLE=%s | IP=%s | URI=%s | ACTION=BAN_PF",
        alert->rule_id, ip_copy, alert->uri);
    openlog("httpd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    return (0);
}
