/* =============================================================================
 * NOM DU SCRIPT   : src/engine/sentry_engine.c
 * RÉVISION        : Rev 1.4
 * PROJET          : RAPTOR DEFENSE v2.0 // Arsenal Souverain C99
 * RESPONSABILITÉ  : Interception passive kqueue (EVFILT_VNODE) à 0% CPU.
 * LISTE DES FONCTIONS NUMÉROTÉES :
 *   111. sentry_deploy_canary    : Dépose un leurre dense (32 Ko, KDBX4).
 *   112. sentry_init_fanotify    : Initialise le descripteur kqueue (VNODE).
 *   113. sentry_listen_loop      : Guet bloquant kevent() à 0% CPU.
 *   114. sentry_trigger_reflex   : Riposte réflexe et journalisation boîte noire.
 *   115. sentry_enter_stealth    : Camouflage proctitle et verrouillage RAM.
 * =============================================================================
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include <syslog.h>
#include "sentry_engine.h"
#include "rap_reflex.h"
#include "rap_oom.h"

void setproctitle(const char *fmt, ...);

__attribute__((unused)) static inline bool sentry_is_protected_pid(pid_t pid)
{
    if (pid <= 1) return true;
    if (pid == getpid()) return true;
    if (pid == getppid()) return true;
    return false;
}

/* =============================================================================
 * 111. sentry_deploy_canary
 * =============================================================================
 */
int sentry_deploy_canary(const char *dir_path)
{
    if (!dir_path || dir_path[0] == '\0') return -1;

    char canary_path[SENTRY_PATH_MAX];
    int ret = snprintf(canary_path, sizeof(canary_path), "%s/%s", dir_path, SENTRY_CANARY_NAME);
    if (ret <= 0 || (size_t)ret >= sizeof(canary_path)) return -1;

    int fd = open(canary_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) return -1;

    fchmod(fd, 0666);

    uint8_t chunk[512];
    const uint8_t kdbx_magic[12] = {
        0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 0x00, 0x00, 0x04, 0x00
    };

    uint32_t seed = 0x1337BEEF;
    for (int block = 0; block < 64; ++block) {
        for (int i = 0; i < 512; ++i) {
            seed = (seed * 1103515245U + 12345U) & 0x7FFFFFFFU;
            chunk[i] = (uint8_t)(seed ^ (block + i));
        }
        if (block == 0) {
            memcpy(chunk, kdbx_magic, sizeof(kdbx_magic));
        }
        ssize_t written = write(fd, chunk, sizeof(chunk));
        if (written != sizeof(chunk)) {
            close(fd);
            return -1;
        }
    }

    fdatasync(fd);
    close(fd);
    return 0;
}

static int   s_kq_canary_fds[SENTRY_MAX_TARGETS];
static char  s_kq_canary_paths[SENTRY_MAX_TARGETS][SENTRY_PATH_MAX];
static ino_t s_kq_canary_inodes[SENTRY_MAX_TARGETS];
static size_t s_kq_canary_count = 0;

static pid_t sentry_resolve_offender(ino_t target_ino)
{
    if (target_ino == 0) return 0;
    FILE *fp = popen("fstat -n 2>/dev/null", "r");
    if (!fp) return 0;

    char line[512];
    pid_t offender = 0;
    pid_t self_pid = getpid();
    pid_t parent_pid = getppid();

    while (fgets(line, sizeof(line), fp)) {
        char user[32], cmd[32];
        int pid_val = 0;
        unsigned long inum = 0;
        if (sscanf(line, "%31s %31s %d %*s %*s %lu", user, cmd, &pid_val, &inum) >= 4) {
            if ((ino_t)inum == target_ino) {
                if (pid_val > 1 && pid_val != self_pid && pid_val != parent_pid) {
                    offender = (pid_t)pid_val;
                    break;
                }
            }
        }
    }
    pclose(fp);
    return offender;
}

/* =============================================================================
 * 112. sentry_init_fanotify (Équivalent natif kqueue OpenBSD)
 * =============================================================================
 */
int sentry_init_fanotify(const SentryConfig *config)
{
    if (!config || config->target_count == 0) return -1;
    int kq = kqueue();
    if (kq < 0) return -1;

    s_kq_canary_count = 0;
    uint32_t marks_applied = 0;

    for (uint32_t i = 0; i < config->target_count && s_kq_canary_count < SENTRY_MAX_TARGETS; ++i) {
        const char *dir = config->target_dirs[i];
        if (!dir || dir[0] == '\0') continue;

        char canary_full_path[SENTRY_PATH_MAX];
        snprintf(canary_full_path, sizeof(canary_full_path), "%s/%s", dir, SENTRY_CANARY_NAME);

        if (access(canary_full_path, F_OK) != 0) {
            if (sentry_deploy_canary(dir) != 0) continue;
        }

        int fd = open(canary_full_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;

        struct stat st;
        if (fstat(fd, &st) != 0) {
            close(fd);
            continue;
        }

        struct kevent ev;
        EV_SET(&ev, fd, EVFILT_VNODE, EV_ADD | EV_ENABLE | EV_CLEAR,
               NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_RENAME, 0, NULL);

        if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0) {
            close(fd);
            continue;
        }

        s_kq_canary_fds[s_kq_canary_count] = fd;
        strncpy(s_kq_canary_paths[s_kq_canary_count], canary_full_path, sizeof(s_kq_canary_paths[s_kq_canary_count]) - 1);
        s_kq_canary_paths[s_kq_canary_count][sizeof(s_kq_canary_paths[s_kq_canary_count]) - 1] = '\0';
        s_kq_canary_inodes[s_kq_canary_count] = st.st_ino;
        s_kq_canary_count++;
        marks_applied++;
    }

    if (marks_applied == 0) {
        close(kq);
        return -1;
    }
    return kq;
}

/* =============================================================================
 * 114. sentry_trigger_reflex
 * =============================================================================
 */
int sentry_trigger_reflex(int fanotify_fd, int fd_event, pid_t pid)
{
    (void)fanotify_fd;
    (void)fd_event;

    int reflex_ret = rap_reflex_dispatch(pid, TRIGGER_CANARY_BREACH);

    uint64_t neutralized = 0;
    reflex_mode_t mode = rap_reflex_get_stats(&neutralized);
    const char *mode_str = (mode == REFLEX_MODE_ARMED) ? "ARMÉ (SIGSTOP + SIGKILL)" :
                           (mode == REFLEX_MODE_DRYRUN) ? "SIMULATION (DRY-RUN)" : "PASSIF (ALERTE SEULE)";

    char alert_msg[512];
    int msg_len = snprintf(alert_msg, sizeof(alert_msg),
        "\n\033[1;31m[ALERTE SENTINELLE]\033[0m ATTEINTE AU CANARI INTERCEPTÉE !\n"
        "   -> PID AGRESSEUR       : %d\n"
        "   -> DÉTECTION NOYAU     : KQUEUE (EVFILT_VNODE)\n"
        "   -> MODE RÉFLEXE        : %s\n"
        "   -> JOURNALISATION      : BOÎTE NOIRE RAM (/raptor_blackbox)\n",
        (int)pid, mode_str);

    if (msg_len > 0) {
        write(STDERR_FILENO, alert_msg, (size_t)msg_len);
    }
    openlog("raptor-sentry", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    syslog(LOG_ALERT, "ATTEINTE AU CANARI INTERCEPTEE | PID=%d |  MODE=ARME | BLACKBOX=/raptor_blackbox", (int)pid);
    closelog();
    return reflex_ret;
}

/* =============================================================================
 * 113. sentry_listen_loop
 * =============================================================================
 */
int sentry_listen_loop(int fanotify_fd, const SentryConfig *config)
{
    if (fanotify_fd < 0 || !config) return -1;

    struct kevent ev;
    while (1) {
        int nev = kevent(fanotify_fd, NULL, 0, &ev, 1, NULL);
        if (nev < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (nev == 0) continue;

        int triggered_fd = (int)ev.ident;
        ino_t triggered_ino = 0;

        for (size_t i = 0; i < s_kq_canary_count; ++i) {
            if (s_kq_canary_fds[i] == triggered_fd) {
                triggered_ino = s_kq_canary_inodes[i];
                break;
            }
        }

        pid_t offender = sentry_resolve_offender(triggered_ino);
        sentry_trigger_reflex(fanotify_fd, triggered_fd, offender);

        if (ev.fflags & (NOTE_DELETE | NOTE_RENAME)) {
            close(triggered_fd);
        }
    }
    return 0;
}

/* =============================================================================
 * 115. sentry_enter_stealth
 * =============================================================================
 */
int sentry_enter_stealth(const char *fake_name)
{
    if (fake_name && fake_name[0] != '\0') {
        setproctitle("%s", fake_name);
    } else {
        setproctitle("kworker/u16:3");
    }

    rap_oom_protect();

    if (rap_oom_lock_memory() != 0) {
        return -1;
    }
    return 0;
}
