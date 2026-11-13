#ifndef RAPTOR_IPC_H
#define RAPTOR_IPC_H

#include <stdint.h>

#define RAPTOR_ALERT_IP_MAX   64
#define RAPTOR_ALERT_RULE_MAX 32
#define RAPTOR_ALERT_URI_MAX  256

struct raptor_http_alert {
    char client_ip[RAPTOR_ALERT_IP_MAX];
    char rule_id[RAPTOR_ALERT_RULE_MAX];
    char uri[RAPTOR_ALERT_URI_MAX];
    uint32_t severity;
};

int raptor_ipc_handle_alert(const struct raptor_http_alert *alert);

#endif
