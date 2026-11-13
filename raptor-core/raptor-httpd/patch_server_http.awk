/^#include "patterns\.h"/ {
    print
    print "#include \"raptor_waf.h\""
    print "#include \"raptor_guard.h\""
    print "#include \"raptor_headers.h\""
    next
}
/while \(!clt->clt_headersdone\) \{/ {
    print "    if (!clt->clt_headersdone && clt->clt_tv_start.tv_sec > 0 &&"
    print "        (clt->clt_tv_last.tv_sec - clt->clt_tv_start.tv_sec) >"
    print "        RAPTOR_SLOW_HEADER_MAX_SEC) {"
    print "        struct raptor_http_alert ralert;"
    print "        char rip[RAPTOR_ALERT_IP_MAX];"
    print "        if (print_host(&clt->clt_ss, rip, sizeof(rip)) == NULL)"
    print "            strlcpy(rip, \"0.0.0.0\", sizeof(rip));"
    print "        if (raptor_guard_record_slowloris(rip, \"/\", &ralert))"
    print "            proc_compose(httpd_env->sc_ps, PROC_PARENT,"
    print "                IMSG_RAPTOR_ALERT, &ralert, sizeof(ralert));"
    print "        server_abort_http(clt, 408, \"request timeout\");"
    print "        goto abort;"
    print "    }"
    print
    next
}
/if \(fcgi_add_stdin\(clt, buf, size\) == -1\)/ {
    print "        {"
    print "            struct http_descriptor *rdesc = clt->clt_descreq;"
    print "            struct raptor_http_alert ralert;"
    print "            char rip[RAPTOR_ALERT_IP_MAX];"
    print "            if (print_host(&clt->clt_ss, rip, sizeof(rip)) == NULL)"
    print "                strlcpy(rip, \"0.0.0.0\", sizeof(rip));"
    print "            if (raptor_waf_inspect_body("
    print "                (rdesc != NULL) ? rdesc->http_path : \"/\","
    print "                (const uint8_t *)buf, size, rip, &ralert)) {"
    print "                proc_compose(httpd_env->sc_ps, PROC_PARENT,"
    print "                    IMSG_RAPTOR_ALERT, &ralert, sizeof(ralert));"
    print "                server_abort_http(clt, 403, \"Forbidden\");"
    print "                return;"
    print "            }"
    print "        }"
    print
    next
}
/if \(srv_conf->flags & SRVFLAG_BLOCK\)/ {
    print "    {"
    print "        struct raptor_http_alert ralert;"
    print "        struct kv rkey, *rhdr;"
    print "        char rip[RAPTOR_ALERT_IP_MAX];"
    print "        const char *rua = NULL, *rcookie = NULL, *rreferer = NULL;"
    print "        if (print_host(&clt->clt_ss, rip, sizeof(rip)) == NULL)"
    print "            strlcpy(rip, \"0.0.0.0\", sizeof(rip));"
    print "        if (raptor_guard_check_rate(rip, desc->http_path, &ralert)) {"
    print "            proc_compose(httpd_env->sc_ps, PROC_PARENT,"
    print "                IMSG_RAPTOR_ALERT, &ralert, sizeof(ralert));"
    print "            server_abort_http(clt, 429, \"Too Many Requests\");"
    print "    \t\treturn (-1);"
    print "        }"
    print "        rkey.kv_key = \"User-Agent\";"
    print "        if ((rhdr = kv_find(&desc->http_headers, &rkey)) != NULL)"
    print "            rua = rhdr->kv_value;"
    print "        rkey.kv_key = \"Cookie\";"
    print "        if ((rhdr = kv_find(&desc->http_headers, &rkey)) != NULL)"
    print "            rcookie = rhdr->kv_value;"
    print "        rkey.kv_key = \"Referer\";"
    print "        if ((rhdr = kv_find(&desc->http_headers, &rkey)) != NULL)"
    print "            rreferer = rhdr->kv_value;"
    print "        if (raptor_waf_inspect(desc->http_path, desc->http_query,"
    print "            rua, rcookie, rreferer, rip, &ralert)) {"
    print "            proc_compose(httpd_env->sc_ps, PROC_PARENT,"
    print "                IMSG_RAPTOR_ALERT, &ralert, sizeof(ralert));"
    print "            server_abort_http(clt, 403, \"Forbidden\");"
    print "    \t\treturn (-1);"
    print "        }"
    print "        if (clt->clt_bev != NULL && clt->clt_toread > 0) {"
    print "            struct evbuffer *rsrc = EVBUFFER_INPUT(clt->clt_bev);"
    print "            size_t rlen = EVBUFFER_LENGTH(rsrc);"
    print "            if (rlen > 0) {"
    print "                const uint8_t *rbuf = (const uint8_t *)EVBUFFER_DATA(rsrc);"
    print "                if (raptor_waf_inspect_body(desc->http_path,"
    print "                    rbuf, rlen, rip, &ralert)) {"
    print "                    proc_compose(httpd_env->sc_ps, PROC_PARENT,"
    print "                        IMSG_RAPTOR_ALERT, &ralert, sizeof(ralert));"
    print "                    server_abort_http(clt, 403, \"Forbidden\");"
    print "            \t\treturn (-1);"
    print "                }"
    print "            }"
    print "        }"
    print "    }"
    print
    next
}
/if \(kv_add\(&http_headers, "Connection", "close"\) == NULL\)/ {
    print "\tif (raptor_inject_sec_headers(&http_headers) == -1)"
    print "\t\tgoto done;"
    print
    next
}
/\/\* Is it a persistent connection\? \*\// {
    print "\tif (raptor_inject_sec_headers(&resp->http_headers) == -1)"
    print "\t\treturn (-1);"
    print
    next
}
{ print }
