
#include "aegiscore.h"

void clear(struct context *ctx) {
    if (ctx->tun_buffer != NULL) {
        ng_free(ctx->tun_buffer, __FILE__, __LINE__);
        ctx->tun_buffer = NULL;
        ctx->tun_buffer_size = 0;
    }
    if (ctx->flow_table != NULL) {
        ng_free(ctx->flow_table, __FILE__, __LINE__);
        ctx->flow_table = NULL;
        ctx->flow_table_size = 0;
    }
    struct ng_session *s = ctx->ng_session;
    while (s != NULL) {
        if (s->socket >= 0 && close(s->socket))
            log_android(ANDROID_LOG_ERROR, "close %d error %d: %s",
                        s->socket, errno, strerror(errno));
        if (s->protocol == IPPROTO_TCP)
            clear_tcp_data(&s->tcp);
        struct ng_session *p = s;
        s = s->next;
        ng_free(p, __FILE__, __LINE__);
    }
    ctx->ng_session = NULL;
}

static void flush_flow_entry(const struct arguments *args, struct flow_log_entry *e) {
    if (e->used && e->count > 0) {
        jobject pkt = create_packet(
                args, e->version, e->protocol, e->flags,
                e->saddr, e->sport, e->daddr, e->dport,
                "", e->uid, e->allowed);
        if (pkt != NULL) {
            if (fidCount != NULL)
                (*args->env)->SetIntField(args->env, pkt, fidCount, (jint) e->count);
            log_packet(args, pkt);
        }
        e->count = 0;
    }
}

int flow_log_absorb(const struct arguments *args,
                    jint version,
                    jint protocol,
                    const char *flags,
                    const char *source,
                    jint sport,
                    const char *dest,
                    jint dport,
                    const char *data,
                    jint uid,
                    jboolean allowed) {
    if (args == NULL || args->ctx == NULL || args->ctx->flow_table == NULL || args->ctx->flow_table_size == 0)
        return 0;

    int is_sni = (data != NULL && strcmp(data, "sni") == 0);
    const char *daddr = (dest != NULL) ? dest : "";

    // 32-bit FNV-1a hash of the key: (uid, protocol, dport, allowed, daddr string)
    uint32_t hash = 2166136261u;
    hash ^= (uint32_t) uid;
    hash *= 16777619u;
    hash ^= (uint32_t) protocol;
    hash *= 16777619u;
    hash ^= (uint32_t) dport;
    hash *= 16777619u;
    hash ^= (uint32_t) (allowed ? 1 : 0);
    hash *= 16777619u;
    for (const char *p = daddr; *p; p++) {
        hash ^= (uint8_t) *p;
        hash *= 16777619u;
    }

    struct flow_log_entry *table = args->ctx->flow_table;
    size_t table_size = args->ctx->flow_table_size;
    uint32_t base = hash % table_size;

    int match_idx = -1;
    int empty_idx = -1;
    int oldest_idx = -1;
    long long oldest_time = 0;

    for (int i = 0; i < 8; i++) {
        int idx = (int) ((base + i) % table_size);
        struct flow_log_entry *e = &table[idx];
        if (e->used) {
            if (e->uid == uid &&
                e->protocol == protocol &&
                e->dport == dport &&
                e->allowed == allowed &&
                strcmp(e->daddr, daddr) == 0) {
                match_idx = idx;
                break;
            }
            if (oldest_idx == -1 || e->last_seen < oldest_time) {
                oldest_idx = idx;
                oldest_time = e->last_seen;
            }
        } else {
            if (empty_idx == -1) {
                empty_idx = idx;
            }
        }
    }

    if (match_idx != -1) {
        if (!is_sni) {
            table[match_idx].count++;
            table[match_idx].last_seen = get_ms();
            return 1;
        }

        // SNI packet: cannot absorb, must cross JNI.
        // Flush any prior counts so they aren't lost, then refresh the entry.
        flush_flow_entry(args, &table[match_idx]);
        struct flow_log_entry *e = &table[match_idx];
        e->version = version;
        e->sport = sport;
        strncpy(e->saddr, (source != NULL) ? source : "", sizeof(e->saddr) - 1);
        e->saddr[sizeof(e->saddr) - 1] = '\0';
        strncpy(e->flags, (flags != NULL) ? flags : "", sizeof(e->flags) - 1);
        e->flags[sizeof(e->flags) - 1] = '\0';
        e->count = 0;
        e->last_seen = get_ms();
        return 0;
    }

    // No match: insert or refresh entry
    int target_idx = (empty_idx != -1) ? empty_idx : oldest_idx;
    if (target_idx < 0)
        return 0;

    struct flow_log_entry *e = &table[target_idx];
    if (e->used) {
        // Reuse slot: flush oldest if it had counts
        flush_flow_entry(args, e);
    }

    e->used = 1;
    e->uid = uid;
    e->protocol = protocol;
    e->version = version;
    e->dport = dport;
    e->sport = sport;
    e->allowed = allowed;
    strncpy(e->daddr, daddr, sizeof(e->daddr) - 1);
    e->daddr[sizeof(e->daddr) - 1] = '\0';
    strncpy(e->saddr, (source != NULL) ? source : "", sizeof(e->saddr) - 1);
    e->saddr[sizeof(e->saddr) - 1] = '\0';
    strncpy(e->flags, (flags != NULL) ? flags : "", sizeof(e->flags) - 1);
    e->flags[sizeof(e->flags) - 1] = '\0';
    e->count = 0;
    e->last_seen = get_ms();
    return 0;
}

void flow_log_flush(const struct arguments *args, long long now_ms) {
    if (args == NULL || args->ctx == NULL || args->ctx->flow_table == NULL)
        return;

    for (size_t i = 0; i < args->ctx->flow_table_size; i++) {
        struct flow_log_entry *e = &args->ctx->flow_table[i];
        if (!e->used)
            continue;

        if (e->count > 0) {
            flush_flow_entry(args, e);
        } else if (now_ms - e->last_seen > 60000LL) {
            e->used = 0;
        }
    }
}

void *handle_events(void *a) {
    struct arguments *args = (struct arguments *) a;
    log_android(ANDROID_LOG_WARN, "Start events tun=%d", args->tun);

    uint16_t mtu = get_mtu();
    if (args->ctx->tun_buffer == NULL || args->ctx->tun_buffer_size < mtu) {
        if (args->ctx->tun_buffer != NULL)
            ng_free(args->ctx->tun_buffer, __FILE__, __LINE__);
        args->ctx->tun_buffer = ng_malloc(mtu, "tun read");
        args->ctx->tun_buffer_size = mtu;
    }
    if (args->ctx->flow_table == NULL) {
        args->ctx->flow_table_size = FLOW_TABLE_SIZE;
        args->ctx->flow_table = ng_calloc(args->ctx->flow_table_size, sizeof(struct flow_log_entry), "flow_table");
    }

    // Get max number of sessions
    int maxsessions = SESSION_MAX;
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim))
        log_android(ANDROID_LOG_WARN, "getrlimit error %d: %s", errno, strerror(errno));
    else {
        maxsessions = (int) (rlim.rlim_cur * SESSION_LIMIT / 100);
        if (maxsessions > SESSION_MAX)
            maxsessions = SESSION_MAX;
        log_android(ANDROID_LOG_WARN, "getrlimit soft %d hard %d max sessions %d",
                    rlim.rlim_cur, rlim.rlim_max, maxsessions);
    }

    // Terminate existing sessions not allowed anymore
    check_allowed(args);

    // Open epoll file
    int epoll_fd = epoll_create(1);
    if (epoll_fd < 0) {
        log_android(ANDROID_LOG_ERROR, "epoll create error %d: %s", errno, strerror(errno));
        report_exit(args, "epoll create error %d: %s", errno, strerror(errno));
        args->ctx->stopping = 1;
    }

    // Monitor stop events
    struct epoll_event ev_pipe;
    memset(&ev_pipe, 0, sizeof(struct epoll_event));
    ev_pipe.events = EPOLLIN | EPOLLERR;
    ev_pipe.data.ptr = &ev_pipe;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, args->ctx->pipefds[0], &ev_pipe)) {
        log_android(ANDROID_LOG_ERROR, "epoll add pipe error %d: %s", errno, strerror(errno));
        report_exit(args, "epoll add pipe error %d: %s", errno, strerror(errno));
        args->ctx->stopping = 1;
    }

    // Monitor tun events
    struct epoll_event ev_tun;
    memset(&ev_tun, 0, sizeof(struct epoll_event));
    ev_tun.events = EPOLLIN | EPOLLERR;
    ev_tun.data.ptr = NULL;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, args->tun, &ev_tun)) {
        log_android(ANDROID_LOG_ERROR, "epoll add tun error %d: %s", errno, strerror(errno));
        report_exit(args, "epoll add tun error %d: %s", errno, strerror(errno));
        args->ctx->stopping = 1;
    }

    // Loop
    long long last_check = 0;
    long long last_flow_flush = 0;
    while (!args->ctx->stopping) {
        log_android(ANDROID_LOG_DEBUG, "Loop");

        int recheck = 0;
        int timeout = EPOLL_TIMEOUT;

        // Count sessions
        int isessions = 0;
        int usessions = 0;
        int tsessions = 0;
        struct ng_session *s = args->ctx->ng_session;
        while (s != NULL) {
            if (s->protocol == IPPROTO_ICMP || s->protocol == IPPROTO_ICMPV6) {
                if (!s->icmp.stop)
                    isessions++;
            } else if (s->protocol == IPPROTO_UDP) {
                if (s->udp.state == UDP_ACTIVE)
                    usessions++;
            } else if (s->protocol == IPPROTO_TCP) {
                if (s->tcp.state != TCP_CLOSING && s->tcp.state != TCP_CLOSE)
                    tsessions++;
                if (s->socket >= 0)
                    recheck = recheck | monitor_tcp_session(args, s, epoll_fd);
            }
            s = s->next;
        }
        int sessions = isessions + usessions + tsessions;

        // Check sessions
        long long ms = get_ms();
        if (ms - last_check > EPOLL_MIN_CHECK) {
            last_check = ms;

            if (ms - last_flow_flush >= 1000) {
                last_flow_flush = ms;
                flow_log_flush(args, ms);
            }

            time_t now = time(NULL);
            struct ng_session *sl = NULL;
            s = args->ctx->ng_session;
            while (s != NULL) {
                int del = 0;
                if (s->protocol == IPPROTO_ICMP || s->protocol == IPPROTO_ICMPV6) {
                    del = check_icmp_session(args, s, sessions, maxsessions);
                    if (!s->icmp.stop && !del) {
                        int stimeout = s->icmp.time +
                                       get_icmp_timeout(&s->icmp, sessions, maxsessions) - now + 1;
                        if (stimeout > 0 && stimeout < timeout)
                            timeout = stimeout;
                    }
                } else if (s->protocol == IPPROTO_UDP) {
                    del = check_udp_session(args, s, sessions, maxsessions);
                    if (s->udp.state == UDP_ACTIVE && !del) {
                        int stimeout = s->udp.time +
                                       get_udp_timeout(&s->udp, sessions, maxsessions) - now + 1;
                        if (stimeout > 0 && stimeout < timeout)
                            timeout = stimeout;
                    }
                } else if (s->protocol == IPPROTO_TCP) {
                    del = check_tcp_session(args, s, sessions, maxsessions);
                    if (s->tcp.state != TCP_CLOSING && s->tcp.state != TCP_CLOSE && !del) {
                        int stimeout = s->tcp.time +
                                       get_tcp_timeout(&s->tcp, sessions, maxsessions) - now + 1;
                        if (stimeout > 0 && stimeout < timeout)
                            timeout = stimeout;
                    }
                }

                if (del) {
                    if (sl == NULL)
                        args->ctx->ng_session = s->next;
                    else
                        sl->next = s->next;

                    struct ng_session *c = s;
                    s = s->next;
                    if (c->protocol == IPPROTO_TCP)
                        clear_tcp_data(&c->tcp);
                    ng_free(c, __FILE__, __LINE__);
                } else {
                    sl = s;
                    s = s->next;
                }
            }
        } else {
            recheck = 1;
            log_android(ANDROID_LOG_DEBUG, "Skipped session checks");
        }

        log_android(ANDROID_LOG_DEBUG,
                    "sessions ICMP %d UDP %d TCP %d max %d/%d timeout %d recheck %d",
                    isessions, usessions, tsessions, sessions, maxsessions, timeout, recheck);

        // Poll
        struct epoll_event ev[EPOLL_EVENTS];
        int ready = epoll_wait(epoll_fd, ev, EPOLL_EVENTS,
                               recheck ? EPOLL_MIN_CHECK : timeout * 1000);

        if (ready < 0) {
            if (errno == EINTR) {
                log_android(ANDROID_LOG_DEBUG, "epoll interrupted tun %d", args->tun);
                continue;
            } else {
                log_android(ANDROID_LOG_ERROR,
                            "epoll tun %d error %d: %s",
                            args->tun, errno, strerror(errno));
                report_exit(args, "epoll tun %d error %d: %s",
                            args->tun, errno, strerror(errno));
                break;
            }
        }

        if (ready == 0)
            log_android(ANDROID_LOG_DEBUG, "epoll timeout");
        else {

            if (pthread_mutex_lock(&args->ctx->lock))
                log_android(ANDROID_LOG_ERROR, "pthread_mutex_lock failed");

            int error = 0;

            for (int i = 0; i < ready; i++) {
                if (ev[i].data.ptr == &ev_pipe) {
                    // Check pipe
                    uint8_t buffer[1];
                    if (read(args->ctx->pipefds[0], buffer, 1) < 0)
                        log_android(ANDROID_LOG_WARN, "Read pipe error %d: %s",
                                    errno, strerror(errno));
                    else
                        log_android(ANDROID_LOG_WARN, "Read pipe");

                } else if (ev[i].data.ptr == NULL) {
                    // Check upstream
                    log_android(ANDROID_LOG_DEBUG, "epoll ready %d/%d in %d out %d err %d hup %d",
                                i, ready,
                                (ev[i].events & EPOLLIN) != 0,
                                (ev[i].events & EPOLLOUT) != 0,
                                (ev[i].events & EPOLLERR) != 0,
                                (ev[i].events & EPOLLHUP) != 0);

                    int count = 0;
                    while (count < TUN_YIELD && !error && !args->ctx->stopping &&
                           is_readable(args->tun)) {
                        count++;
                        if (check_tun(args, &ev[i], epoll_fd, sessions, maxsessions) < 0)
                            error = 1;
                    }

                } else {
                    // Check downstream
                    log_android(ANDROID_LOG_DEBUG,
                                "epoll ready %d/%d in %d out %d err %d hup %d prot %d sock %d",
                                i, ready,
                                (ev[i].events & EPOLLIN) != 0,
                                (ev[i].events & EPOLLOUT) != 0,
                                (ev[i].events & EPOLLERR) != 0,
                                (ev[i].events & EPOLLHUP) != 0,
                                ((struct ng_session *) ev[i].data.ptr)->protocol,
                                ((struct ng_session *) ev[i].data.ptr)->socket);

                    struct ng_session *session = (struct ng_session *) ev[i].data.ptr;
                    if (session->protocol == IPPROTO_ICMP ||
                        session->protocol == IPPROTO_ICMPV6)
                        check_icmp_socket(args, &ev[i]);
                    else if (session->protocol == IPPROTO_UDP) {
                        int count = 0;
                        while (count < UDP_YIELD && !args->ctx->stopping &&
                               !(ev[i].events & EPOLLERR) && (ev[i].events & EPOLLIN) &&
                               is_readable(session->socket)) {
                            count++;
                            check_udp_socket(args, &ev[i]);
                        }
                    } else if (session->protocol == IPPROTO_TCP)
                        check_tcp_socket(args, &ev[i], epoll_fd);
                }

                if (error)
                    break;
            }

            if (pthread_mutex_unlock(&args->ctx->lock))
                log_android(ANDROID_LOG_ERROR, "pthread_mutex_unlock failed");

            if (error)
                break;
        }
    }

    // Close epoll file
    if (epoll_fd >= 0 && close(epoll_fd))
        log_android(ANDROID_LOG_ERROR,
                    "epoll close error %d: %s", errno, strerror(errno));

    log_android(ANDROID_LOG_WARN, "Stopped events tun=%d", args->tun);

    // Cleanup
    ng_free(args, __FILE__, __LINE__);

    return NULL;
}

void check_allowed(const struct arguments *args) {
    char source[INET6_ADDRSTRLEN + 1];
    char dest[INET6_ADDRSTRLEN + 1];

    struct ng_session *l = NULL;
    struct ng_session *s = args->ctx->ng_session;
    while (s != NULL) {
        if (s->protocol == IPPROTO_ICMP || s->protocol == IPPROTO_ICMPV6) {
            if (!s->icmp.stop) {
                if (s->icmp.version == 4) {
                    inet_ntop(AF_INET, &s->icmp.saddr.ip4, source, sizeof(source));
                    inet_ntop(AF_INET, &s->icmp.daddr.ip4, dest, sizeof(dest));
                } else {
                    inet_ntop(AF_INET6, &s->icmp.saddr.ip6, source, sizeof(source));
                    inet_ntop(AF_INET6, &s->icmp.daddr.ip6, dest, sizeof(dest));
                }

                jobject objPacket = create_packet(
                        args, s->icmp.version, IPPROTO_ICMP, "",
                        source, 0, dest, 0, "", s->icmp.uid, 0);
                if (is_address_allowed(args, objPacket) == NULL) {
                    s->icmp.stop = 1;
                    log_android(ANDROID_LOG_WARN, "ICMP terminate %d uid %d",
                                s->socket, s->icmp.uid);
                }
            }

        } else if (s->protocol == IPPROTO_UDP) {
            if (s->udp.state == UDP_ACTIVE) {
                if (s->udp.version == 4) {
                    inet_ntop(AF_INET, &s->udp.saddr.ip4, source, sizeof(source));
                    inet_ntop(AF_INET, &s->udp.daddr.ip4, dest, sizeof(dest));
                } else {
                    inet_ntop(AF_INET6, &s->udp.saddr.ip6, source, sizeof(source));
                    inet_ntop(AF_INET6, &s->udp.daddr.ip6, dest, sizeof(dest));
                }

                jobject objPacket = create_packet(
                        args, s->udp.version, IPPROTO_UDP, "",
                        source, ntohs(s->udp.source), dest, ntohs(s->udp.dest), "", s->udp.uid, 0);
                if (is_address_allowed(args, objPacket) == NULL) {
                    s->udp.state = UDP_FINISHING;
                    log_android(ANDROID_LOG_WARN, "UDP terminate session socket %d uid %d",
                                s->socket, s->udp.uid);
                }
            } else if (s->udp.state == UDP_BLOCKED) {
                log_android(ANDROID_LOG_WARN, "UDP remove blocked session uid %d", s->udp.uid);

                if (l == NULL)
                    args->ctx->ng_session = s->next;
                else
                    l->next = s->next;

                struct ng_session *c = s;
                s = s->next;
                ng_free(c, __FILE__, __LINE__);
                continue;
            }

        } else if (s->protocol == IPPROTO_TCP) {
            if (s->tcp.state != TCP_CLOSING && s->tcp.state != TCP_CLOSE) {
                if (s->tcp.version == 4) {
                    inet_ntop(AF_INET, &s->tcp.saddr.ip4, source, sizeof(source));
                    inet_ntop(AF_INET, &s->tcp.daddr.ip4, dest, sizeof(dest));
                } else {
                    inet_ntop(AF_INET6, &s->tcp.saddr.ip6, source, sizeof(source));
                    inet_ntop(AF_INET6, &s->tcp.daddr.ip6, dest, sizeof(dest));
                }

                jobject objPacket = create_packet(
                        args, s->tcp.version, IPPROTO_TCP, "",
                        source, ntohs(s->tcp.source), dest, ntohs(s->tcp.dest), "", s->tcp.uid, 0);
                if (is_address_allowed(args, objPacket) == NULL) {
                    write_rst(args, &s->tcp);
                    log_android(ANDROID_LOG_WARN, "TCP terminate socket %d uid %d",
                                s->socket, s->tcp.uid);
                }
            }

        }

        l = s;
        s = s->next;
    }
}

