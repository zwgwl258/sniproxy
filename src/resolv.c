/*
 * Copyright (c) 2014, Dustin Lundquist <dustin@null-ptr.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ev.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#ifdef HAVE_LIBUDNS
#include <udns.h>
#ifdef HAVE_LIBMAXMINDDB
#include <maxminddb.h>
#endif
#endif
#include "resolv.h"
#include "address.h"
#include "logger.h"


int
resolv_is_country(const char *value) {
    return strlen(value) == 2 && value[0] >= 'A' && value[0] <= 'Z' &&
            value[1] >= 'A' && value[1] <= 'Z';
}

int
parse_client_cidr(const char *cidr, unsigned char *network, unsigned int *prefix) {
    const char *slash = strchr(cidr, '/');
    char address[INET6_ADDRSTRLEN];
    size_t len = slash ? (size_t)(slash - cidr) : strlen(cidr);
    if (len == 0 || len >= sizeof(address))
        return 0;
    memcpy(address, cidr, len);
    address[len] = '\0';
    int family = inet_pton(AF_INET, address, network) == 1 ? AF_INET :
                 inet_pton(AF_INET6, address, network) == 1 ? AF_INET6 : 0;
    if (!family)
        return 0;
    unsigned int max = family == AF_INET ? 32 : 128;
    if (!slash) {
        *prefix = max;
        return family;
    }
    const char *digits = slash + 1;
    if (!*digits || digits[strspn(digits, "0123456789")])
        return 0;
    unsigned long value = strtoul(digits, NULL, 10);
    if (value > max)
        return 0;
    *prefix = (unsigned int)value;
    return family;
}

struct ResolvQuery *
resolv_query(const char *hostname, int mode,
        void (*cb)(struct Address *, void *), void (*free_cb)(void *), void *data) {
    return resolv_query_client(hostname, mode, NULL, cb, free_cb, data);
}

#if !defined(HAVE_LIBUDNS) || !defined(HAVE_LIBMAXMINDDB)
int
resolv_open_country_db(const char *path) {
    (void)path;
    err("Country rules require a build with libudns and libmaxminddb");
    return -1;
}
#endif

#ifndef HAVE_LIBUDNS
int
resolv_add_client(struct ev_loop *loop, const char *cidr, char **nameservers,
        char **search, int mode) {
    (void)loop;
    (void)cidr;
    (void)nameservers;
    (void)search;
    (void)mode;
    return -1;
}

/*
 * If we do not have a DNS resolution library stub out module as no ops
 */

int
resolv_init(struct ev_loop *loop, char **nameservers, char **search_domains,
        int mode) {
    (void)loop;
    (void)nameservers;
    (void)search_domains;
    (void)mode;

    return 0;
}

void
resolv_shutdown(struct ev_loop *loop) {
    (void)loop;
}

struct ResolvQuery *
resolv_query_client(const char *hostname, int mode, const struct sockaddr_storage *peer,
        void (*client_cb)(struct Address *, void *),
        void (*client_free_cb)(void *), void *client_cb_data) {
    (void)hostname;
    (void)peer;
    (void)mode;
    (void)client_cb;
    (void)client_free_cb;
    (void)client_cb_data;

    return NULL;
}

void
resolv_cancel(struct ResolvQuery *query_handle) {
    (void)query_handle;
}

#else
/*
 * Implement DNS resolution interface using libudns
 */

struct ResolvQuery {
    struct dns_ctx *ctx;
    char *fallback_hostname;
    const struct DnsProbe *fallback_next;
    const struct DnsProbe *fallback_first;
    int fallback_preferred_pending;
    void (*client_cb)(struct Address *, void *);
    void (*client_free_cb)(void *);
    void *client_cb_data;
    int resolv_mode;
    struct dns_query *queries[2];
    size_t response_count;
    struct Address **responses;
};


struct Resolver {
    struct dns_ctx *ctx;
    struct ev_loop *loop;
    ev_io io;
    ev_timer timer;
    struct Resolver *next;
    struct DnsProbe *probes;
    ev_timer probe_timer;
    unsigned char network[16];
    char country[2];
    int family;
    unsigned int prefix;
    int mode;
};

static struct Resolver default_resolver;
static struct Resolver *client_resolvers;
static struct Resolver *fallback_resolver;
#ifdef HAVE_LIBMAXMINDDB
static MMDB_s country_db;
static int country_db_open;

int
resolv_open_country_db(const char *path) {
    int status = MMDB_open(path, MMDB_MODE_MMAP, &country_db);
    if (status != MMDB_SUCCESS) {
        err("Cannot open country database %s: %s", path, MMDB_strerror(status));
        return -1;
    }
    country_db_open = 1;
    return 0;
}

static struct Resolver *
select_country_resolver(const struct sockaddr_storage *peer) {
    if (!country_db_open)
        return &default_resolver;
    int status;
    MMDB_lookup_result_s result =
        MMDB_lookup_sockaddr(&country_db, (const struct sockaddr *)peer, &status);
    if (status != MMDB_SUCCESS || !result.found_entry)
        return &default_resolver;

    MMDB_entry_data_s value;
    status = MMDB_get_value(&result.entry, &value, "country", "iso_code", NULL);
    if (status != MMDB_SUCCESS || !value.has_data ||
            value.type != MMDB_DATA_TYPE_UTF8_STRING || value.data_size != 2)
        return &default_resolver;

    for (struct Resolver *r = client_resolvers; r != NULL; r = r->next)
        if (r->country[0] && memcmp(r->country, value.utf8_string, 2) == 0)
            return r;
    return &default_resolver;
}
#endif


static void resolv_sock_cb(struct ev_loop *, struct ev_io *, int);
static void resolv_timeout_cb(struct ev_loop *, struct ev_timer *, int);
static void dns_query_v4_cb(struct dns_ctx *, struct dns_rr_a4 *, void *);
static void dns_query_v6_cb(struct dns_ctx *, struct dns_rr_a6 *, void *);
static void dns_timer_setup_cb(struct dns_ctx *, int, void *);
static void process_client_callback(struct ResolvQuery *);
static void submit_queries(struct ResolvQuery *, const char *);
static void retry_fallback(struct ResolvQuery *);
static inline int all_queries_are_null(struct ResolvQuery *);
static struct Address *choose_ipv4_first(struct ResolvQuery *);
static struct Address *choose_ipv6_first(struct ResolvQuery *);
static struct Address *choose_any(struct ResolvQuery *);


static int
open_resolver(struct Resolver *resolver, struct ev_loop *loop,
        char **nameservers, char **search, int mode, int fast) {
    struct dns_ctx *ctx = resolver->ctx;
    resolver->loop = loop;
    resolver->mode = mode;
    if (nameservers == NULL) {
        /* Nameservers not specified, use system resolver config */
        dns_init(ctx, 0);
    } else {
        dns_reset(ctx);

        for (int i = 0; nameservers[i] != NULL; i++)
            if (dns_add_serv(ctx, nameservers[i]) < 0)
                fatal("Invalid or excess DNS nameserver: %s", nameservers[i]);

        if (search != NULL)
            for (int i = 0; search[i] != NULL; i++)
                dns_add_srch(ctx, search[i]);
    }

    if (fast) {
        dns_set_opt(ctx, DNS_OPT_TIMEOUT, 2);
        dns_set_opt(ctx, DNS_OPT_NTRIES, 1);
    }

    int sockfd = dns_open(ctx);
    if (sockfd < 0)
        fatal("Failed to open DNS resolver socket: %s",
                strerror(errno));

    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    ev_io_init(&resolver->io, resolv_sock_cb, sockfd, EV_READ);
    resolver->io.data = ctx;

    ev_io_start(loop, &resolver->io);


    ev_timer_init(&resolver->timer, resolv_timeout_cb, 0.0, 0.0);
    resolver->timer.data = ctx;

    dns_set_tmcbck(ctx, dns_timer_setup_cb, resolver);

    return sockfd;
}


struct DnsProbe {
    struct Resolver endpoint;
    char server[INET6_ADDRSTRLEN];
    char source[64];
    struct dns_query *query;
    ev_tstamp started;
    double latency; /* 0: unknown, negative: failed */
    struct DnsProbe *next;
};

static const struct DnsProbe *best_fallback_probe(void);

static void
probe_answer(struct DnsProbe *probe, int usable) {
    probe->query = NULL;
    probe->latency = usable ? ev_time() - probe->started + 0.000001 : -1;
    fprintf(stderr, "SNIPROXY_DNS_HEALTH %s %s %d\n",
            probe->source, probe->server, usable ? (int)(probe->latency * 1000) : -1);
    if (strcmp(probe->source, "fallback") == 0) {
        const struct DnsProbe *best = best_fallback_probe();
        fprintf(stderr, "SNIPROXY_DNS_PREFERRED %s\n", best ? best->server : "-");
    }
}

static void
probe_a4(struct dns_ctx *ctx, struct dns_rr_a4 *answer, void *data) {
    (void)ctx;
    probe_answer(data, answer != NULL && answer->dnsa4_nrr > 0);
    free(answer);
}

static void
probe_a6(struct dns_ctx *ctx, struct dns_rr_a6 *answer, void *data) {
    (void)ctx;
    probe_answer(data, answer != NULL && answer->dnsa6_nrr > 0);
    free(answer);
}

static void
probe_tick(struct ev_loop *loop, ev_timer *timer, int events) {
    (void)loop;
    (void)events;
    struct Resolver *resolver = timer->data;
    for (struct DnsProbe *p = resolver->probes; p != NULL; p = p->next) {
        if (p->query != NULL)
            continue;
        p->started = ev_time();
        p->query = resolver->mode == RESOLV_MODE_IPV6_ONLY
            ? dns_submit_a6(p->endpoint.ctx, "example.com.", 0, probe_a6, p)
            : dns_submit_a4(p->endpoint.ctx, "example.com.", 0, probe_a4, p);
        if (p->query == NULL)
            probe_answer(p, 0);
    }
}

static void
start_probes(struct Resolver *resolver, const char *source, char **nameservers) {
    if (nameservers == NULL)
        return;
    struct DnsProbe **tail = &resolver->probes;
    for (size_t i = 0; nameservers[i] != NULL; i++) {
        struct DnsProbe *p = calloc(1, sizeof(*p));
        if (p == NULL)
            break;
        p->endpoint.ctx = dns_new(NULL);
        if (p->endpoint.ctx == NULL) {
            free(p);
            break;
        }
        snprintf(p->server, sizeof(p->server), "%s", nameservers[i]);
        snprintf(p->source, sizeof(p->source), "%s", source);
        char *server[] = {nameservers[i], NULL};
        open_resolver(&p->endpoint, resolver->loop, server, NULL, resolver->mode, 1);
        *tail = p;
        tail = &p->next;
    }
    if (resolver->probes == NULL)
        return;
    ev_timer_init(&resolver->probe_timer, probe_tick, 0., 300.);
    resolver->probe_timer.data = resolver;
    ev_timer_start(resolver->loop, &resolver->probe_timer);
}

static int
resolver_unhealthy(const struct Resolver *resolver) {
    if (resolver->probes == NULL)
        return 0;
    for (const struct DnsProbe *p = resolver->probes; p != NULL; p = p->next)
        if (p->latency >= 0)
            return 0;
    return 1;
}

static const struct DnsProbe *
best_fallback_probe(void) {
    const struct DnsProbe *best = NULL;
    for (const struct DnsProbe *p = fallback_resolver->probes; p != NULL; p = p->next)
        if (p->latency > 0 && (best == NULL || p->latency < best->latency))
            best = p;
    return best;
}

struct BenchmarkRoute {
    char domain[254];
    char server[INET6_ADDRSTRLEN];
};

static const struct DnsProbe *
benchmark_preference(const char *hostname) {
    static time_t checked;
    static struct BenchmarkRoute *routes;
    static size_t count;
    time_t now = time(NULL);
    if (now != checked) {
        checked = now;
        count = 0;
        free(routes);
        routes = NULL;
        FILE *report = fopen("/run/sniproxy-dns-benchmark", "r");
        if (report != NULL) {
            struct stat info;
            size_t capacity = 0;
            char line[sizeof(struct BenchmarkRoute) + 4];
            if (fstat(fileno(report), &info) == 0 && info.st_mtime <= now &&
                    now - info.st_mtime <= 4500) {
                while (fgets(line, sizeof(line), report) != NULL && line[0] != '\n') {
                    struct BenchmarkRoute route;
                    if (sscanf(line, "%253s %45s", route.domain, route.server) != 2)
                        break;
                    if (count == capacity) {
                        size_t next = capacity ? capacity * 2 : 32;
                        struct BenchmarkRoute *grown = realloc(routes, next * sizeof(*routes));
                        if (grown == NULL)
                            break;
                        routes = grown;
                        capacity = next;
                    }
                    routes[count++] = route;
                }
            }
            fclose(report);
        }
    }
    size_t len = strlen(hostname);
    if (len && hostname[len - 1] == '.')
        len--;
    for (size_t i = 0; i < count; i++) {
        if (strlen(routes[i].domain) != len || strncasecmp(routes[i].domain, hostname, len) != 0)
            continue;
        for (const struct DnsProbe *p = fallback_resolver->probes; p != NULL; p = p->next)
            if (strcmp(p->server, routes[i].server) == 0)
                return p;
        break;
    }
    return NULL;
}

static const struct DnsProbe *
preferred_fallback(const char *hostname) {
    if (fallback_resolver == NULL)
        return NULL;
    const struct DnsProbe *best = benchmark_preference(hostname);
    if (best == NULL)
        best = best_fallback_probe();
    return best != NULL ? best : fallback_resolver->probes;
}


int
resolv_init(struct ev_loop *loop, char **nameservers, char **search, int mode) {
    default_resolver.ctx = &dns_defctx;
    return open_resolver(&default_resolver, loop, nameservers, search, mode, 0);
}

int
resolv_add_client(struct ev_loop *loop, const char *cidr, char **nameservers,
        char **search, int mode) {
    struct Resolver *resolver = calloc(1, sizeof(*resolver));
    if (resolver == NULL)
        return -1;
    if (resolv_is_country(cidr))
        memcpy(resolver->country, cidr, 2);
    else
        resolver->family = parse_client_cidr(cidr, resolver->network, &resolver->prefix);
    int is_fallback = strcmp(cidr, "fallback") == 0;
    if ((!is_fallback && !resolver->family && !resolver->country[0]) ||
            (resolver->ctx = dns_new(NULL)) == NULL) {
        free(resolver);
        return -1;
    }
    /* Each fallback server has its own context; udns limits servers per context. */
    char *first[] = {nameservers != NULL ? nameservers[0] : NULL, NULL};
    open_resolver(resolver, loop, is_fallback ? first : nameservers, search, mode, 0);
    start_probes(resolver, cidr, nameservers);
    if (is_fallback)
        fallback_resolver = resolver;
    resolver->next = client_resolvers;
    client_resolvers = resolver;
    return 0;
}

static void
close_resolver(struct Resolver *resolver, struct ev_loop *loop) {
    ev_io_stop(loop, &resolver->io);
    ev_timer_stop(loop, &resolver->timer);
    dns_close(resolver->ctx);
}

void
resolv_shutdown(struct ev_loop *loop) {
    while (client_resolvers != NULL) {
        struct Resolver *resolver = client_resolvers;
        client_resolvers = resolver->next;
        if (resolver->probes != NULL)
            ev_timer_stop(loop, &resolver->probe_timer);
        while (resolver->probes != NULL) {
            struct DnsProbe *p = resolver->probes;
            resolver->probes = p->next;
            close_resolver(&p->endpoint, loop);
            dns_free(p->endpoint.ctx);
            free(p);
        }
        close_resolver(resolver, loop);
        dns_free(resolver->ctx);
        free(resolver);
    }
    fallback_resolver = NULL;
    close_resolver(&default_resolver, loop);
#ifdef HAVE_LIBMAXMINDDB
    if (country_db_open) {
        MMDB_close(&country_db);
        country_db_open = 0;
    }
#endif
}

static struct Resolver *
select_resolver(const struct sockaddr_storage *peer) {
    struct Resolver *best = &default_resolver;
    if (peer == NULL)
        return best;
    int family = peer->ss_family;
    const unsigned char *ip;
    if (family == AF_INET) {
        ip = (const unsigned char *)&((const struct sockaddr_in *)peer)->sin_addr;
    } else if (family == AF_INET6) {
        const struct in6_addr *v6 = &((const struct sockaddr_in6 *)peer)->sin6_addr;
        ip = v6->s6_addr;
        if (IN6_IS_ADDR_V4MAPPED(v6)) {
            ip += 12;
            family = AF_INET;
        }
    } else {
        return best;
    }
    for (struct Resolver *r = client_resolvers; r != NULL; r = r->next) {
        if (family != r->family || (best != &default_resolver && r->prefix <= best->prefix))
            continue;
        unsigned int bytes = r->prefix / 8, bits = r->prefix % 8;
        if (memcmp(ip, r->network, bytes) == 0 &&
                (!bits || ((ip[bytes] ^ r->network[bytes]) >> (8 - bits)) == 0))
            best = r;
    }
#ifdef HAVE_LIBMAXMINDDB
    if (best == &default_resolver)
        return select_country_resolver(peer);
#endif
    return best;
}

struct ResolvQuery *
resolv_query_client(const char *hostname, int mode, const struct sockaddr_storage *peer,
        void (*client_cb)(struct Address *, void *),
        void (*client_free_cb)(void *), void *client_cb_data) {
    struct Resolver *resolver = select_resolver(peer);
    if (fallback_resolver != NULL &&
            (resolver == &default_resolver || resolver_unhealthy(resolver)))
        resolver = fallback_resolver;
    const struct DnsProbe *preferred = preferred_fallback(hostname);
    struct dns_ctx *ctx = resolver == fallback_resolver && preferred != NULL
        ? preferred->endpoint.ctx : resolver->ctx;

    /*
     * Wrap udns's call back in our own
     */
    struct ResolvQuery *cb_data = malloc(sizeof(struct ResolvQuery));
    if (cb_data == NULL) {
        err("Failed to allocate memory for DNS query callback data.");
        return NULL;
    }
    cb_data->ctx = ctx;
    cb_data->fallback_first = preferred;
    cb_data->fallback_preferred_pending = resolver != fallback_resolver;
    cb_data->fallback_next = preferred == NULL ? NULL :
        resolver != fallback_resolver ? preferred : fallback_resolver->probes;
    if (resolver == fallback_resolver && cb_data->fallback_next == preferred && preferred != NULL)
        cb_data->fallback_next = preferred->next;
    cb_data->fallback_hostname = cb_data->fallback_next != NULL ? strdup(hostname) : NULL;
    cb_data->client_cb = client_cb;
    cb_data->client_free_cb = client_free_cb;
    cb_data->client_cb_data = client_cb_data;
    cb_data->resolv_mode = mode != RESOLV_MODE_DEFAULT ?
                           mode : resolver->mode;
    memset(cb_data->queries, 0, sizeof(cb_data->queries));
    cb_data->response_count = 0;
    cb_data->responses = NULL;

    submit_queries(cb_data, hostname);
    if (all_queries_are_null(cb_data))
        retry_fallback(cb_data);

    if (all_queries_are_null(cb_data)) {
        if (cb_data->client_free_cb != NULL)
            cb_data->client_free_cb(cb_data->client_cb_data);
        free(cb_data->fallback_hostname);
        free(cb_data);
        return NULL;
    }
    return cb_data;
}

static void
submit_queries(struct ResolvQuery *cb_data, const char *hostname) {
    struct dns_ctx *ctx = cb_data->ctx;
    /* Submit A and AAAA queries */
    if (cb_data->resolv_mode != RESOLV_MODE_IPV6_ONLY) {
        cb_data->queries[0] = dns_submit_a4(ctx,
                hostname, 0,
                dns_query_v4_cb, cb_data);
        if (cb_data->queries[0] == NULL)
            err("Failed to submit DNS query: %s", dns_strerror(dns_status(ctx)));
    };

    if (cb_data->resolv_mode != RESOLV_MODE_IPV4_ONLY) {
        cb_data->queries[1] = dns_submit_a6(ctx,
                hostname, 0,
                dns_query_v6_cb, cb_data);
        if (cb_data->queries[1] == NULL)
            err("Failed to submit DNS query: %s", dns_strerror(dns_status(ctx)));
    }

}

static void
retry_fallback(struct ResolvQuery *query) {
    char *hostname = query->fallback_hostname;
    if (hostname == NULL)
        return;
    do {
        const struct DnsProbe *next = query->fallback_next;
        query->ctx = next->endpoint.ctx;
        query->fallback_next = query->fallback_preferred_pending
            ? fallback_resolver->probes : next->next;
        query->fallback_preferred_pending = 0;
        if (query->fallback_next == query->fallback_first)
            query->fallback_next = query->fallback_first->next;
        submit_queries(query, hostname);
    } while (all_queries_are_null(query) && query->fallback_next != NULL);
    if (query->fallback_next == NULL) {
        query->fallback_hostname = NULL;
        free(hostname);
    }
}

void
resolv_cancel(struct ResolvQuery *query_handle) {
    if (query_handle == NULL)
        return;

    struct ResolvQuery *cb_data = (struct ResolvQuery *)query_handle;
    struct dns_ctx *ctx = cb_data->ctx;

    for (size_t i = 0; i < sizeof(cb_data->queries) / sizeof(cb_data->queries[0]); i++) {
        if (cb_data->queries[i] != NULL) {
            dns_cancel(ctx, cb_data->queries[i]);
            free(cb_data->queries[i]);
            cb_data->queries[i] = NULL;
        }
    }

    if (cb_data->client_free_cb != NULL)
        cb_data->client_free_cb(cb_data->client_cb_data);

    for (size_t i = 0; i < cb_data->response_count; i++)
        free(cb_data->responses[i]);
    free(cb_data->responses);
    free(cb_data->fallback_hostname);
    free(cb_data);
}

/*
 * DNS UDP socket activity callback
 */
static void
resolv_sock_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
    struct dns_ctx *ctx = (struct dns_ctx *)w->data;

    if (revents & EV_READ)
        dns_ioevent(ctx, ev_now(loop));
}

/*
 * Wrapper for client callback we provide to udns
 */
static void
dns_query_v4_cb(struct dns_ctx *ctx, struct dns_rr_a4 *result, void *data) {
    struct ResolvQuery *cb_data = (struct ResolvQuery *)data;

    if (result == NULL) {
        info("resolv: %s\n", dns_strerror(dns_status(ctx)));
    } else if (result->dnsa4_nrr > 0) {
        struct Address **new_responses = realloc(cb_data->responses,
                (cb_data->response_count + (size_t)result->dnsa4_nrr) *
                    sizeof(struct Address *));
        if (new_responses == NULL) {
            err("Failed to allocate memory for additional DNS responses");
        } else {
            cb_data->responses = new_responses;

            for (int i = 0; i < result->dnsa4_nrr; i++) {
                struct sockaddr_in sa = {
                    .sin_family = AF_INET,
                    .sin_port = 0,
                    .sin_addr = result->dnsa4_addr[i],
                };

                cb_data->responses[cb_data->response_count] =
                        new_address_sa((struct sockaddr *)&sa, sizeof(sa));
                if (cb_data->responses[cb_data->response_count] == NULL)
                    err("Failed to allocate memory for DNS query result address");
                else
                    cb_data->response_count++;
            }
        }
    }

    free(result);
    cb_data->queries[0] = NULL; /* mark A query as being completed */

    /* Once all queries have completed, call client callback */
    if (all_queries_are_null(cb_data))
        process_client_callback(cb_data);
}

static void
dns_query_v6_cb(struct dns_ctx *ctx, struct dns_rr_a6 *result, void *data) {
    struct ResolvQuery *cb_data = (struct ResolvQuery *)data;

    if (result == NULL) {
        info("resolv: %s\n", dns_strerror(dns_status(ctx)));
    } else if (result->dnsa6_nrr > 0) {
        struct Address **new_responses = realloc(cb_data->responses,
                (cb_data->response_count + (size_t)result->dnsa6_nrr) *
                    sizeof(struct Address *));
        if (new_responses == NULL) {
            err("Failed to allocate memory for additional DNS responses");
        } else {
            cb_data->responses = new_responses;

            for (int i = 0; i < result->dnsa6_nrr; i++) {
                struct sockaddr_in6 sa = {
                    .sin6_family = AF_INET6,
                    .sin6_port = 0,
                    .sin6_addr = result->dnsa6_addr[i],
                };

                cb_data->responses[cb_data->response_count] =
                        new_address_sa((struct sockaddr *)&sa, sizeof(sa));
                if (cb_data->responses[cb_data->response_count] == NULL)
                    err("Failed to allocate memory for DNS query result address");
                else
                    cb_data->response_count++;
            }
        }
    }

    free(result);
    cb_data->queries[1] = NULL; /* mark AAAA query as being completed */

    /* Once all queries have completed, call client callback */
    if (all_queries_are_null(cb_data))
        process_client_callback(cb_data);
}

/*
 * Called once all queries have been completed
 */
static void
process_client_callback(struct ResolvQuery *cb_data) {
    struct Address *best_address = NULL;

    if (cb_data->resolv_mode == RESOLV_MODE_IPV4_FIRST)
        best_address = choose_ipv4_first(cb_data);
    else if (cb_data->resolv_mode == RESOLV_MODE_IPV6_FIRST)
        best_address = choose_ipv6_first(cb_data);
    else
        best_address = choose_any(cb_data);

    if (best_address == NULL) {
        retry_fallback(cb_data);
        if (!all_queries_are_null(cb_data))
            return;
    }
    cb_data->client_cb(best_address, cb_data->client_cb_data);

    for (size_t i = 0; i < cb_data->response_count; i++)
        free(cb_data->responses[i]);

    free(cb_data->responses);
    if (cb_data->client_free_cb != NULL)
        cb_data->client_free_cb(cb_data->client_cb_data);
    free(cb_data->fallback_hostname);
    free(cb_data);
}

static struct Address *
choose_ipv4_first(struct ResolvQuery *cb_data) {
    for (size_t i = 0; i < cb_data->response_count; i++)
        if (address_is_sockaddr(cb_data->responses[i]) &&
                address_sa(cb_data->responses[i])->sa_family == AF_INET)
            return cb_data->responses[i];

    return choose_any(cb_data);;
}

static struct Address *
choose_ipv6_first(struct ResolvQuery *cb_data) {
    for (size_t i = 0; i < cb_data->response_count; i++)
        if (address_is_sockaddr(cb_data->responses[i]) &&
                address_sa(cb_data->responses[i])->sa_family == AF_INET6)
            return cb_data->responses[i];

    return choose_any(cb_data);;
}

static struct Address *
choose_any(struct ResolvQuery *cb_data) {
    if (cb_data->response_count >= 1)
        return cb_data->responses[0];

    return NULL;
}

/*
 * DNS timeout callback
 */
static void
resolv_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
    struct dns_ctx *ctx = (struct dns_ctx *)w->data;

    if (revents & EV_TIMER)
        dns_timeouts(ctx, 30, ev_now(loop));
}

/*
 * Callback to setup DNS timeout callback
 */
static void
dns_timer_setup_cb(struct dns_ctx *ctx, int timeout, void *data) {
    struct Resolver *resolver = data;
    struct ev_loop *loop = resolver->loop;

    if (ev_is_active(&resolver->timer))
        ev_timer_stop(loop, &resolver->timer);

    if (ctx != NULL && timeout >= 0) {
        ev_timer_set(&resolver->timer, timeout, 0.0);
        ev_timer_start(loop, &resolver->timer);
    }
}

static inline int
all_queries_are_null(struct ResolvQuery *cb_data) {
    int result = 1;

    for (size_t i = 0; i < sizeof(cb_data->queries) / sizeof(cb_data->queries[0]); i++)
        result = result && cb_data->queries[i] == NULL;

    return result;
}
#endif
