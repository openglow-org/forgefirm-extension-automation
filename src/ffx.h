/*
 * ffx.h - a native package's side of the ForgeFIRM extension API, version 0.1
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * One header, no dependency beyond libc. A service reaches the machine
 * through one Unix socket, the one its environment names in FFX_API: one
 * request per connection, JSON both ways. This is the transport; the JSON
 * is the package's own (the answers are small objects, and a package that
 * wants a parser brings one).
 *
 * In exactly one C file:
 *
 *     #define FFX_IMPLEMENTATION
 *     #include "ffx.h"
 *
 *     ffx_reply_t r;
 *     if (ffx_request("POST", "/v0/hold", "{\"raised\":true,\"reason\":\"no exhaust\"}", &r, 5000) == 0
 *         && r.status == 200)
 *         ...
 *     ffx_reply_free(&r);
 *
 * A service whose package has a page answers that page with
 * ffx_serve_one().
 *
 * The machine has no clock that keeps the date: time every wait with
 * CLOCK_MONOTONIC, never with the wall clock.
 */
#ifndef FFX_H
#define FFX_H

#include <stddef.h>

#define FFX_API_VERSION "0.1"

typedef struct {
    int status;                 /* the HTTP status, or 0 when there was no answer */
    char ctype[64];             /* the answer's Content-Type */
    char *body;                 /* the answer, NUL-terminated (a JPEG is binary: use len) */
    size_t len;
} ffx_reply_t;

/* One request. json may be NULL (a GET); a POST sends it as
 * application/json. 0 when an answer came back (whatever its status), -1
 * with r->status 0 when none did: the socket, the connection, or the
 * timeout. */
int ffx_request(const char *method, const char *path, const char *json, ffx_reply_t *r, int timeout_ms);
void ffx_reply_free(ffx_reply_t *r);

/* s as a JSON string, quotes included, into out; -1 when it does not fit. */
int ffx_json_string(const char *s, char *out, size_t olen);

/* ui: a service whose package has a page answers it. The host hands the
 * service the listening end of a socket, at the descriptor FFX_CALL_FD
 * names; each call the page makes arrives there, one per connection.
 *
 * The handler gets "GET" or "POST", the path the page named, and the JSON
 * object it sent ("{}" for a GET); it writes a JSON answer, NUL-terminated,
 * into answer (alen bytes) and returns the HTTP status to answer with. */
typedef int (*ffx_handler_t)(void *ctx, const char *method, const char *path, const char *body, char *answer,
                             size_t alen);

/* The listening descriptor, to poll for POLLIN beside the service's own
 * work; -1 when there is none (the package has no page). */
int ffx_call_fd(void);

/* Accept one call and answer it, waiting up to timeout_ms for it (-1:
 * without end). 1 when a call was answered, 0 when none came, -1 when
 * there is no descriptor or the call was cut short. */
int ffx_serve_one(ffx_handler_t h, void *ctx, int timeout_ms);

#ifdef FFX_IMPLEMENTATION

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define FFX_ANSWER_MAX (4 * 1024 * 1024)

static long ffx_ms_left(const struct timespec *end)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long)(end->tv_sec - now.tv_sec) * 1000 + (end->tv_nsec - now.tv_nsec) / 1000000;
}

static int ffx_wait(int fd, short ev, const struct timespec *end)
{
    for (;;) {
        long left = ffx_ms_left(end);
        if (left <= 0)
            return -1;
        struct pollfd p = { fd, ev, 0 };
        int n = poll(&p, 1, (int)left);
        if (n > 0)
            return 0;
        if (n < 0 && errno != EINTR)
            return -1;
    }
}

int ffx_request(const char *method, const char *path, const char *json, ffx_reply_t *r, int timeout_ms)
{
    const char *api = getenv("FFX_API");
    memset(r, 0, sizeof(*r));
    if (!api || strlen(api) >= sizeof(((struct sockaddr_un *)0)->sun_path))
        return -1;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    end.tv_sec += timeout_ms / 1000;
    end.tv_nsec += (long)(timeout_ms % 1000) * 1000000;
    if (end.tv_nsec >= 1000000000) {
        end.tv_sec++;
        end.tv_nsec -= 1000000000;
    }

    size_t blen = json ? strlen(json) : 0;
    char head[512];
    int hn = json ? snprintf(head, sizeof(head), "%s %s HTTP/1.1\r\nHost: forgeext\r\nContent-Type: application/json\r\n"
                             "Content-Length: %zu\r\n\r\n", method, path, blen)
                  : snprintf(head, sizeof(head), "%s %s HTTP/1.1\r\nHost: forgeext\r\n\r\n", method, path);
    if (hn < 0 || (size_t)hn >= sizeof(head))
        return -1;

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    memcpy(sa.sun_path, api, strlen(api) + 1);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    /* the head and the body, whole */
    const char *parts[2] = { head, json };
    size_t lens[2] = { (size_t)hn, blen };
    for (int i = 0; i < 2; i++)
        for (size_t off = 0; off < lens[i];) {
            if (ffx_wait(fd, POLLOUT, &end) != 0) {
                close(fd);
                return -1;
            }
            ssize_t w = send(fd, parts[i] + off, lens[i] - off, MSG_NOSIGNAL);
            if (w < 0 && errno == EINTR)
                continue;
            if (w <= 0) {
                close(fd);
                return -1;
            }
            off += (size_t)w;
        }
    /* the whole answer: the host closes the connection after it */
    size_t cap = 4096, len = 0;
    char *buf = malloc(cap + 1);
    while (buf) {
        if (ffx_wait(fd, POLLIN, &end) != 0)
            break;
        if (len == cap) {
            if (cap >= FFX_ANSWER_MAX)
                break;
            char *nb = realloc(buf, cap * 2 + 1);
            if (!nb)
                break;
            buf = nb;
            cap *= 2;
        }
        ssize_t n = recv(fd, buf + len, cap - len, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            if (n == 0) {
                close(fd);
                fd = -1;
            }
            break;
        }
        len += (size_t)n;
    }
    if (fd >= 0)
        close(fd);
    if (!buf)
        return -1;
    buf[len] = '\0';

    char *sep = strstr(buf, "\r\n\r\n");
    if (!sep || sscanf(buf, "HTTP/1.%*c %d", &r->status) != 1) {
        free(buf);
        r->status = 0;
        return -1;
    }
    *sep = '\0';
    char *ct = NULL;
    for (char *p = buf; (p = strstr(p, "\r\n")) != NULL; p += 2)
        if (strncasecmp(p + 2, "Content-Type:", 13) == 0) {
            ct = p;
            break;
        }
    if (ct) {
        ct += strlen("\r\nContent-Type:");
        while (*ct == ' ')
            ct++;
        size_t n = strcspn(ct, "\r");
        if (n >= sizeof(r->ctype))
            n = sizeof(r->ctype) - 1;
        memcpy(r->ctype, ct, n);
        r->ctype[n] = '\0';
    }
    size_t off = (size_t)(sep + 4 - buf);
    r->len = len - off;
    memmove(buf, sep + 4, r->len + 1);
    r->body = buf;
    return 0;
}

void ffx_reply_free(ffx_reply_t *r)
{
    free(r->body);
    r->body = NULL;
    r->len = 0;
}

int ffx_json_string(const char *s, char *out, size_t olen)
{
    size_t o = 0;
    if (olen < 3)
        return -1;
    out[o++] = '"';
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        char esc[8];
        const char *add = esc;
        if (c == '"' || c == '\\')
            snprintf(esc, sizeof(esc), "\\%c", c);
        else if (c < 0x20)
            snprintf(esc, sizeof(esc), "\\u%04x", c);
        else {
            esc[0] = (char)c;
            esc[1] = '\0';
        }
        size_t n = strlen(add);
        if (o + n + 2 > olen)
            return -1;
        memcpy(out + o, add, n);
        o += n;
    }
    out[o++] = '"';
    out[o] = '\0';
    return 0;
}

#define FFX_CALL_REQUEST_MAX (16 * 1024)
#define FFX_CALL_ANSWER_MAX  (64 * 1024)    /* what the host takes back, the head included */
#define FFX_CALL_TIMEOUT_MS  10000          /* what the host waits for the whole answer */

int ffx_call_fd(void)
{
    const char *v = getenv("FFX_CALL_FD");
    return v && v[0] >= '0' && v[0] <= '9' ? atoi(v) : -1;
}

static int ffx_send_all(int fd, const char *p, size_t n, const struct timespec *end)
{
    for (size_t off = 0; off < n;) {
        if (ffx_wait(fd, POLLOUT, end) != 0)
            return -1;
        ssize_t w = send(fd, p + off, n - off, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            return -1;
        off += (size_t)w;
    }
    return 0;
}

int ffx_serve_one(ffx_handler_t h, void *ctx, int timeout_ms)
{
    int lfd = ffx_call_fd();
    if (lfd < 0)
        return -1;
    struct pollfd p = { lfd, POLLIN, 0 };
    int n = poll(&p, 1, timeout_ms);
    if (n == 0 || (n < 0 && errno == EINTR))
        return 0;
    if (n < 0)
        return -1;
    int fd = accept(lfd, NULL, NULL);
    if (fd < 0)
        return errno == EAGAIN || errno == EINTR || errno == ECONNABORTED ? 0 : -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    end.tv_sec += FFX_CALL_TIMEOUT_MS / 1000;
    char *req = malloc(FFX_CALL_REQUEST_MAX + 1), *ans = malloc(FFX_CALL_ANSWER_MAX);
    size_t len = 0, want = 0;
    char *body = NULL;
    int rc = -1;
    if (!req || !ans)
        goto out;
    /* the head, then as much body as it says */
    while (!body || len < (size_t)(body - req) + want) {
        if (len == FFX_CALL_REQUEST_MAX || ffx_wait(fd, POLLIN, &end) != 0)
            goto out;
        ssize_t got = recv(fd, req + len, FFX_CALL_REQUEST_MAX - len, 0);
        if (got < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (got <= 0)
            goto out;
        len += (size_t)got;
        req[len] = '\0';
        char *sep = body ? NULL : strstr(req, "\r\n\r\n");
        if (sep) {
            body = sep + 4;
            for (char *q = req; (q = strstr(q, "\r\n")) != NULL && q < sep; q += 2)
                if (strncasecmp(q + 2, "Content-Length:", 15) == 0)
                    want = strtoul(q + 17, NULL, 10);
            if (want > FFX_CALL_REQUEST_MAX)
                goto out;
        }
    }
    body[want] = '\0';
    char method[8], path[256];
    if (sscanf(req, "%7s %255s HTTP/1.", method, path) != 2)
        goto out;
    snprintf(ans, FFX_CALL_ANSWER_MAX, "null");
    int status = h(ctx, method, path, want ? body : "{}", ans, FFX_CALL_ANSWER_MAX - 256);
    if (status < 100 || status > 599)
        status = 500;
    char head[200];
    size_t alen = strlen(ans);
    int hn = snprintf(head, sizeof(head), "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n"
                      "Connection: close\r\n\r\n", status, status == 200 ? "OK" : "Refused", alen);
    if (ffx_send_all(fd, head, (size_t)hn, &end) == 0 && ffx_send_all(fd, ans, alen, &end) == 0)
        rc = 1;
out:
    free(req);
    free(ans);
    close(fd);
    return rc;
}

#endif /* FFX_IMPLEMENTATION */
#endif /* FFX_H */
