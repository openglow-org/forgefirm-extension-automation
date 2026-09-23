/*
 * web.c - one HTTP request, through the image's curl
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * See web.h.
 */
#define _GNU_SOURCE
#include "web.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *curl_bin = WEB_CURL_DEFAULT;

void web_set_curl(const char *path)
{
    curl_bin = path && path[0] ? path : WEB_CURL_DEFAULT;
}

static int fail(char *err, size_t elen, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

static int fail(char *err, size_t elen, const char *fmt, ...)
{
    if (err && elen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, elen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

/* The authority of an http or https URL: [start, end) and whether it is
 * https. -1 when it is neither. */
static int authority(const char *url, const char **a, const char **e, int *tls)
{
    if (strncmp(url, "http://", 7) == 0) {
        *a = url + 7;
        *tls = 0;
    } else if (strncmp(url, "https://", 8) == 0) {
        *a = url + 8;
        *tls = 1;
    } else {
        return -1;
    }
    *e = *a + strcspn(*a, "/?#");
    return *e > *a ? 0 : -1;
}

int web_url_ok(const char *url)
{
    const char *a, *e;
    int tls;
    if (!url || strlen(url) > 1024 || authority(url, &a, &e, &tls) != 0)
        return 0;
    for (const unsigned char *p = (const unsigned char *)url; *p; p++)
        if (*p <= 0x20 || *p == 0x7f)
            return 0;
    return memchr(a, '@', (size_t)(e - a)) == NULL;
}

int web_url_dest(const char *url, char *out, size_t olen)
{
    const char *a, *e, *colon;
    int tls;
    char host[256];
    if (!web_url_ok(url) || authority(url, &a, &e, &tls) != 0)
        return -1;
    long port = tls ? 443 : 80;
    if (*a == '[') {
        const char *close = memchr(a, ']', (size_t)(e - a));
        if (!close || (size_t)(close - a + 1) >= sizeof(host))
            return -1;
        memcpy(host, a, (size_t)(close - a + 1));
        host[close - a + 1] = '\0';
        colon = close + 1 < e && close[1] == ':' ? close + 1 : NULL;
    } else {
        colon = memchr(a, ':', (size_t)(e - a));
        size_t n = (size_t)((colon ? colon : e) - a);
        if (n == 0 || n >= sizeof(host))
            return -1;
        memcpy(host, a, n);
        host[n] = '\0';
        for (char *h = host; *h; h++)
            *h = (char)tolower((unsigned char)*h);
    }
    if (colon) {
        char *end;
        port = strtol(colon + 1, &end, 10);
        if (end != e || port < 1 || port > 65535)
            return -1;
    }
    int n = snprintf(out, olen, "%s:%ld", host, port);
    return n > 0 && (size_t)n < olen ? 0 : -1;
}

static long left_ms(const struct timespec *end)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long)(end->tv_sec - now.tv_sec) * 1000 + (end->tv_nsec - now.tv_nsec) / 1000000;
}

int web_do(const web_req_t *r, web_ans_t *ans, char *err, size_t elen)
{
    const char *argv[64];
    char maxtime[16], conntime[16];
    int n = 0, t = r->timeout_s > 0 && r->timeout_s <= 60 ? r->timeout_s : 10;
    memset(ans, 0, sizeof(*ans));
    if (!web_url_ok(r->url))
        return fail(err, elen, "a URL is http:// or https://, a host, and no user or password in it");
    snprintf(maxtime, sizeof(maxtime), "%d", t);
    snprintf(conntime, sizeof(conntime), "%d", t < 5 ? t : 5);
    argv[n++] = curl_bin;
    argv[n++] = "-q";                                   /* no configuration file of anybody's */
    argv[n++] = "-sS";
    argv[n++] = "--proto";
    argv[n++] = "=http,https";
    argv[n++] = "--proto-redir";
    argv[n++] = "=http,https";
    argv[n++] = "-L";
    argv[n++] = "--max-redirs";
    argv[n++] = "3";
    argv[n++] = "--max-time";
    argv[n++] = maxtime;
    argv[n++] = "--connect-timeout";
    argv[n++] = conntime;
    argv[n++] = "-X";
    argv[n++] = r->method && r->method[0] ? r->method : "GET";
    for (int i = 0; i < WEB_MAX_HEADERS && r->headers[i]; i++) {
        argv[n++] = "-H";
        argv[n++] = r->headers[i];
    }
    if (r->body) {
        argv[n++] = "--data-binary";
        argv[n++] = "@-";
    }
    for (int i = 0; !r->body && i < 16 && r->form[i] && n < 56; i++) {
        argv[n++] = "--data-urlencode";
        argv[n++] = r->form[i];
    }
    argv[n++] = "-o";
    argv[n++] = "-";
    argv[n++] = "-w";
    argv[n++] = "\n%{http_code}";
    argv[n++] = "--url";
    argv[n++] = r->url;
    argv[n] = NULL;

    int in[2], out[2], er[2];
    if (pipe2(in, O_CLOEXEC) != 0)
        return fail(err, elen, "cannot make a pipe: %s", strerror(errno));
    if (pipe2(out, O_CLOEXEC) != 0) {
        close(in[0]);
        close(in[1]);
        return fail(err, elen, "cannot make a pipe: %s", strerror(errno));
    }
    if (pipe2(er, O_CLOEXEC) != 0) {
        close(in[0]);
        close(in[1]);
        close(out[0]);
        close(out[1]);
        return fail(err, elen, "cannot make a pipe: %s", strerror(errno));
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(in[0]);
        close(in[1]);
        close(out[0]);
        close(out[1]);
        close(er[0]);
        close(er[1]);
        return fail(err, elen, "cannot start curl: %s", strerror(errno));
    }
    if (pid == 0) {
        dup2(in[0], 0);
        dup2(out[1], 1);
        dup2(er[1], 2);
        syscall(SYS_close_range, 3U, ~0U, 0U);          /* the page's socket stays with the service */
        execv(curl_bin, (char *const *)argv);
        _exit(127);
    }
    close(in[0]);
    close(out[1]);
    close(er[1]);
    fcntl(in[1], F_SETFL, O_NONBLOCK);

    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    end.tv_sec += t + 5;
    static char buf[64 * 1024];
    char words[512];
    size_t len = 0, wlen = 0, sent = 0;
    int ofd = out[0], efd = er[0], ifd = r->body ? in[1] : -1, late = 0;
    char tail[16];
    size_t tlen = 0;
    if (ifd < 0)
        close(in[1]);
    while (ofd >= 0 || efd >= 0) {
        struct pollfd p[3];
        int np = 0, io = -1, oo = -1, eo = -1;
        if (ifd >= 0) {
            io = np;
            p[np++] = (struct pollfd){ ifd, POLLOUT, 0 };
        }
        if (ofd >= 0) {
            oo = np;
            p[np++] = (struct pollfd){ ofd, POLLIN, 0 };
        }
        if (efd >= 0) {
            eo = np;
            p[np++] = (struct pollfd){ efd, POLLIN, 0 };
        }
        long l = left_ms(&end);
        if (l <= 0) {
            late = 1;
            break;
        }
        if (poll(p, (nfds_t)np, (int)l) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (io >= 0 && p[io].revents) {
            ssize_t w = write(ifd, r->body + sent, r->blen - sent);
            if (w > 0)
                sent += (size_t)w;
            if (w < 0 && errno != EAGAIN && errno != EINTR)
                sent = r->blen;
            if (sent >= r->blen) {
                close(ifd);
                ifd = -1;
            }
        }
        if (oo >= 0 && p[oo].revents) {
            char chunk[4096];
            ssize_t k = read(ofd, chunk, sizeof(chunk));
            if (k <= 0) {
                close(ofd);
                ofd = -1;
            } else {
                size_t take = (size_t)k < sizeof(buf) - len ? (size_t)k : sizeof(buf) - len;
                memcpy(buf + len, chunk, take);
                len += take;
                /* past what is kept, only the end matters: the status is written last */
                for (ssize_t i = 0; i < k; i++) {
                    if (tlen == sizeof(tail))
                        memmove(tail, tail + 1, --tlen);
                    tail[tlen++] = chunk[i];
                }
            }
        }
        if (eo >= 0 && p[eo].revents) {
            ssize_t k = read(efd, words + wlen, sizeof(words) - 1 - wlen);
            if (k <= 0) {
                close(efd);
                efd = -1;
            } else {
                wlen += (size_t)k;
            }
        }
    }
    if (ifd >= 0)
        close(ifd);
    if (ofd >= 0)
        close(ofd);
    if (efd >= 0)
        close(efd);
    if (late)
        kill(pid, SIGKILL);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;
    words[wlen] = '\0';
    words[strcspn(words, "\n")] = '\0';
    if (late)
        return fail(err, elen, "no answer within %d s", t + 5);
    if (!WIFEXITED(status) || WEXITSTATUS(status) == 127)
        return fail(err, elen, "curl could not be run (%s)", curl_bin);
    /* The answer ends "\n<code>": the code from the tail, the body before it. */
    tail[tlen] = '\0';
    char *nl = strrchr(tail, '\n');
    int code = nl ? atoi(nl + 1) : 0;
    size_t body = 0;
    if (len >= 1) {
        char *last = NULL;
        for (size_t i = len; i > 0; i--)
            if (buf[i - 1] == '\n') {
                last = buf + i - 1;
                break;
            }
        body = last && len < sizeof(buf) ? (size_t)(last - buf) : len;
    }
    ans->blen = body < WEB_ANSWER_MAX ? body : WEB_ANSWER_MAX;
    memcpy(ans->body, buf, ans->blen);
    ans->body[ans->blen] = '\0';
    ans->status = code;
    if (WEXITSTATUS(status) != 0 || code == 0) {
        const char *w = words;
        if (strncmp(w, "curl: ", 6) == 0)
            w += 6;
        return fail(err, elen, "%s", w[0] ? w : "no answer");
    }
    return 0;
}
