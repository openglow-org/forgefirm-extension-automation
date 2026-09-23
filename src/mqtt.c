/*
 * mqtt.c - one MQTT 3.1.1 publish, at most once, over plain TCP
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * See mqtt.h.
 */
#define _GNU_SOURCE
#include "mqtt.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

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

/* The remaining length, MQTT's variable-length integer. */
static int put_len(unsigned char *out, size_t olen, size_t *at, size_t n)
{
    do {
        if (*at >= olen)
            return -1;
        unsigned char b = (unsigned char)(n % 128);
        n /= 128;
        out[(*at)++] = (unsigned char)(b | (n ? 0x80 : 0));
    } while (n);
    return 0;
}

static int put_str(unsigned char *out, size_t olen, size_t *at, const char *s, size_t n)
{
    if (n > 65535 || *at + 2 + n > olen)
        return -1;
    out[(*at)++] = (unsigned char)(n >> 8);
    out[(*at)++] = (unsigned char)(n & 0xff);
    memcpy(out + *at, s, n);
    *at += n;
    return 0;
}

/* A fixed header and a body built apart, joined. */
static int frame(unsigned char type, const unsigned char *body, size_t blen, unsigned char *out, size_t olen)
{
    size_t at = 0;
    if (olen < 1)
        return -1;
    out[at++] = type;
    if (put_len(out, olen, &at, blen) != 0 || at + blen > olen)
        return -1;
    memcpy(out + at, body, blen);
    return (int)(at + blen);
}

int mqtt_connect_packet(const mqtt_broker_t *b, unsigned char *out, size_t olen)
{
    unsigned char body[1024];
    size_t at = 0;
    int user = b->username && b->username[0], pass = user && b->password && b->password[0];
    const char *id = b->client_id ? b->client_id : "";
    if (put_str(body, sizeof(body), &at, "MQTT", 4) != 0 || at + 4 > sizeof(body))
        return -1;
    body[at++] = 4;                                 /* 3.1.1 */
    body[at++] = (unsigned char)(0x02 | (user ? 0x80 : 0) | (pass ? 0x40 : 0));    /* a clean session */
    body[at++] = 0;
    body[at++] = 30;                                /* keep-alive, s: it is gone long before */
    if (put_str(body, sizeof(body), &at, id, strlen(id)) != 0
        || (user && put_str(body, sizeof(body), &at, b->username, strlen(b->username)) != 0)
        || (pass && put_str(body, sizeof(body), &at, b->password, strlen(b->password)) != 0))
        return -1;
    return frame(0x10, body, at, out, olen);
}

int mqtt_publish_packet(const char *topic, const char *payload, size_t plen, int retain, unsigned char *out,
                        size_t olen)
{
    static unsigned char body[MQTT_TOPIC_MAX + MQTT_PAYLOAD_MAX + 8];
    size_t at = 0, tlen = strlen(topic);
    if (tlen == 0 || tlen > MQTT_TOPIC_MAX || plen > MQTT_PAYLOAD_MAX || strpbrk(topic, "#+"))
        return -1;
    if (put_str(body, sizeof(body), &at, topic, tlen) != 0 || at + plen > sizeof(body))
        return -1;
    memcpy(body + at, payload, plen);
    at += plen;
    return frame((unsigned char)(0x30 | (retain ? 1 : 0)), body, at, out, olen);
}

static long left_ms(const struct timespec *end)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long)(end->tv_sec - now.tv_sec) * 1000 + (end->tv_nsec - now.tv_nsec) / 1000000;
}

static int wait_fd(int fd, short ev, const struct timespec *end)
{
    for (;;) {
        long l = left_ms(end);
        if (l <= 0)
            return -1;
        struct pollfd p = { fd, ev, 0 };
        int n = poll(&p, 1, (int)l);
        if (n > 0)
            return (p.revents & (POLLERR | POLLHUP)) && !(p.revents & ev) ? -1 : 0;
        if (n < 0 && errno != EINTR)
            return -1;
    }
}

static int send_all(int fd, const unsigned char *p, size_t n, const struct timespec *end)
{
    for (size_t off = 0; off < n;) {
        if (wait_fd(fd, POLLOUT, end) != 0)
            return -1;
        ssize_t w = send(fd, p + off, n - off, MSG_NOSIGNAL);
        if (w < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (w <= 0)
            return -1;
        off += (size_t)w;
    }
    return 0;
}

static int dial(const char *host, int port, const struct timespec *end, char *err, size_t elen)
{
    char svc[8];
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    snprintf(svc, sizeof(svc), "%d", port);
    int g = getaddrinfo(host, svc, &hints, &res);
    if (g != 0)
        return fail(err, elen, "the broker %s does not resolve: %s", host, gai_strerror(g));
    int fd = -1, why = 0;
    for (struct addrinfo *a = res; a && fd < 0; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0)
            continue;
        if (connect(fd, a->ai_addr, a->ai_addrlen) != 0 && errno != EINPROGRESS) {
            why = errno;
            close(fd);
            fd = -1;
            continue;
        }
        int soerr = 0;
        socklen_t sl = sizeof(soerr);
        if (wait_fd(fd, POLLOUT, end) != 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr) {
            why = soerr ? soerr : ETIMEDOUT;
            close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(res);
    if (fd < 0)
        return fail(err, elen, "the broker %s:%d did not take the connection: %s", host, port, strerror(why));
    return fd;
}

int mqtt_publish(const mqtt_broker_t *b, const char *topic, const char *payload, size_t plen, int retain, char *err,
                 size_t elen)
{
    static unsigned char pkt[MQTT_TOPIC_MAX + MQTT_PAYLOAD_MAX + 16];
    unsigned char conn[1100], ack[4];
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    end.tv_sec += (b->timeout_ms > 0 ? b->timeout_ms : 5000) / 1000;

    int cl = mqtt_connect_packet(b, conn, sizeof(conn));
    int pl = mqtt_publish_packet(topic, payload, plen, retain, pkt, sizeof(pkt));
    if (cl < 0)
        return fail(err, elen, "the broker's name, user, or password is too long");
    if (pl < 0)
        return fail(err, elen, "a topic is 1 to %d bytes with no wildcard, and a payload at most %d", MQTT_TOPIC_MAX,
                    MQTT_PAYLOAD_MAX);
    int fd = dial(b->host, b->port, &end, err, elen);
    if (fd < 0)
        return -1;
    int rc = -1;
    size_t got = 0;
    if (send_all(fd, conn, (size_t)cl, &end) != 0) {
        fail(err, elen, "the broker went away during the connect");
        goto out;
    }
    while (got < 4) {
        if (wait_fd(fd, POLLIN, &end) != 0) {
            fail(err, elen, "the broker did not answer the connect in time");
            goto out;
        }
        ssize_t n = recv(fd, ack + got, 4 - got, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (n <= 0) {
            fail(err, elen, "the broker closed the connection before it answered");
            goto out;
        }
        got += (size_t)n;
    }
    if (ack[0] != 0x20 || ack[1] != 2) {
        fail(err, elen, "the broker's answer is not MQTT 3.1.1");
        goto out;
    }
    if (ack[3] != 0) {
        static const char *const why[] = { "", "it does not take this protocol level", "it refused the client id",
                                           "it is unavailable", "it refused the user or the password",
                                           "it does not authorize this client" };
        fail(err, elen, "the broker refused the connection: %s", ack[3] < 6 ? why[ack[3]] : "an unknown code");
        goto out;
    }
    static const unsigned char bye[2] = { 0xe0, 0x00 };
    if (send_all(fd, pkt, (size_t)pl, &end) != 0 || send_all(fd, bye, sizeof(bye), &end) != 0) {
        fail(err, elen, "the broker went away before the message was sent");
        goto out;
    }
    rc = 0;
out:
    close(fd);
    return rc;
}
