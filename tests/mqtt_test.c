/*
 * mqtt_test.c - host test: one MQTT 3.1.1 publish
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * The packets byte for byte against the specification's layout, and a
 * publish against a stand-in broker on loopback: taken, refused with its
 * return code, and a broker that closes the door.
 */
#define _GNU_SOURCE
#include "mqtt.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

typedef struct {
    int lfd, code, close_at_once;
    unsigned char got[2048];
    size_t len;
} broker_t;

static void *broker(void *p)
{
    broker_t *b = p;
    int fd = accept(b->lfd, NULL, NULL);
    if (fd < 0)
        return NULL;
    if (b->close_at_once) {
        close(fd);
        return NULL;
    }
    ssize_t n = recv(fd, b->got, sizeof(b->got), 0);
    if (n > 0)
        b->len = (size_t)n;
    unsigned char ack[4] = { 0x20, 2, 0, (unsigned char)b->code };
    send(fd, ack, 4, MSG_NOSIGNAL);
    /* the publish and the disconnect, whatever the pieces they arrive in */
    for (;;) {
        n = recv(fd, b->got + b->len, sizeof(b->got) - b->len, 0);
        if (n <= 0)
            break;
        b->len += (size_t)n;
    }
    close(fd);
    return NULL;
}

static int listener(int *port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t len = sizeof(a);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(s, 4) != 0 || getsockname(s, (struct sockaddr *)&a, &len) != 0)
        return -1;
    *port = ntohs(a.sin_port);
    return s;
}

int main(void)
{
    unsigned char pkt[5000];
    char err[200];
    mqtt_broker_t b = { "127.0.0.1", 0, "me", "pw", "id1", 3000 };
    int n = mqtt_connect_packet(&b, pkt, sizeof(pkt));
    static const unsigned char want_connect[] = {
        0x10, 23, 0, 4, 'M', 'Q', 'T', 'T', 4, 0xc2, 0, 30, 0, 3, 'i', 'd', '1', 0, 2, 'm', 'e', 0, 2, 'p', 'w',
    };
    CHECK(n == (int)sizeof(want_connect) && memcmp(pkt, want_connect, sizeof(want_connect)) == 0,
          "CONNECT with a user and a password (%d bytes)", n);
    b.username = "";
    n = mqtt_connect_packet(&b, pkt, sizeof(pkt));
    CHECK(n == 17 && pkt[9] == 0x02, "CONNECT with neither: a clean session and no flags (%d, %02x)", n, pkt[9]);
    n = mqtt_publish_packet("a/b", "hi", 2, 1, pkt, sizeof(pkt));
    static const unsigned char want_pub[] = { 0x31, 7, 0, 3, 'a', '/', 'b', 'h', 'i' };
    CHECK(n == (int)sizeof(want_pub) && memcmp(pkt, want_pub, sizeof(want_pub)) == 0, "PUBLISH, retained (%d)", n);
    static char payload[300];
    memset(payload, 'x', sizeof(payload));
    n = mqtt_publish_packet("t", payload, sizeof(payload), 0, pkt, sizeof(pkt));
    CHECK(n == 1 + 2 + (2 + 1 + 300) && pkt[1] == ((2 + 1 + 300) % 128 | 0x80) && pkt[2] == (2 + 1 + 300) / 128,
          "a remaining length of two bytes (%d)", n);
    CHECK(mqtt_publish_packet("a/#", "x", 1, 0, pkt, sizeof(pkt)) < 0 && mqtt_publish_packet("", "x", 1, 0, pkt, sizeof(pkt)) < 0,
          "a wildcard or no topic is no publish");

    /* against a stand-in */
    broker_t st;
    memset(&st, 0, sizeof(st));
    st.lfd = listener(&b.port);
    pthread_t th;
    pthread_create(&th, NULL, broker, &st);
    b.username = "me";
    int rc = mqtt_publish(&b, "forgefirm/job.ended", "{\"result\":\"ended\"}", 18, 0, err, sizeof(err));
    pthread_join(th, NULL);
    CHECK(rc == 0, "a publish the broker took: %s", err);
    CHECK(st.len > 27 && st.got[0] == 0x10 && memmem(st.got, st.len, "forgefirm/job.ended", 19)
          && memmem(st.got, st.len, "{\"result\":\"ended\"}", 18) && st.got[st.len - 2] == 0xe0 && st.got[st.len - 1] == 0,
          "it got the connect, the publish, and the disconnect (%zu bytes)", st.len);

    memset(&st, 0, sizeof(st));
    st.lfd = listener(&b.port);
    st.code = 5;
    pthread_create(&th, NULL, broker, &st);
    rc = mqtt_publish(&b, "t", "x", 1, 0, err, sizeof(err));
    pthread_join(th, NULL);
    CHECK(rc != 0 && strstr(err, "does not authorize"), "refused by the broker: %s", err);

    memset(&st, 0, sizeof(st));
    st.lfd = listener(&b.port);
    st.close_at_once = 1;
    pthread_create(&th, NULL, broker, &st);
    rc = mqtt_publish(&b, "t", "x", 1, 0, err, sizeof(err));
    pthread_join(th, NULL);
    CHECK(rc != 0 && (strstr(err, "closed") || strstr(err, "went away")), "a broker that closes at once: %s", err);

    close(st.lfd);
    rc = mqtt_publish(&b, "t", "x", 1, 0, err, sizeof(err));
    CHECK(rc != 0 && strstr(err, "did not take the connection"), "nobody listening: %s", err);
    b.host = "no-such-host.invalid";
    rc = mqtt_publish(&b, "t", "x", 1, 0, err, sizeof(err));
    CHECK(rc != 0 && strstr(err, "does not resolve"), "a name that does not resolve: %s", err);

    printf("%s: mqtt_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
