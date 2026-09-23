/*
 * mqtt.h - one MQTT 3.1.1 publish, at most once, over plain TCP
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * A connection per message: CONNECT with a clean session, the CONNACK,
 * one PUBLISH at QoS 0, DISCONNECT. That is what a rule needs to tell a
 * broker something, and it keeps no session a broker could leave half
 * open. A broker that takes only TLS is not reached.
 */
#ifndef AUTOMATION_MQTT_H
#define AUTOMATION_MQTT_H

#include <stddef.h>

#define MQTT_TOPIC_MAX   256
#define MQTT_PAYLOAD_MAX 4096

typedef struct {
    const char *host;               /* a name or an address */
    int port;
    const char *username, *password;    /* "" or NULL for none */
    const char *client_id;
    int timeout_ms;                 /* for the whole exchange */
} mqtt_broker_t;

/* 0 when the broker took the connection and the publish went out, or -1
 * with the words (a refused connection, the broker's own return code, a
 * timeout). */
int mqtt_publish(const mqtt_broker_t *b, const char *topic, const char *payload, size_t plen, int retain, char *err,
                 size_t elen);

/* The bytes of a CONNECT or a PUBLISH, for the host test: the length, or
 * -1 when it does not fit. */
int mqtt_connect_packet(const mqtt_broker_t *b, unsigned char *out, size_t olen);
int mqtt_publish_packet(const char *topic, const char *payload, size_t plen, int retain, unsigned char *out,
                        size_t olen);

#endif
