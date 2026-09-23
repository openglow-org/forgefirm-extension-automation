/*
 * web.h - one HTTP request, through the image's curl
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * The image carries curl, with TLS, and the service carries none of its
 * own: a request is curl run with an argument vector (never a shell), the
 * protocols held to http and https, redirects too, no configuration file
 * read, and a deadline. The body goes in on standard input and the answer
 * comes back on standard output with the status after it.
 */
#ifndef AUTOMATION_WEB_H
#define AUTOMATION_WEB_H

#include <stddef.h>

#define WEB_CURL_DEFAULT  "/usr/bin/curl"
#define WEB_MAX_HEADERS   8
#define WEB_ANSWER_MAX    (8 * 1024)        /* what is kept of an answer: enough to match a word in it */

typedef struct {
    const char *method;                     /* GET, POST, PUT */
    const char *url;
    const char *headers[WEB_MAX_HEADERS];   /* "Name: value", NULL-ended */
    const char *body;                       /* NULL for none */
    size_t blen;
    const char *form[16];                   /* "name=value" pairs sent URL-encoded, NULL-ended; with no body */
    int timeout_s;
} web_req_t;

typedef struct {
    int status;                             /* the HTTP status, or 0 when there was none */
    char body[WEB_ANSWER_MAX + 1];          /* NUL-ended, cut at WEB_ANSWER_MAX */
    size_t blen;
} web_ans_t;

/* The curl to run (a test's stand-in); WEB_CURL_DEFAULT unless set. */
void web_set_curl(const char *path);

/* A URL this service may ask for: http or https, a host, at most 1024
 * bytes, no whitespace, no control character, and no user:password part. */
int web_url_ok(const char *url);

/* host:port of a URL, as net.outbound writes it (IPv6 in brackets); 0,
 * or -1 when it is no such URL. */
int web_url_dest(const char *url, char *out, size_t olen);

/* One request. 0 when an answer came back, whatever its status; -1 with
 * the words when none did (curl's own reason). */
int web_do(const web_req_t *r, web_ans_t *a, char *err, size_t elen);

#endif
