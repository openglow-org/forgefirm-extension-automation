/*
 * main.c - org.openglow.automation: the machine's events, turned into notifications and actions
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * Three threads. One follows the machine's events through the extension
 * API and matches each against the rules; one carries the actions out, one
 * at a time, so that a slow notification service delays the next action
 * and nothing else; and the main one answers the package's page and starts
 * the actions whose wait is over. A hold_until has a thread of its own
 * while it watches: it holds the job until an address answers with the
 * word it was given, which is how a job waits for its exhaust.
 *
 * The machine keeps no date, so every wait here is on the monotonic clock.
 */
#define _GNU_SOURCE
#define FFX_IMPLEMENTATION
#include "ffx.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "js.h"
#include "mqtt.h"
#include "rules.h"
#include "web.h"

#define LOG_EVENTS    16
#define LOG_OUTCOMES  24
#define TIMERS_MAX    64
#define QUEUE_MAX     64
#define TEST_TIMEOUT_S 7            /* a test answers the page inside the host's 10 s */

typedef struct {
    char rule[33];
    int index;
    js_t *action;                   /* a copy, secrets and all */
    char event[32];
    js_t *data;
    double due;
    js_t *cancel_on;                /* the action's own list, or NULL */
} job_t;

typedef struct {
    char event[32];
    char data[224];
    double t;
} event_log_t;

typedef struct {
    char rule[33];
    int index;
    char type[12];
    int ok;
    char detail[200];
    double t;
} outcome_t;

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t work = PTHREAD_COND_INITIALIZER;
static js_t *doc;                   /* the rules */
static char rules_path[512], rules_error[240];
static job_t timers[TIMERS_MAX], queue[QUEUE_MAX];
static int ntimers, nqueue;
static event_log_t events[LOG_EVENTS];
static int nevents;
static outcome_t outcomes[LOG_OUTCOMES];
static int noutcomes;
static int connected;               /* the host's own word on the machine's stream */
static unsigned long seen;          /* events matched since the start */

/* The one hold_until that may watch at a time. */
static pthread_mutex_t hold_mu = PTHREAD_MUTEX_INITIALIZER;
static int hold_running, hold_stop, hold_raised;
static char hold_reason[96];

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void say(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
}

static void job_free(job_t *j)
{
    js_free(j->action);
    js_free(j->data);
    js_free(j->cancel_on);
    memset(j, 0, sizeof(*j));
}

static void outcome(const char *rule, int index, const char *type, int ok, const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));

static void outcome(const char *rule, int index, const char *type, int ok, const char *fmt, ...)
{
    outcome_t o;
    memset(&o, 0, sizeof(o));
    snprintf(o.rule, sizeof(o.rule), "%s", rule);
    snprintf(o.type, sizeof(o.type), "%s", type);
    o.index = index;
    o.ok = ok;
    o.t = now();
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(o.detail, sizeof(o.detail), fmt, ap);
    va_end(ap);
    say("%s %s %d: %s: %s", ok ? "done" : "failed", o.rule, index + 1, o.type, o.detail);
    pthread_mutex_lock(&mu);
    if (noutcomes == LOG_OUTCOMES)
        memmove(outcomes, outcomes + 1, sizeof(outcomes[0]) * (LOG_OUTCOMES - 1)), noutcomes--;
    outcomes[noutcomes++] = o;
    pthread_mutex_unlock(&mu);
}

/* ---- the host ------------------------------------------------------------ */

static int api(const char *method, const char *path, const char *json, js_t **answer, int timeout_ms)
{
    ffx_reply_t r;
    *answer = NULL;
    if (ffx_request(method, path, json, &r, timeout_ms) != 0)
        return 0;
    int status = r.status;
    *answer = js_parse(r.body, r.len, NULL, 0);
    ffx_reply_free(&r);
    return status;
}

static int hold(int raise, const char *reason, char *err, size_t elen)
{
    js_t *ans = NULL, *req = js_object();
    js_set(req, "raised", js_boolean(raise));
    js_set(req, "reason", js_string(raise ? reason : ""));
    char *body = js_dump(req);
    js_free(req);
    if (!body)
        return snprintf(err, elen, "out of memory"), -1;
    int st = api("POST", "/v0/hold", body, &ans, 5000);
    free(body);
    int rc = st == 200 ? 0 : -1;
    if (rc != 0)
        snprintf(err, elen, "%s", st ? js_str(js_get(ans, "error"), "the host refused the hold") : "the host did not answer");
    js_free(ans);
    return rc;
}

/* ---- the actions ----------------------------------------------------------- */

static void strip_ctl(char *s)
{
    for (; *s; s++)
        if ((unsigned char)*s < 0x20 || *s == 0x7f)
            *s = ' ';
}

static int http_outcome(const web_req_t *rq, web_ans_t *ans, char *detail, size_t dlen)
{
    char err[200];
    if (web_do(rq, ans, err, sizeof(err)) != 0) {
        snprintf(detail, dlen, "%s", err);
        return 0;
    }
    int ok = ans->status >= 200 && ans->status < 300;
    char first[80];
    snprintf(first, sizeof(first), "%.79s", ans->body);
    strip_ctl(first);
    snprintf(detail, dlen, "HTTP %d%s%s", ans->status, ok || !first[0] ? "" : ": ", ok ? "" : first);
    return ok;
}

/* A notification, in each service's own form. */
static int notify(const js_t *a, const char *event, const js_t *data, char *detail, size_t dlen, int timeout_s)
{
    static web_ans_t ans;
    web_req_t rq;
    const char *svc = js_str(js_get(a, "service"), "");
    char *title = rules_expand(js_str(js_get(a, "title"), ""), event, data, 0);
    char *msg = rules_expand(js_str(js_get(a, "message"), ""), event, data, 0);
    char url[1200], h1[200], h2[200], h3[700], f[6][600];
    char *body = NULL;
    size_t blen = 0, bcap = 0;
    int ok = 0;
    memset(&rq, 0, sizeof(rq));
    rq.method = "POST";
    rq.timeout_s = timeout_s;
    if (!title || !msg) {
        snprintf(detail, dlen, "out of memory");
        goto out;
    }
    strip_ctl(title);
    if (strcmp(svc, "ntfy") == 0) {
        const char *server = js_str(js_get(a, "server"), "");
        snprintf(url, sizeof(url), "%s/%s", server[0] ? server : "https://ntfy.sh", js_str(js_get(a, "topic"), ""));
        int h = 0;
        if (title[0])
            snprintf(h1, sizeof(h1), "Title: %.180s", title), rq.headers[h++] = h1;
        if (js_get(a, "priority"))
            snprintf(h2, sizeof(h2), "Priority: %d", (int)js_num(js_get(a, "priority"), 3)), rq.headers[h++] = h2;
        if (js_str(js_get(a, "token"), "")[0])
            snprintf(h3, sizeof(h3), "Authorization: Bearer %.600s", js_str(js_get(a, "token"), "")), rq.headers[h++] = h3;
        rq.headers[h++] = "Content-Type: text/plain; charset=utf-8";
        rq.url = url;
        rq.body = msg;
        rq.blen = strlen(msg);
    } else if (strcmp(svc, "pushover") == 0) {
        snprintf(url, sizeof(url), "https://api.pushover.net/1/messages.json");
        snprintf(f[0], sizeof(f[0]), "token=%s", js_str(js_get(a, "token"), ""));
        snprintf(f[1], sizeof(f[1]), "user=%s", js_str(js_get(a, "user"), ""));
        snprintf(f[2], sizeof(f[2]), "message=%s", msg);
        int k = 3;
        if (title[0])
            snprintf(f[k], sizeof(f[k]), "title=%s", title), k++;
        if (js_get(a, "priority"))
            snprintf(f[k], sizeof(f[k]), "priority=%d", (int)js_num(js_get(a, "priority"), 0)), k++;
        for (int i = 0; i < k; i++)
            rq.form[i] = f[i];
        rq.url = url;
    } else {
        /* the three that take JSON */
        js_t *o = js_object();
        if (strcmp(svc, "telegram") == 0) {
            snprintf(url, sizeof(url), "https://api.telegram.org/bot%s/sendMessage", js_str(js_get(a, "token"), ""));
            char text[RULE_TEXT_MAX * 5];
            snprintf(text, sizeof(text), "%s%s%s", title, title[0] ? "\n" : "", msg);
            js_set(o, "chat_id", js_string(js_str(js_get(a, "chat_id"), "")));
            js_set(o, "text", js_string(text));
        } else if (strcmp(svc, "discord") == 0) {
            snprintf(url, sizeof(url), "%s", js_str(js_get(a, "url"), ""));
            char text[RULE_TEXT_MAX * 5];
            snprintf(text, sizeof(text), "%s%s%s%s", title[0] ? "**" : "", title, title[0] ? "**\n" : "", msg);
            js_set(o, "content", js_string(text));
        } else {
            snprintf(url, sizeof(url), "%s", js_str(js_get(a, "url"), ""));
            js_set(o, "event", js_string(event));
            js_set(o, "data", data ? js_copy(data) : js_object());
            js_set(o, "title", js_string(title));
            js_set(o, "message", js_string(msg));
        }
        body = js_dump(o);
        js_free(o);
        if (!body) {
            snprintf(detail, dlen, "out of memory");
            goto out;
        }
        blen = strlen(body);
        (void)bcap;
        rq.headers[0] = "Content-Type: application/json";
        rq.url = url;
        rq.body = body;
        rq.blen = blen;
    }
    ok = http_outcome(&rq, &ans, detail, dlen);
out:
    free(title);
    free(msg);
    free(body);
    return ok;
}

static int http_action(const js_t *a, const char *event, const js_t *data, char *detail, size_t dlen, int timeout_s)
{
    static web_ans_t ans;
    web_req_t rq;
    char ct[100], auth[560];
    const char *type = js_str(js_get(a, "content_type"), "");
    char *body = js_get(a, "body") ? rules_expand(js_str(js_get(a, "body"), ""), event, data, strstr(type, "json") != NULL)
                                   : NULL;
    memset(&rq, 0, sizeof(rq));
    rq.method = js_str(js_get(a, "method"), "GET");
    rq.url = js_str(js_get(a, "url"), "");
    rq.timeout_s = timeout_s;
    int h = 0;
    if (type[0])
        snprintf(ct, sizeof(ct), "Content-Type: %s", type), rq.headers[h++] = ct;
    if (js_str(js_get(a, "auth"), "")[0])
        snprintf(auth, sizeof(auth), "Authorization: %s", js_str(js_get(a, "auth"), "")), rq.headers[h++] = auth;
    if (body) {
        rq.body = body;
        rq.blen = strlen(body);
    }
    int ok = http_outcome(&rq, &ans, detail, dlen);
    free(body);
    return ok;
}

static int mqtt_action(const js_t *a, const char *event, const js_t *data, char *detail, size_t dlen, int timeout_s)
{
    char host[260], err[200], id[40];
    snprintf(host, sizeof(host), "%s", js_str(js_get(a, "broker"), ""));
    char *colon = strrchr(host, ':');
    int port = colon ? atoi(colon + 1) : 1883;
    if (colon)
        *colon = '\0';
    if (host[0] == '[' && strlen(host) > 2 && host[strlen(host) - 1] == ']') {
        memmove(host, host + 1, strlen(host));
        host[strlen(host) - 1] = '\0';
    }
    char *topic = rules_expand(js_str(js_get(a, "topic"), ""), event, data, 0);
    char *payload = js_get(a, "payload") ? rules_expand(js_str(js_get(a, "payload"), ""), event, data, 0) : NULL;
    if (!payload) {
        js_t *o = js_object();
        js_set(o, "event", js_string(event));
        js_set(o, "data", data ? js_copy(data) : js_object());
        payload = js_dump(o);
        js_free(o);
    }
    snprintf(id, sizeof(id), "forgefirm-%d", (int)getpid());
    mqtt_broker_t b = { host, port, js_str(js_get(a, "username"), ""), js_str(js_get(a, "password"), ""), id,
                        timeout_s * 1000 };
    int ok = topic && payload && mqtt_publish(&b, topic, payload, strlen(payload), js_bool(js_get(a, "retain"), 0), err,
                                              sizeof(err)) == 0;
    snprintf(detail, dlen, "%s", ok ? "published" : (topic && payload ? err : "out of memory"));
    free(topic);
    free(payload);
    return ok;
}

typedef struct {
    js_t *action;
    char rule[33];
    int index;
} hold_arg_t;

/* Does the answer hold the word? Spacing is not what tells a device's
 * "on" from its "off", and devices space their JSON as they like, so the
 * two are compared once as they are and once with the white space out. */
static int holds_word(const char *body, const char *word)
{
    if (strstr(body, word))
        return 1;
    static char b[WEB_ANSWER_MAX + 1];
    char w[200];
    size_t nb = 0, nw = 0;
    for (const char *p = body; *p && nb < WEB_ANSWER_MAX; p++)
        if (*p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
            b[nb++] = *p;
    b[nb] = '\0';
    for (const char *p = word; *p && nw < sizeof(w) - 1; p++)
        if (*p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
            w[nw++] = *p;
    w[nw] = '\0';
    return nw > 0 && strstr(b, w) != NULL;
}

/* hold_until, on a thread of its own: the hold goes up, the address is
 * asked every every_s seconds, and the hold comes down when the answer
 * holds the word. A job that ends stops the watch; one that does not see
 * the word in time leaves the hold up, in words, for the operator. */
static void *hold_watch(void *p)
{
    hold_arg_t *h = p;
    const js_t *a = h->action;
    int timeout = (int)js_num(js_get(a, "timeout_s"), 30), every = (int)js_num(js_get(a, "every_s"), 2);
    const char *match = js_str(js_get(a, "match"), "");
    char reason[96], err[200];
    snprintf(reason, sizeof(reason), "%.80s", js_str(js_get(a, "reason"), "")[0] ? js_str(js_get(a, "reason"), "")
                                                                                     : "waiting for the exhaust to confirm");
    if (hold(1, reason, err, sizeof(err)) != 0) {
        outcome(h->rule, h->index, "hold_until", 0, "the hold could not be raised: %s", err);
        goto out;
    }
    pthread_mutex_lock(&hold_mu);
    hold_raised = 1;
    snprintf(hold_reason, sizeof(hold_reason), "%s", reason);
    pthread_mutex_unlock(&hold_mu);
    double end = now() + timeout;
    static web_ans_t ans;
    while (now() < end) {
        pthread_mutex_lock(&hold_mu);
        int stop = hold_stop;
        pthread_mutex_unlock(&hold_mu);
        if (stop) {
            outcome(h->rule, h->index, "hold_until", 1, "the job ended while it waited");
            goto out;
        }
        web_req_t rq;
        char auth[560];
        memset(&rq, 0, sizeof(rq));
        rq.method = "GET";
        rq.url = js_str(js_get(a, "url"), "");
        rq.timeout_s = every + 3;
        if (js_str(js_get(a, "auth"), "")[0])
            snprintf(auth, sizeof(auth), "Authorization: %s", js_str(js_get(a, "auth"), "")), rq.headers[0] = auth;
        if (web_do(&rq, &ans, err, sizeof(err)) == 0 && ans.status >= 200 && ans.status < 300 && holds_word(ans.body, match)) {
            if (hold(0, "", err, sizeof(err)) == 0) {
                pthread_mutex_lock(&hold_mu);
                hold_raised = 0;
                hold_reason[0] = '\0';
                pthread_mutex_unlock(&hold_mu);
                outcome(h->rule, h->index, "hold_until", 1, "confirmed after %.0f s: the hold is clear",
                        timeout - (end - now()));
            } else {
                outcome(h->rule, h->index, "hold_until", 0, "confirmed, and the hold could not be cleared: %s", err);
            }
            goto out;
        }
        for (int i = 0; i < every * 10; i++) {
            pthread_mutex_lock(&hold_mu);
            int s = hold_stop;
            pthread_mutex_unlock(&hold_mu);
            if (s)
                break;
            usleep(100000);
        }
    }
    snprintf(reason, sizeof(reason), "it did not confirm within %d s", timeout);
    hold(1, reason, err, sizeof(err));
    pthread_mutex_lock(&hold_mu);
    snprintf(hold_reason, sizeof(hold_reason), "%s", reason);
    pthread_mutex_unlock(&hold_mu);
    outcome(h->rule, h->index, "hold_until", 0, "%s; the hold stands until the job ends", reason);
out:
    pthread_mutex_lock(&hold_mu);
    hold_running = 0;
    pthread_mutex_unlock(&hold_mu);
    js_free(h->action);
    free(h);
    return NULL;
}

static void clear_hold(const char *rule, int index)
{
    char err[200];
    pthread_mutex_lock(&hold_mu);
    hold_stop = hold_running;
    int was = hold_raised;
    pthread_mutex_unlock(&hold_mu);
    if (!was && rule == NULL)
        return;
    if (hold(0, "", err, sizeof(err)) == 0) {
        pthread_mutex_lock(&hold_mu);
        hold_raised = 0;
        hold_reason[0] = '\0';
        pthread_mutex_unlock(&hold_mu);
        if (rule)
            outcome(rule, index, "clear_hold", 1, "the hold is clear");
    } else if (rule) {
        outcome(rule, index, "clear_hold", 0, "%s", err);
    }
}

static void run(job_t *j, int timeout_s)
{
    char detail[200];
    const char *type = js_str(js_get(j->action, "type"), "");
    int ok = 0;
    if (strcmp(type, "notify") == 0) {
        ok = notify(j->action, j->event, j->data, detail, sizeof(detail), timeout_s);
    } else if (strcmp(type, "http") == 0) {
        ok = http_action(j->action, j->event, j->data, detail, sizeof(detail), timeout_s);
    } else if (strcmp(type, "mqtt") == 0) {
        ok = mqtt_action(j->action, j->event, j->data, detail, sizeof(detail), timeout_s);
    } else if (strcmp(type, "clear_hold") == 0) {
        clear_hold(j->rule, j->index);
        return;
    } else if (strcmp(type, "hold_until") == 0) {
        pthread_mutex_lock(&hold_mu);
        int busy = hold_running;
        if (!busy) {
            hold_running = 1;
            hold_stop = 0;
        }
        pthread_mutex_unlock(&hold_mu);
        if (busy) {
            outcome(j->rule, j->index, type, 0, "another hold_until is already watching");
            return;
        }
        hold_arg_t *h = calloc(1, sizeof(*h));
        pthread_t th;
        if (h && (h->action = js_copy(j->action))) {
            snprintf(h->rule, sizeof(h->rule), "%s", j->rule);
            h->index = j->index;
            if (pthread_create(&th, NULL, hold_watch, h) == 0) {
                pthread_detach(th);
                return;
            }
            js_free(h->action);
        }
        free(h);
        pthread_mutex_lock(&hold_mu);
        hold_running = 0;
        pthread_mutex_unlock(&hold_mu);
        outcome(j->rule, j->index, type, 0, "it could not start watching");
        return;
    }
    outcome(j->rule, j->index, type, ok, "%s", detail);
}

static void *worker(void *unused)
{
    (void)unused;
    for (;;) {
        pthread_mutex_lock(&mu);
        while (nqueue == 0)
            pthread_cond_wait(&work, &mu);
        job_t j = queue[0];
        memmove(queue, queue + 1, sizeof(queue[0]) * (size_t)(--nqueue));
        pthread_mutex_unlock(&mu);
        run(&j, 10);
        job_free(&j);
    }
    return NULL;
}

/* Under mu. */
static void enqueue(job_t *j)
{
    if (nqueue == QUEUE_MAX) {
        say("the action queue is full: %s %d is dropped", j->rule, j->index + 1);
        job_free(j);
        return;
    }
    queue[nqueue++] = *j;
    memset(j, 0, sizeof(*j));
    pthread_cond_signal(&work);
}

/* ---- the events ------------------------------------------------------------ */

static int listed(const js_t *list, const char *event)
{
    for (int i = 0; i < js_len(list); i++)
        if (strcmp(js_str(js_at(list, i), ""), event) == 0 || strcmp(js_str(js_at(list, i), ""), "*") == 0)
            return 1;
    return 0;
}

static void on_event(const char *event, const js_t *data)
{
    int ended = strcmp(event, "job.ended") == 0;
    if (strncmp(event, "ext.", 4) == 0)
        say("the host says %s%s%s", event, js_get(data, "reason") ? ": " : "", js_str(js_get(data, "reason"), ""));
    pthread_mutex_lock(&mu);
    if (nevents == LOG_EVENTS)
        memmove(events, events + 1, sizeof(events[0]) * (LOG_EVENTS - 1)), nevents--;
    event_log_t *e = &events[nevents++];
    snprintf(e->event, sizeof(e->event), "%s", event);
    char *d = js_dump(data);
    snprintf(e->data, sizeof(e->data), "%s", d ? d : "");
    free(d);
    e->t = now();
    /* a waiting action goes when an event it names comes first */
    for (int i = 0; i < ntimers;) {
        if (listed(timers[i].cancel_on, event)) {
            say("canceled: %s %d waited for %s, and %s came first", timers[i].rule, timers[i].index + 1,
                timers[i].event, event);
            job_free(&timers[i]);
            timers[i] = timers[--ntimers];
            memset(&timers[ntimers], 0, sizeof(timers[0]));
            continue;
        }
        i++;
    }
    js_t *list = js_get(doc, "rules");
    for (int r = 0; r < js_len(list); r++) {
        js_t *rule = js_at(list, r);
        if (!rules_match(rule, event, data))
            continue;
        seen++;
        js_t *act = js_get(rule, "do");
        for (int k = 0; k < js_len(act); k++) {
            js_t *a = js_at(act, k);
            job_t j;
            memset(&j, 0, sizeof(j));
            snprintf(j.rule, sizeof(j.rule), "%s", js_str(js_get(rule, "id"), ""));
            snprintf(j.event, sizeof(j.event), "%s", event);
            j.index = k;
            j.action = js_copy(a);
            j.data = data ? js_copy(data) : js_object();
            j.cancel_on = js_copy(js_get(a, "cancel_on"));
            double after = js_num(js_get(a, "after_s"), 0);
            if (after > 0) {
                if (ntimers == TIMERS_MAX) {
                    say("too many actions are waiting: %s %d is dropped", j.rule, k + 1);
                    job_free(&j);
                    continue;
                }
                j.due = now() + after;
                timers[ntimers++] = j;
            } else {
                enqueue(&j);
            }
        }
    }
    pthread_mutex_unlock(&mu);
    /* A hold this package put up for a job does not outlive the job. */
    if (ended)
        clear_hold(NULL, 0);
}

static void *follower(void *unused)
{
    (void)unused;
    unsigned long next = 0;
    int placed = 0;
    for (;;) {
        char body[64];
        js_t *ans = NULL;
        if (placed)
            snprintf(body, sizeof(body), "{\"since\":%lu,\"wait\":25}", next);
        else
            snprintf(body, sizeof(body), "{}");
        int st = api("POST", "/v0/events", body, &ans, 40000);
        if (st != 200) {
            if (st == 403 || st == 404)
                say("the host does not give this package its events (%d)", st);
            js_free(ans);
            pthread_mutex_lock(&mu);
            connected = 0;
            pthread_mutex_unlock(&mu);
            sleep(5);
            continue;
        }
        pthread_mutex_lock(&mu);
        connected = js_bool(js_get(ans, "connected"), 0);
        pthread_mutex_unlock(&mu);
        js_t *list = js_get(ans, "events");
        for (int i = 0; placed && i < js_len(list); i++) {
            js_t *ev = js_at(list, i);
            on_event(js_str(js_get(ev, "event"), ""), js_get(ev, "data"));
        }
        next = (unsigned long)js_num(js_get(ans, "next"), (double)next);
        placed = 1;
        js_free(ans);
    }
    return NULL;
}

/* ---- the page ------------------------------------------------------------- */

static void answer_json(char *out, size_t olen, js_t *v)
{
    char *t = js_dump(v);
    js_free(v);
    if (!t || strlen(t) >= olen)
        snprintf(out, olen, "{\"error\":\"the answer does not fit\"}");
    else
        strcpy(out, t);
    free(t);
}

static int refuse(char *out, size_t olen, int status, const char *why)
{
    js_t *o = js_object();
    js_set(o, "error", js_string(why));
    answer_json(out, olen, o);
    return status;
}

static js_t *rules_view(void)
{
    js_t *o = js_object(), *types = js_array(), *known = js_array();
    js_t *masked = rules_masked(doc);
    js_set(o, "rules", js_copy(js_get(masked, "rules")));
    js_free(masked);
    for (int i = 0; rules_action_types[i]; i++)
        js_push(types, js_string(rules_action_types[i]));
    for (int i = 0; rules_known_events[i]; i++)
        js_push(known, js_string(rules_known_events[i]));
    js_set(o, "action_types", types);
    js_set(o, "known_events", known);
    js_set(o, "kept", js_string(RULES_KEPT));
    if (rules_error[0])
        js_set(o, "error", js_string(rules_error));
    return o;
}

static int save(js_t *next, char *err, size_t elen)
{
    if (rules_check(next, err, elen) != 0 || rules_save(rules_path, next, err, elen) != 0) {
        js_free(next);
        return -1;
    }
    js_free(doc);
    doc = next;
    rules_error[0] = '\0';
    return 0;
}

static js_t *status_view(void)
{
    double t = now();
    js_t *o = js_object(), *ev = js_array(), *oc = js_array(), *pend = js_array(), *h = js_object();
    js_set(o, "connected", js_boolean(connected));
    js_set(o, "matched", js_number((double)seen));
    for (int i = nevents - 1; i >= 0; i--) {
        js_t *e = js_object();
        js_set(e, "event", js_string(events[i].event));
        js_set(e, "data", js_string(events[i].data));
        js_set(e, "ago_s", js_number((double)(long)(t - events[i].t)));
        js_push(ev, e);
    }
    for (int i = noutcomes - 1; i >= 0; i--) {
        js_t *e = js_object();
        js_set(e, "rule", js_string(outcomes[i].rule));
        js_set(e, "action", js_number(outcomes[i].index + 1));
        js_set(e, "type", js_string(outcomes[i].type));
        js_set(e, "ok", js_boolean(outcomes[i].ok));
        js_set(e, "detail", js_string(outcomes[i].detail));
        js_set(e, "ago_s", js_number((double)(long)(t - outcomes[i].t)));
        js_push(oc, e);
    }
    for (int i = 0; i < ntimers; i++) {
        js_t *e = js_object();
        js_set(e, "rule", js_string(timers[i].rule));
        js_set(e, "action", js_number(timers[i].index + 1));
        js_set(e, "after", js_string(timers[i].event));
        js_set(e, "in_s", js_number((double)(long)(timers[i].due - t + 0.5)));
        js_push(pend, e);
    }
    pthread_mutex_lock(&hold_mu);
    js_set(h, "raised", js_boolean(hold_raised));
    js_set(h, "reason", js_string(hold_reason));
    js_set(h, "watching", js_boolean(hold_running));
    pthread_mutex_unlock(&hold_mu);
    js_set(o, "events", ev);
    js_set(o, "outcomes", oc);
    js_set(o, "pending", pend);
    js_set(o, "hold", h);
    return o;
}

static int handle(void *ctx, const char *method, const char *path, const char *body, char *out, size_t olen)
{
    char err[240];
    (void)ctx;
    int get = strcmp(method, "GET") == 0;
    if (get && strcmp(path, "/rules") == 0) {
        pthread_mutex_lock(&mu);
        js_t *v = rules_view();
        pthread_mutex_unlock(&mu);
        answer_json(out, olen, v);
        return 200;
    }
    if (get && strcmp(path, "/status") == 0) {
        pthread_mutex_lock(&mu);
        js_t *v = status_view();
        pthread_mutex_unlock(&mu);
        answer_json(out, olen, v);
        return 200;
    }
    if (get)
        return refuse(out, olen, 404, "there is no such page call");
    js_t *req = js_parse(body, strlen(body), err, sizeof(err));
    if (!req)
        return refuse(out, olen, 400, err);
    int status = 200;
    pthread_mutex_lock(&mu);
    if (strcmp(path, "/rule") == 0) {
        js_t *rule = js_copy(js_get(req, "rule"));
        js_t *next = js_copy(doc);
        js_t *list = js_get(next, "rules");
        if (!rule || rules_check_rule(rule, err, sizeof(err)) != 0 || rules_keep_secrets(rule, doc, err, sizeof(err)) != 0) {
            if (!rule)
                snprintf(err, sizeof(err), "the call names no rule");
            js_free(rule);
            js_free(next);
            status = 400;
        } else {
            int at = -1;
            for (int i = 0; i < js_len(list); i++)
                if (strcmp(js_str(js_get(js_at(list, i), "id"), ""), js_str(js_get(rule, "id"), "")) == 0)
                    at = i;
            if (at >= 0) {
                js_free(list->kids[at]);
                list->kids[at] = rule;
            } else if (js_len(list) >= RULES_MAX) {
                js_free(rule);
                js_free(next);
                snprintf(err, sizeof(err), "at most %d rules", RULES_MAX);
                status = 400;
                next = NULL;
            } else {
                js_push(list, rule);
            }
            if (next && save(next, err, sizeof(err)) != 0)
                status = 400;
        }
    } else if (strcmp(path, "/rule/delete") == 0) {
        const char *id = js_str(js_get(req, "id"), "");
        js_t *next = js_object(), *keep = js_array();
        js_t *list = js_get(doc, "rules");
        int found = 0;
        for (int i = 0; i < js_len(list); i++) {
            if (strcmp(js_str(js_get(js_at(list, i), "id"), ""), id) == 0)
                found = 1;
            else
                js_push(keep, js_copy(js_at(list, i)));
        }
        js_set(next, "rules", keep);
        if (!found) {
            js_free(next);
            snprintf(err, sizeof(err), "there is no rule %.40s", id);
            status = 404;
        } else if (save(next, err, sizeof(err)) != 0) {
            status = 400;
        }
    } else if (strcmp(path, "/test") == 0) {
        /* A saved action, now, with the event "test": the page asks for
         * one to see that it reaches what it should. */
        const char *id = js_str(js_get(req, "rule"), "");
        int index = (int)js_num(js_get(req, "action"), 0) - 1;
        js_t *list = js_get(doc, "rules"), *rule = NULL;
        for (int i = 0; i < js_len(list); i++)
            if (strcmp(js_str(js_get(js_at(list, i), "id"), ""), id) == 0)
                rule = js_at(list, i);
        js_t *a = js_at(js_get(rule, "do"), index);
        const char *type = js_str(js_get(a, "type"), "");
        if (!a) {
            snprintf(err, sizeof(err), "there is no saved action %d in rule %.40s", index + 1, id);
            status = 404;
        } else if (strcmp(type, "hold_until") == 0 || strcmp(type, "clear_hold") == 0) {
            snprintf(err, sizeof(err), "a hold is tried with a job, not from here");
            status = 400;
        } else {
            job_t j;
            memset(&j, 0, sizeof(j));
            snprintf(j.rule, sizeof(j.rule), "%s", id);
            snprintf(j.event, sizeof(j.event), "test");
            j.index = index;
            j.action = js_copy(a);
            j.data = js_object();
            js_set(j.data, "test", js_boolean(1));
            pthread_mutex_unlock(&mu);
            run(&j, TEST_TIMEOUT_S);
            job_free(&j);
            pthread_mutex_lock(&mu);
            js_t *o = js_object();
            if (noutcomes > 0) {
                js_set(o, "ok", js_boolean(outcomes[noutcomes - 1].ok));
                js_set(o, "detail", js_string(outcomes[noutcomes - 1].detail));
            }
            pthread_mutex_unlock(&mu);
            js_free(req);
            answer_json(out, olen, o);
            return 200;
        }
    } else {
        status = 404;
        snprintf(err, sizeof(err), "there is no such page call");
    }
    js_t *v = status == 200 ? rules_view() : NULL;
    pthread_mutex_unlock(&mu);
    js_free(req);
    if (status != 200)
        return refuse(out, olen, status, err);
    answer_json(out, olen, v);
    return 200;
}

int main(void)
{
    const char *data = getenv("FFX_DATA");
    pthread_t th;
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (!data)
        return 2;
    snprintf(rules_path, sizeof(rules_path), "%.490s/rules.json", data);
    doc = rules_load(rules_path, rules_error, sizeof(rules_error));
    if (!doc) {
        say("%s: running with no rules until the page saves some", rules_error);
        doc = js_object();
        js_set(doc, "rules", js_array());
    }
    say("automation up: %d rule%s", js_len(js_get(doc, "rules")), js_len(js_get(doc, "rules")) == 1 ? "" : "s");
    if (pthread_create(&th, NULL, worker, NULL) != 0 || pthread_detach(th) != 0 ||
        pthread_create(&th, NULL, follower, NULL) != 0 || pthread_detach(th) != 0)
        return 3;
    int page = ffx_call_fd() >= 0;
    for (;;) {
        if (page)
            ffx_serve_one(handle, NULL, 250);
        else
            usleep(250000);
        double t = now();
        pthread_mutex_lock(&mu);
        for (int i = 0; i < ntimers;) {
            if (timers[i].due <= t) {
                job_t j = timers[i];
                timers[i] = timers[--ntimers];
                memset(&timers[ntimers], 0, sizeof(timers[0]));
                enqueue(&j);
                continue;
            }
            i++;
        }
        pthread_mutex_unlock(&mu);
    }
}
