/*
 * rules.c - the automation package's rules
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * See rules.h.
 */
#define _GNU_SOURCE
#include "rules.h"

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "web.h"

const char *const rules_action_types[] = { "notify", "http", "mqtt", "hold_until", "clear_hold", NULL };
const char *const rules_known_events[] = {
    "job.arming", "job.armed", "job.paused", "job.resumed", "job.ended", "alarm", "cooling.verdict", "lid",
    "interlock", "mode.changed", "controller.started", "controller.stopped", "homing.started", "homing.completed",
    "homing.failed", "motors.released", "motors.energized", "lease.changed", NULL,
};
static const char *const services[] = { "ntfy", "pushover", "telegram", "discord", "webhook", NULL };

/* Where each action keeps a secret: (type, service or NULL, field). */
static const struct { const char *type, *service, *field; } secrets[] = {
    { "notify", "ntfy", "token" },       { "notify", "pushover", "token" }, { "notify", "pushover", "user" },
    { "notify", "telegram", "token" },   { "notify", "discord", "url" },
    { "http", NULL, "auth" },            { "mqtt", NULL, "password" },      { "hold_until", NULL, "auth" },
};

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

static int in_list(const char *s, const char *const *list)
{
    for (int i = 0; s && list[i]; i++)
        if (strcmp(s, list[i]) == 0)
            return 1;
    return 0;
}

static int event_name_ok(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    if (n == 1 && s[0] == '*')
        return 1;
    if (n < 1 || n > 31 || s[0] < 'a' || s[0] > 'z')
        return 0;
    return strspn(s, "abcdefghijklmnopqrstuvwxyz0123456789._-") == n;
}

/* The keys an object may hold; any other is refused by name. */
static int only_keys(const js_t *o, const char *const *allowed, const char *what, char *err, size_t elen)
{
    for (int i = 0; i < js_len(o); i++)
        if (!in_list(o->keys[i], allowed))
            return fail(err, elen, "%s has no field \"%.32s\"", what, o->keys[i]);
    return 0;
}

/* A text field: absent (when optional) or a string of at most max bytes. */
static int text(const js_t *o, const char *key, int required, size_t max, const char *what, char *err, size_t elen)
{
    js_t *v = js_get(o, key);
    if (!v)
        return required ? fail(err, elen, "%s needs %s", what, key) : 0;
    if (!js_is(v, JS_STR))
        return fail(err, elen, "%s's %s is text", what, key);
    if (strlen(v->s) > max)
        return fail(err, elen, "%s's %s is at most %zu bytes", what, key, max);
    if (required && !v->s[0])
        return fail(err, elen, "%s needs %s", what, key);
    return 0;
}

static int number(const js_t *o, const char *key, double lo, double hi, const char *what, char *err, size_t elen)
{
    js_t *v = js_get(o, key);
    if (!v)
        return 0;
    if (!js_is(v, JS_NUM) || v->n < lo || v->n > hi || v->n != floor(v->n))
        return fail(err, elen, "%s's %s is a whole number from %.0f to %.0f", what, key, lo, hi);
    return 0;
}

static int url_field(const js_t *o, const char *key, int required, const char *what, char *err, size_t elen)
{
    if (text(o, key, required, 1024, what, err, elen) != 0)
        return -1;
    const char *u = js_str(js_get(o, key), NULL);
    if (u && strcmp(u, RULES_KEPT) != 0 && (u[0] || required) && !web_url_ok(u))
        return fail(err, elen, "%s's %s is an http:// or https:// address with no user or password in it", what, key);
    return 0;
}

static int check_action(const js_t *a, int i, char *err, size_t elen)
{
    char what[40];
    snprintf(what, sizeof(what), "action %d", i + 1);
    if (!js_is(a, JS_OBJ))
        return fail(err, elen, "%s is an object", what);
    const char *type = js_str(js_get(a, "type"), NULL);
    if (!in_list(type, rules_action_types))
        return fail(err, elen, "%s's type is notify, http, mqtt, hold_until, or clear_hold", what);
    if (number(a, "after_s", 0, 3600, what, err, elen) != 0)
        return -1;
    js_t *cancel = js_get(a, "cancel_on");
    if (cancel) {
        if (!js_is(cancel, JS_ARR) || js_len(cancel) > RULE_EVENTS_MAX)
            return fail(err, elen, "%s's cancel_on is a list of at most %d events", what, RULE_EVENTS_MAX);
        for (int k = 0; k < js_len(cancel); k++)
            if (!event_name_ok(js_str(js_at(cancel, k), NULL)))
                return fail(err, elen, "%s's cancel_on names no event", what);
    }
    if (strcmp(type, "notify") == 0) {
        static const char *const keys[] = { "type", "after_s", "cancel_on", "service", "title", "message", "topic",
                                            "server", "token", "priority", "user", "chat_id", "url", NULL };
        const char *svc = js_str(js_get(a, "service"), NULL);
        if (only_keys(a, keys, what, err, elen) != 0)
            return -1;
        if (!in_list(svc, services))
            return fail(err, elen, "%s's service is ntfy, pushover, telegram, discord, or webhook", what);
        if (text(a, "title", 0, 128, what, err, elen) != 0 || text(a, "message", 1, RULE_TEXT_MAX, what, err, elen) != 0)
            return -1;
        if (strcmp(svc, "ntfy") == 0) {
            const char *topic = js_str(js_get(a, "topic"), "");
            if (text(a, "topic", 1, 64, what, err, elen) != 0 || text(a, "token", 0, 128, what, err, elen) != 0
                || url_field(a, "server", 0, what, err, elen) != 0 || number(a, "priority", 1, 5, what, err, elen) != 0)
                return -1;
            if (strspn(topic, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != strlen(topic))
                return fail(err, elen, "%s's topic is letters, digits, '-', and '_'", what);
        } else if (strcmp(svc, "pushover") == 0) {
            if (text(a, "token", 1, 64, what, err, elen) != 0 || text(a, "user", 1, 64, what, err, elen) != 0
                || number(a, "priority", -2, 1, what, err, elen) != 0)
                return -1;
        } else if (strcmp(svc, "telegram") == 0) {
            if (text(a, "token", 1, 128, what, err, elen) != 0 || text(a, "chat_id", 1, 64, what, err, elen) != 0)
                return -1;
            const char *tok = js_str(js_get(a, "token"), "");
            if (strcmp(tok, RULES_KEPT) != 0 && strspn(tok, "0123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-")
                                                    != strlen(tok))
                return fail(err, elen, "%s's token is a Telegram bot's token", what);
        } else {
            if (url_field(a, "url", 1, what, err, elen) != 0)
                return -1;
        }
        return 0;
    }
    if (strcmp(type, "http") == 0) {
        static const char *const keys[] = { "type", "after_s", "cancel_on", "method", "url", "body", "content_type",
                                            "auth", NULL };
        const char *m = js_str(js_get(a, "method"), "GET");
        if (only_keys(a, keys, what, err, elen) != 0 || url_field(a, "url", 1, what, err, elen) != 0
            || text(a, "body", 0, 2048, what, err, elen) != 0 || text(a, "content_type", 0, 64, what, err, elen) != 0
            || text(a, "auth", 0, 512, what, err, elen) != 0 || text(a, "method", 0, 8, what, err, elen) != 0)
            return -1;
        if (strcmp(m, "GET") != 0 && strcmp(m, "POST") != 0 && strcmp(m, "PUT") != 0)
            return fail(err, elen, "%s's method is GET, POST, or PUT", what);
        for (const char *f = js_str(js_get(a, "content_type"), ""); *f; f++)
            if (*f < 0x20 || *f == 0x7f)
                return fail(err, elen, "%s's content_type holds a control character", what);
        for (const char *f = js_str(js_get(a, "auth"), ""); *f; f++)
            if (*f < 0x20 || *f == 0x7f)
                return fail(err, elen, "%s's auth holds a control character", what);
        return 0;
    }
    if (strcmp(type, "mqtt") == 0) {
        static const char *const keys[] = { "type", "after_s", "cancel_on", "broker", "topic", "payload", "retain",
                                            "username", "password", NULL };
        if (only_keys(a, keys, what, err, elen) != 0 || text(a, "broker", 1, 260, what, err, elen) != 0
            || text(a, "topic", 1, 256, what, err, elen) != 0 || text(a, "payload", 0, 2048, what, err, elen) != 0
            || text(a, "username", 0, 128, what, err, elen) != 0 || text(a, "password", 0, 128, what, err, elen) != 0)
            return -1;
        js_t *r = js_get(a, "retain");
        if (r && !js_is(r, JS_BOOL))
            return fail(err, elen, "%s's retain is true or false", what);
        const char *b = js_str(js_get(a, "broker"), ""), *colon = strrchr(b, ':');
        char *end = NULL;
        long port = colon ? strtol(colon + 1, &end, 10) : 0;
        if (!colon || colon == b || !end || *end || port < 1 || port > 65535)
            return fail(err, elen, "%s's broker is host:port", what);
        if (strpbrk(js_str(js_get(a, "topic"), ""), "#+"))
            return fail(err, elen, "%s's topic names one topic, with no wildcard", what);
        return 0;
    }
    if (strcmp(type, "hold_until") == 0) {
        static const char *const keys[] = { "type", "after_s", "cancel_on", "url", "match", "timeout_s", "every_s",
                                            "reason", "auth", NULL };
        if (only_keys(a, keys, what, err, elen) != 0 || url_field(a, "url", 1, what, err, elen) != 0
            || text(a, "match", 1, 128, what, err, elen) != 0 || text(a, "reason", 0, 80, what, err, elen) != 0
            || text(a, "auth", 0, 512, what, err, elen) != 0 || number(a, "timeout_s", 5, 300, what, err, elen) != 0
            || number(a, "every_s", 1, 10, what, err, elen) != 0)
            return -1;
        for (const char *f = js_str(js_get(a, "auth"), ""); *f; f++)
            if (*f < 0x20 || *f == 0x7f)
                return fail(err, elen, "%s's auth holds a control character", what);
        for (const char *f = js_str(js_get(a, "reason"), ""); *f; f++)
            if (*f < 0x20 || *f > 0x7e || *f == '"' || *f == '\\')
                return fail(err, elen, "%s's reason is printable ASCII without the quote and the backslash", what);
        return 0;
    }
    static const char *const keys[] = { "type", "after_s", "cancel_on", NULL };
    return only_keys(a, keys, what, err, elen);
}

int rules_check_rule(const js_t *rule, char *err, size_t elen)
{
    static const char *const keys[] = { "id", "name", "enabled", "on", "if", "do", NULL };
    char e[200];
    if (!js_is(rule, JS_OBJ))
        return fail(err, elen, "a rule is an object");
    const char *id = js_str(js_get(rule, "id"), "");
    size_t n = strlen(id);
    if (n < 1 || n > 32 || strspn(id, "abcdefghijklmnopqrstuvwxyz0123456789-") != n)
        return fail(err, elen, "a rule's id is 1 to 32 lowercase letters, digits, and '-'");
    if (only_keys(rule, keys, "a rule", err, elen) != 0 || text(rule, "name", 0, 64, "a rule", err, elen) != 0)
        return -1;
    js_t *en = js_get(rule, "enabled");
    if (en && !js_is(en, JS_BOOL))
        return fail(err, elen, "rule %s: enabled is true or false", id);
    js_t *on = js_get(rule, "on");
    if (!js_is(on, JS_ARR) || js_len(on) < 1 || js_len(on) > RULE_EVENTS_MAX)
        return fail(err, elen, "rule %s: on is a list of 1 to %d events", id, RULE_EVENTS_MAX);
    for (int i = 0; i < js_len(on); i++)
        if (!event_name_ok(js_str(js_at(on, i), NULL)))
            return fail(err, elen, "rule %s: on names an event, or \"*\" for every one", id);
    js_t *cond = js_get(rule, "if");
    if (cond) {
        if (!js_is(cond, JS_OBJ) || js_len(cond) > 8)
            return fail(err, elen, "rule %s: if is an object of at most 8 fields", id);
        for (int i = 0; i < js_len(cond); i++) {
            js_t *v = js_at(cond, i);
            if (!js_is(v, JS_STR) && !js_is(v, JS_NUM) && !js_is(v, JS_BOOL))
                return fail(err, elen, "rule %s: if compares text, numbers, and true or false", id);
            if (js_is(v, JS_STR) && strlen(v->s) > 64)
                return fail(err, elen, "rule %s: an if value is at most 64 bytes", id);
        }
    }
    js_t *act = js_get(rule, "do");
    if (!js_is(act, JS_ARR) || js_len(act) < 1 || js_len(act) > RULE_ACTIONS_MAX)
        return fail(err, elen, "rule %s: do is a list of 1 to %d actions", id, RULE_ACTIONS_MAX);
    for (int i = 0; i < js_len(act); i++)
        if (check_action(js_at(act, i), i, e, sizeof(e)) != 0)
            return fail(err, elen, "rule %s: %s", id, e);
    return 0;
}

int rules_check(const js_t *doc, char *err, size_t elen)
{
    js_t *list = js_get(doc, "rules");
    if (!js_is(doc, JS_OBJ) || !js_is(list, JS_ARR))
        return fail(err, elen, "the rules are {\"rules\": [...]}");
    if (js_len(list) > RULES_MAX)
        return fail(err, elen, "at most %d rules", RULES_MAX);
    for (int i = 0; i < js_len(list); i++) {
        if (rules_check_rule(js_at(list, i), err, elen) != 0)
            return -1;
        for (int k = 0; k < i; k++)
            if (strcmp(js_str(js_get(js_at(list, k), "id"), ""), js_str(js_get(js_at(list, i), "id"), "")) == 0)
                return fail(err, elen, "two rules are named %s", js_str(js_get(js_at(list, i), "id"), ""));
    }
    return 0;
}

static int is_secret(const js_t *action, const char *field)
{
    const char *type = js_str(js_get(action, "type"), ""), *svc = js_str(js_get(action, "service"), "");
    for (size_t i = 0; i < sizeof(secrets) / sizeof(secrets[0]); i++)
        if (strcmp(secrets[i].type, type) == 0 && (!secrets[i].service || strcmp(secrets[i].service, svc) == 0)
            && strcmp(secrets[i].field, field) == 0)
            return 1;
    return 0;
}

js_t *rules_masked(const js_t *doc)
{
    js_t *out = js_copy(doc);
    js_t *list = js_get(out, "rules");
    for (int r = 0; r < js_len(list); r++) {
        js_t *act = js_get(js_at(list, r), "do");
        for (int a = 0; a < js_len(act); a++) {
            js_t *one = js_at(act, a);
            for (int k = 0; k < js_len(one); k++)
                if (is_secret(one, one->keys[k]) && js_str(one->kids[k], "")[0])
                    js_set(one, one->keys[k], js_string(RULES_KEPT));
        }
    }
    return out;
}

int rules_keep_secrets(js_t *rule, const js_t *saved_doc, char *err, size_t elen)
{
    const char *id = js_str(js_get(rule, "id"), "");
    const js_t *old = NULL;
    js_t *list = js_get(saved_doc, "rules");
    for (int i = 0; i < js_len(list); i++)
        if (strcmp(js_str(js_get(js_at(list, i), "id"), ""), id) == 0)
            old = js_at(list, i);
    js_t *act = js_get(rule, "do");
    for (int a = 0; a < js_len(act); a++) {
        js_t *one = js_at(act, a);
        for (int k = 0; k < js_len(one); k++) {
            if (!js_is(one->kids[k], JS_STR) || strcmp(one->kids[k]->s, RULES_KEPT) != 0)
                continue;
            js_t *was = js_at(js_get(old, "do"), a);
            const char *v = js_str(js_get(was, one->keys[k]), NULL);
            if (!is_secret(one, one->keys[k]) || !was
                || strcmp(js_str(js_get(was, "type"), ""), js_str(js_get(one, "type"), "")) != 0
                || strcmp(js_str(js_get(was, "service"), ""), js_str(js_get(one, "service"), "")) != 0 || !v
                || !v[0])
                return fail(err, elen, "rule %s, action %d: its %s is to be kept, and there is none to keep: type it again",
                            id, a + 1, one->keys[k]);
            if (js_set(one, one->keys[k], js_string(v)) != 0)
                return fail(err, elen, "out of memory");
        }
    }
    return 0;
}

static int same(const js_t *want, const js_t *have)
{
    if (!have)
        return 0;
    if (js_is(want, JS_STR))
        return js_is(have, JS_STR) && strcmp(want->s, have->s) == 0;
    if (js_is(want, JS_NUM))
        return js_is(have, JS_NUM) && want->n == have->n;
    if (js_is(want, JS_BOOL))
        return js_is(have, JS_BOOL) && want->b == have->b;
    return 0;
}

int rules_match(const js_t *rule, const char *event, const js_t *data)
{
    if (!js_bool(js_get(rule, "enabled"), 1) || !event)
        return 0;
    js_t *on = js_get(rule, "on");
    int hit = 0;
    for (int i = 0; i < js_len(on) && !hit; i++) {
        const char *e = js_str(js_at(on, i), "");
        hit = strcmp(e, "*") == 0 || strcmp(e, event) == 0;
    }
    if (!hit)
        return 0;
    js_t *cond = js_get(rule, "if");
    for (int i = 0; i < js_len(cond); i++)
        if (!same(cond->kids[i], js_get(data, cond->keys[i])))
            return 0;
    return 1;
}

static int addc(char *out, size_t *n, size_t cap, const char *s, size_t len, int json)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        char esc[8];
        const char *e = NULL;
        if (json && (c == '"' || c == '\\'))
            snprintf(esc, sizeof(esc), "\\%c", c), e = esc;
        else if (json && c < 0x20)
            snprintf(esc, sizeof(esc), "\\u%04x", c), e = esc;
        size_t k = e ? strlen(e) : 1;
        if (*n + k >= cap)
            return -1;
        memcpy(out + *n, e ? e : (const char *)&s[i], k);
        *n += k;
    }
    return 0;
}

char *rules_expand(const char *tmpl, const char *event, const js_t *data, int json)
{
    size_t cap = RULE_TEXT_MAX * 4 + 1, n = 0;
    char *out = malloc(cap);
    if (!out)
        return NULL;
    for (const char *p = tmpl ? tmpl : ""; *p;) {
        const char *close = *p == '{' ? strchr(p, '}') : NULL;
        if (close && close - p <= 40) {
            char name[48];
            memcpy(name, p + 1, (size_t)(close - p - 1));
            name[close - p - 1] = '\0';
            const char *val = NULL;
            char num[40];
            if (strcmp(name, "event") == 0) {
                val = event ? event : "";
            } else if (strncmp(name, "data.", 5) == 0) {
                js_t *v = js_get(data, name + 5);
                if (js_is(v, JS_STR))
                    val = v->s;
                else if (js_is(v, JS_NUM))
                    snprintf(num, sizeof(num), "%g", v->n), val = num;
                else if (js_is(v, JS_BOOL))
                    val = v->b ? "true" : "false";
                else
                    val = "";
            } else if (strcmp(name, "data") == 0) {
                /* the whole of it, as a JSON value: never escaped */
                char *d = js_dump(data);
                int rc = addc(out, &n, cap, d ? d : "{}", strlen(d ? d : "{}"), 0);
                free(d);
                if (rc != 0)
                    break;
                p = close + 1;
                continue;
            }
            if (val) {
                if (addc(out, &n, cap, val, strlen(val), json) != 0)
                    break;
                p = close + 1;
                continue;
            }
        }
        if (addc(out, &n, cap, p, 1, 0) != 0)
            break;
        p++;
    }
    out[n] = '\0';
    return out;
}

js_t *rules_load(const char *path, char *err, size_t elen)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno != ENOENT) {
            fail(err, elen, "the rules cannot be read: %s", strerror(errno));
            return NULL;
        }
        js_t *doc = js_object();
        if (doc && js_set(doc, "rules", js_array()) != 0) {
            js_free(doc);
            doc = NULL;
        }
        return doc;
    }
    static char buf[RULES_FILE_MAX + 1];
    size_t len = 0;
    ssize_t k;
    while (len < RULES_FILE_MAX && (k = read(fd, buf + len, RULES_FILE_MAX - len)) > 0)
        len += (size_t)k;
    close(fd);
    char why[200];
    js_t *doc = js_parse(buf, len, why, sizeof(why));
    if (!doc) {
        fail(err, elen, "the rules file is not JSON: %s", why);
        return NULL;
    }
    if (rules_check(doc, why, sizeof(why)) != 0) {
        js_free(doc);
        fail(err, elen, "the rules file does not hold: %s", why);
        return NULL;
    }
    return doc;
}

int rules_save(const char *path, const js_t *doc, char *err, size_t elen)
{
    char tmp[600];
    char *text = js_dump(doc);
    if (!text)
        return fail(err, elen, "out of memory");
    size_t len = strlen(text);
    if (len > RULES_FILE_MAX) {
        free(text);
        return fail(err, elen, "the rules would be more than %d bytes", RULES_FILE_MAX);
    }
    snprintf(tmp, sizeof(tmp), "%.580s.new", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    int ok = fd >= 0 && write(fd, text, len) == (ssize_t)len && fsync(fd) == 0;
    if (fd >= 0)
        close(fd);
    free(text);
    if (!ok || rename(tmp, path) != 0) {
        int e = errno;
        unlink(tmp);
        return fail(err, elen, "the rules cannot be written: %s", strerror(e));
    }
    return 0;
}
