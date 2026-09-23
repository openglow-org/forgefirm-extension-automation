/*
 * js.c - the automation service's JSON
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * See js.h.
 */
#include "js.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *p, *end;
    int nodes;
    char *err;
    size_t elen;
    int failed;
} parser_t;

static js_t *fail(parser_t *ps, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static js_t *fail(parser_t *ps, const char *fmt, ...)
{
    if (!ps->failed && ps->err && ps->elen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(ps->err, ps->elen, fmt, ap);
        va_end(ap);
    }
    ps->failed = 1;
    return NULL;
}

static js_t *node(parser_t *ps, js_type_t t)
{
    if (ps && ++ps->nodes > JS_MAX_NODES)
        return fail(ps, "more than %d values", JS_MAX_NODES);
    js_t *v = calloc(1, sizeof(*v));
    if (!v && ps)
        return fail(ps, "out of memory");
    if (v)
        v->type = t;
    return v;
}

static void ws(parser_t *ps)
{
    while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r'))
        ps->p++;
}

static int grow(js_t *v)
{
    if (v->count < v->cap)
        return 0;
    int cap = v->cap ? v->cap * 2 : 4;
    js_t **k = realloc(v->kids, sizeof(*k) * (size_t)cap);
    if (!k)
        return -1;
    v->kids = k;
    if (v->type == JS_OBJ) {
        char **n = realloc(v->keys, sizeof(*n) * (size_t)cap);
        if (!n)
            return -1;
        v->keys = n;
    }
    v->cap = cap;
    return 0;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int hex4(parser_t *ps, unsigned *out)
{
    if (ps->end - ps->p < 4)
        return -1;
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        int h = hexval(ps->p[i]);
        if (h < 0)
            return -1;
        v = v * 16 + (unsigned)h;
    }
    ps->p += 4;
    *out = v;
    return 0;
}

static int put_utf8(char *buf, size_t *n, unsigned cp)
{
    if (cp == 0)
        return -1;                                  /* a NUL in a string is refused */
    if (cp < 0x80) {
        buf[(*n)++] = (char)cp;
    } else if (cp < 0x800) {
        buf[(*n)++] = (char)(0xc0 | (cp >> 6));
        buf[(*n)++] = (char)(0x80 | (cp & 0x3f));
    } else if (cp < 0x10000) {
        buf[(*n)++] = (char)(0xe0 | (cp >> 12));
        buf[(*n)++] = (char)(0x80 | ((cp >> 6) & 0x3f));
        buf[(*n)++] = (char)(0x80 | (cp & 0x3f));
    } else {
        buf[(*n)++] = (char)(0xf0 | (cp >> 18));
        buf[(*n)++] = (char)(0x80 | ((cp >> 12) & 0x3f));
        buf[(*n)++] = (char)(0x80 | ((cp >> 6) & 0x3f));
        buf[(*n)++] = (char)(0x80 | (cp & 0x3f));
    }
    return 0;
}

/* A string at ps->p (on its opening quote): malloc'd text, or NULL. */
static char *string(parser_t *ps)
{
    ps->p++;
    char *buf = malloc(JS_MAX_STRING + 8);
    size_t n = 0;
    if (!buf) {
        fail(ps, "out of memory");
        return NULL;
    }
    while (ps->p < ps->end && *ps->p != '"') {
        if (n >= JS_MAX_STRING) {
            free(buf);
            fail(ps, "a string longer than %d bytes", JS_MAX_STRING);
            return NULL;
        }
        unsigned char c = (unsigned char)*ps->p++;
        if (c < 0x20) {
            free(buf);
            fail(ps, "a control character inside a string");
            return NULL;
        }
        if (c != '\\') {
            buf[n++] = (char)c;
            continue;
        }
        if (ps->p >= ps->end)
            break;
        char e = *ps->p++;
        unsigned cp;
        switch (e) {
        case '"': buf[n++] = '"'; break;
        case '\\': buf[n++] = '\\'; break;
        case '/': buf[n++] = '/'; break;
        case 'b': buf[n++] = '\b'; break;
        case 'f': buf[n++] = '\f'; break;
        case 'n': buf[n++] = '\n'; break;
        case 'r': buf[n++] = '\r'; break;
        case 't': buf[n++] = '\t'; break;
        case 'u':
            if (hex4(ps, &cp) != 0)
                goto bad;
            if (cp >= 0xd800 && cp < 0xdc00) {
                unsigned lo;
                if (ps->end - ps->p < 6 || ps->p[0] != '\\' || ps->p[1] != 'u')
                    goto bad;
                ps->p += 2;
                if (hex4(ps, &lo) != 0 || lo < 0xdc00 || lo >= 0xe000)
                    goto bad;
                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
            } else if (cp >= 0xdc00 && cp < 0xe000) {
                goto bad;
            }
            if (put_utf8(buf, &n, cp) != 0)
                goto bad;
            break;
        default:
            goto bad;
        }
    }
    if (ps->p >= ps->end) {
        free(buf);
        fail(ps, "a string that does not end");
        return NULL;
    }
    ps->p++;
    buf[n] = '\0';
    return buf;
bad:
    free(buf);
    fail(ps, "an escape that is not JSON");
    return NULL;
}

static js_t *value(parser_t *ps, int depth);

static js_t *container(parser_t *ps, int depth, int obj)
{
    js_t *v = node(ps, obj ? JS_OBJ : JS_ARR);
    if (!v)
        return NULL;
    ps->p++;
    ws(ps);
    if (ps->p < ps->end && *ps->p == (obj ? '}' : ']')) {
        ps->p++;
        return v;
    }
    for (;;) {
        char *key = NULL;
        ws(ps);
        if (obj) {
            if (ps->p >= ps->end || *ps->p != '"') {
                js_free(v);
                return fail(ps, "an object's key is a string");
            }
            if (!(key = string(ps))) {
                js_free(v);
                return NULL;
            }
            if (js_get(v, key)) {
                free(key);
                js_free(v);
                return fail(ps, "a key given twice in one object");
            }
            ws(ps);
            if (ps->p >= ps->end || *ps->p != ':') {
                free(key);
                js_free(v);
                return fail(ps, "a key with no value");
            }
            ps->p++;
        }
        js_t *item = value(ps, depth + 1);
        if (!item || grow(v) != 0) {
            free(key);
            js_free(item);
            js_free(v);
            return item ? fail(ps, "out of memory") : NULL;
        }
        if (obj)
            v->keys[v->count] = key;
        v->kids[v->count++] = item;
        ws(ps);
        if (ps->p < ps->end && *ps->p == ',') {
            ps->p++;
            continue;
        }
        if (ps->p < ps->end && *ps->p == (obj ? '}' : ']')) {
            ps->p++;
            return v;
        }
        js_free(v);
        return fail(ps, obj ? "an object that does not end" : "an array that does not end");
    }
}

static js_t *value(parser_t *ps, int depth)
{
    if (depth > JS_MAX_DEPTH)
        return fail(ps, "nested deeper than %d", JS_MAX_DEPTH);
    ws(ps);
    if (ps->p >= ps->end)
        return fail(ps, "no value");
    char c = *ps->p;
    if (c == '{' || c == '[')
        return container(ps, depth, c == '{');
    if (c == '"') {
        js_t *v = node(ps, JS_STR);
        if (v && !(v->s = string(ps))) {
            free(v);
            return NULL;
        }
        return v;
    }
    static const struct { const char *word; js_type_t t; int b; } words[] = {
        { "true", JS_BOOL, 1 }, { "false", JS_BOOL, 0 }, { "null", JS_NULL, 0 },
    };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
        size_t n = strlen(words[i].word);
        if ((size_t)(ps->end - ps->p) >= n && memcmp(ps->p, words[i].word, n) == 0) {
            ps->p += n;
            js_t *v = node(ps, words[i].t);
            if (v)
                v->b = words[i].b;
            return v;
        }
    }
    /* A number, in JSON's form and no other: no leading zero, no bare
     * point, no NaN or infinity. */
    const char *s = ps->p;
    if (s < ps->end && *s == '-')
        s++;
    if (s >= ps->end || *s < '0' || *s > '9')
        return fail(ps, "a value that is not JSON");
    if (*s == '0')
        s++;
    else
        while (s < ps->end && *s >= '0' && *s <= '9')
            s++;
    if (s < ps->end && *s == '.') {
        s++;
        if (s >= ps->end || *s < '0' || *s > '9')
            return fail(ps, "a number that is not JSON");
        while (s < ps->end && *s >= '0' && *s <= '9')
            s++;
    }
    if (s < ps->end && (*s == 'e' || *s == 'E')) {
        s++;
        if (s < ps->end && (*s == '+' || *s == '-'))
            s++;
        if (s >= ps->end || *s < '0' || *s > '9')
            return fail(ps, "a number that is not JSON");
        while (s < ps->end && *s >= '0' && *s <= '9')
            s++;
    }
    char num[64];
    size_t n = (size_t)(s - ps->p);
    if (n >= sizeof(num))
        return fail(ps, "a number too long");
    memcpy(num, ps->p, n);
    num[n] = '\0';
    ps->p = s;
    js_t *v = node(ps, JS_NUM);
    if (v) {
        v->n = strtod(num, NULL);
        if (!isfinite(v->n)) {
            free(v);
            return fail(ps, "a number out of range");
        }
    }
    return v;
}

js_t *js_parse(const char *text, size_t len, char *err, size_t elen)
{
    parser_t ps = { text, text + len, 0, err, elen, 0 };
    if (!text)
        return fail(&ps, "no text");
    js_t *v = value(&ps, 0);
    if (!v)
        return NULL;
    ws(&ps);
    if (ps.p != ps.end) {
        js_free(v);
        return fail(&ps, "text after the value");
    }
    return v;
}

void js_free(js_t *v)
{
    if (!v)
        return;
    for (int i = 0; i < v->count; i++) {
        js_free(v->kids[i]);
        if (v->keys)
            free(v->keys[i]);
    }
    free(v->kids);
    free(v->keys);
    free(v->s);
    free(v);
}

js_t *js_get(const js_t *obj, const char *key)
{
    if (!obj || obj->type != JS_OBJ || !key)
        return NULL;
    for (int i = 0; i < obj->count; i++)
        if (strcmp(obj->keys[i], key) == 0)
            return obj->kids[i];
    return NULL;
}

js_t *js_at(const js_t *arr, int i)
{
    if (!arr || (arr->type != JS_ARR && arr->type != JS_OBJ) || i < 0 || i >= arr->count)
        return NULL;
    return arr->kids[i];
}

int js_len(const js_t *v)
{
    return v && (v->type == JS_ARR || v->type == JS_OBJ) ? v->count : 0;
}

const char *js_str(const js_t *v, const char *dflt)
{
    return v && v->type == JS_STR ? v->s : dflt;
}

double js_num(const js_t *v, double dflt)
{
    return v && v->type == JS_NUM ? v->n : dflt;
}

int js_bool(const js_t *v, int dflt)
{
    return v && v->type == JS_BOOL ? v->b : dflt;
}

int js_is(const js_t *v, js_type_t t)
{
    return v && v->type == t;
}

js_t *js_null(void)
{
    return node(NULL, JS_NULL);
}

js_t *js_boolean(int b)
{
    js_t *v = node(NULL, JS_BOOL);
    if (v)
        v->b = b ? 1 : 0;
    return v;
}

js_t *js_number(double n)
{
    js_t *v = node(NULL, JS_NUM);
    if (v)
        v->n = isfinite(n) ? n : 0;
    return v;
}

js_t *js_string(const char *s)
{
    js_t *v = node(NULL, JS_STR);
    if (v && !(v->s = strdup(s ? s : ""))) {
        free(v);
        return NULL;
    }
    return v;
}

js_t *js_array(void)
{
    return node(NULL, JS_ARR);
}

js_t *js_object(void)
{
    return node(NULL, JS_OBJ);
}

int js_push(js_t *arr, js_t *v)
{
    if (!v)
        v = js_null();
    if (!arr || arr->type != JS_ARR || !v || grow(arr) != 0) {
        js_free(v);
        return -1;
    }
    arr->kids[arr->count++] = v;
    return 0;
}

int js_set(js_t *obj, const char *key, js_t *v)
{
    if (!v)
        v = js_null();
    if (!obj || obj->type != JS_OBJ || !key || !v) {
        js_free(v);
        return -1;
    }
    for (int i = 0; i < obj->count; i++)
        if (strcmp(obj->keys[i], key) == 0) {
            js_free(obj->kids[i]);
            obj->kids[i] = v;
            return 0;
        }
    char *k = strdup(key);
    if (!k || grow(obj) != 0) {
        free(k);
        js_free(v);
        return -1;
    }
    obj->keys[obj->count] = k;
    obj->kids[obj->count++] = v;
    return 0;
}

js_t *js_copy(const js_t *v)
{
    if (!v)
        return NULL;
    switch (v->type) {
    case JS_NULL: return js_null();
    case JS_BOOL: return js_boolean(v->b);
    case JS_NUM: return js_number(v->n);
    case JS_STR: return js_string(v->s);
    default: break;
    }
    js_t *c = v->type == JS_OBJ ? js_object() : js_array();
    for (int i = 0; c && i < v->count; i++) {
        js_t *k = js_copy(v->kids[i]);
        if ((v->type == JS_OBJ ? js_set(c, v->keys[i], k) : js_push(c, k)) != 0) {
            js_free(c);
            return NULL;
        }
    }
    return c;
}

static int add(char **buf, size_t *len, size_t *cap, const char *s, size_t n)
{
    if (*len + n + 1 > *cap) {
        size_t c = *cap ? *cap : 256;
        while (c < *len + n + 1)
            c *= 2;
        char *b = realloc(*buf, c);
        if (!b)
            return -1;
        *buf = b;
        *cap = c;
    }
    memcpy(*buf + *len, s, n);
    *len += n;
    (*buf)[*len] = '\0';
    return 0;
}

int js_quote(char **buf, size_t *len, size_t *cap, const char *s)
{
    if (add(buf, len, cap, "\"", 1) != 0)
        return -1;
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
        char esc[8];
        const char *e = NULL;
        switch (*p) {
        case '"': e = "\\\""; break;
        case '\\': e = "\\\\"; break;
        case '\n': e = "\\n"; break;
        case '\r': e = "\\r"; break;
        case '\t': e = "\\t"; break;
        default:
            if (*p < 0x20) {
                snprintf(esc, sizeof(esc), "\\u%04x", *p);
                e = esc;
            }
        }
        if (e ? add(buf, len, cap, e, strlen(e)) : add(buf, len, cap, (const char *)p, 1))
            return -1;
    }
    return add(buf, len, cap, "\"", 1);
}

static int dump(const js_t *v, char **buf, size_t *len, size_t *cap)
{
    char num[40];
    switch (v ? v->type : JS_NULL) {
    case JS_NULL: return add(buf, len, cap, "null", 4);
    case JS_BOOL: return v->b ? add(buf, len, cap, "true", 4) : add(buf, len, cap, "false", 5);
    case JS_NUM:
        if (v->n == floor(v->n) && fabs(v->n) < 1e15)
            snprintf(num, sizeof(num), "%.0f", v->n);
        else
            snprintf(num, sizeof(num), "%.17g", v->n);
        return add(buf, len, cap, num, strlen(num));
    case JS_STR: return js_quote(buf, len, cap, v->s);
    case JS_ARR:
    case JS_OBJ:
        if (add(buf, len, cap, v->type == JS_OBJ ? "{" : "[", 1) != 0)
            return -1;
        for (int i = 0; i < v->count; i++) {
            if (i && add(buf, len, cap, ",", 1) != 0)
                return -1;
            if (v->type == JS_OBJ && (js_quote(buf, len, cap, v->keys[i]) != 0 || add(buf, len, cap, ":", 1) != 0))
                return -1;
            if (dump(v->kids[i], buf, len, cap) != 0)
                return -1;
        }
        return add(buf, len, cap, v->type == JS_OBJ ? "}" : "]", 1);
    }
    return -1;
}

char *js_dump(const js_t *v)
{
    char *buf = NULL;
    size_t len = 0, cap = 0;
    if (dump(v, &buf, &len, &cap) != 0) {
        free(buf);
        return NULL;
    }
    return buf;
}
