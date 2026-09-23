/*
 * js.h - the automation service's JSON: a bounded parser, a tree, a writer
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * The service links against the C library alone, so it carries its own
 * JSON. What it reads is the host's answers, the page's calls, and its own
 * rules file, and every one of them is held to limits here: a depth, a
 * node count, and a string length, past which the text is refused rather
 * than half read. A key given twice in one object is refused too.
 */
#ifndef AUTOMATION_JS_H
#define AUTOMATION_JS_H

#include <stddef.h>

#define JS_MAX_DEPTH  24
#define JS_MAX_NODES  8192
#define JS_MAX_STRING (16 * 1024)

typedef enum { JS_NULL, JS_BOOL, JS_NUM, JS_STR, JS_ARR, JS_OBJ } js_type_t;

typedef struct js js_t;
struct js {
    js_type_t type;
    int b;                  /* JS_BOOL */
    double n;               /* JS_NUM */
    char *s;                /* JS_STR, NUL-ended (a string holding a NUL is refused) */
    js_t **kids;            /* JS_ARR, JS_OBJ */
    char **keys;            /* JS_OBJ */
    int count, cap;
};

/* The tree of text[0..len), or NULL with the words. */
js_t *js_parse(const char *text, size_t len, char *err, size_t elen);
void js_free(js_t *v);

/* Reading. Each is safe on NULL and on a value of another type. */
js_t *js_get(const js_t *obj, const char *key);
js_t *js_at(const js_t *arr, int i);
int js_len(const js_t *v);                                  /* items or members; 0 otherwise */
const char *js_str(const js_t *v, const char *dflt);
double js_num(const js_t *v, double dflt);
int js_bool(const js_t *v, int dflt);
int js_is(const js_t *v, js_type_t t);

/* Building. A NULL value handed in is a JS_NULL; set replaces a key. */
js_t *js_null(void);
js_t *js_boolean(int b);
js_t *js_number(double n);
js_t *js_string(const char *s);
js_t *js_array(void);
js_t *js_object(void);
int js_push(js_t *arr, js_t *v);                            /* 0, or -1 (and v is freed) */
int js_set(js_t *obj, const char *key, js_t *v);            /* 0, or -1 (and v is freed) */
js_t *js_copy(const js_t *v);

/* Compact text, malloc'd; NULL when out of memory. */
char *js_dump(const js_t *v);

/* s as a JSON string, quotes included, appended to a growing buffer. */
int js_quote(char **buf, size_t *len, size_t *cap, const char *s);

#endif
