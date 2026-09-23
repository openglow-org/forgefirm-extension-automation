/*
 * js_test.c - host test: the automation service's JSON
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * What it reads is the host's answers, the page's calls, and its own file:
 * JSON's own form, and nothing past its limits.
 */
#include "js.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

static js_t *parse(const char *t, char *err)
{
    return js_parse(t, strlen(t), err, 200);
}

int main(void)
{
    char err[200];
    js_t *v = parse(" {\"a\": [1, -2.5e2, true, false, null, \"x\\u00e9\\ud83d\\ude00\\n\"], \"b\": {}} ", err);
    CHECK(v && js_len(v) == 2 && js_len(js_get(v, "a")) == 6, "a document: %s", v ? "" : err);
    CHECK(js_num(js_at(js_get(v, "a"), 1), 0) == -250 && js_bool(js_at(js_get(v, "a"), 2), 0) == 1
          && js_is(js_at(js_get(v, "a"), 4), JS_NULL), "its values");
    CHECK(strcmp(js_str(js_at(js_get(v, "a"), 5), ""), "x\xc3\xa9\xf0\x9f\x98\x80\n") == 0, "escapes to UTF-8, a pair included");
    char *d = js_dump(v);
    CHECK(d && strcmp(d, "{\"a\":[1,-250,true,false,null,\"x\xc3\xa9\xf0\x9f\x98\x80\\n\"],\"b\":{}}") == 0, "written again: %s", d ? d : "(none)");
    js_t *back = d ? parse(d, err) : NULL;
    char *d2 = back ? js_dump(back) : NULL;
    CHECK(d2 && strcmp(d, d2) == 0, "and read back the same");
    free(d);
    free(d2);
    js_free(back);
    js_free(v);

    static const char *const bad[] = {
        "", "{", "[1,]", "{\"a\":1,}", "{\"a\" 1}", "{a:1}", "01", "1.", ".5", "-", "1e", "NaN", "Infinity", "tru",
        "\"a", "\"\\x\"", "\"\\u12\"", "\"\\ud800\"", "\"\\udc00\"", "\"\\u0000\"", "\"a\tb\"", "{\"a\":1,\"a\":2}",
        "[1] 2", "1e999",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        v = parse(bad[i], err);
        CHECK(!v && err[0], "taken: %s", bad[i]);
        js_free(v);
    }

    /* the limits */
    char deep[200];
    memset(deep, '[', 30);
    memset(deep + 30, ']', 30);
    deep[60] = '\0';
    v = parse(deep, err);
    CHECK(!v && strstr(err, "nested deeper"), "30 deep: %s", err);
    js_free(v);
    size_t n = JS_MAX_STRING + 10;
    char *big = malloc(n + 3);
    big[0] = '"';
    memset(big + 1, 'a', n);
    big[n + 1] = '"';
    big[n + 2] = '\0';
    v = parse(big, err);
    CHECK(!v && strstr(err, "longer than"), "a long string: %s", err);
    js_free(v);
    free(big);
    char *many = malloc(JS_MAX_NODES * 2 + 10);
    size_t k = 0;
    many[k++] = '[';
    for (int i = 0; i < JS_MAX_NODES + 1; i++) {
        many[k++] = '1';
        many[k++] = ',';
    }
    many[k - 1] = ']';
    many[k] = '\0';
    v = parse(many, err);
    CHECK(!v && strstr(err, "more than"), "too many values: %s", err);
    js_free(v);
    free(many);

    /* building */
    js_t *o = js_object();
    CHECK(js_set(o, "k", js_string("a \"q\" \\ \x01")) == 0 && js_set(o, "n", js_number(3)) == 0 &&
          js_set(o, "k", js_string("again")) == 0 && js_len(o) == 2, "set, and set again");
    d = js_dump(o);
    CHECK(d && strcmp(d, "{\"k\":\"again\",\"n\":3}") == 0, "replaced in place: %s", d ? d : "(none)");
    free(d);
    js_set(o, "k", js_string("a \"q\" \\ \x01"));
    d = js_dump(o);
    CHECK(d && strcmp(d, "{\"k\":\"a \\\"q\\\" \\\\ \\u0001\",\"n\":3}") == 0, "quoted: %s", d ? d : "(none)");
    free(d);
    js_t *c = js_copy(o);
    CHECK(c && js_len(c) == 2 && strcmp(js_str(js_get(c, "k"), ""), js_str(js_get(o, "k"), "")) == 0, "a copy");
    js_free(c);
    js_free(o);
    CHECK(js_str(NULL, "d")[0] == 'd' && js_num(NULL, 7) == 7 && js_len(NULL) == 0 && !js_get(NULL, "x"), "NULL is safe");

    printf("%s: js_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
