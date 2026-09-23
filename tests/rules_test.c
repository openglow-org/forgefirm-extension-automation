/*
 * rules_test.c - host test: the automation package's rules
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * Their form, each refusal in its words, the secrets the page is never
 * shown and a saved rule keeps, what an event matches, the text put into
 * a message, the file written whole, and the destination of a URL.
 */
#include "rules.h"
#include "web.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

static js_t *j(const char *t)
{
    char err[200];
    js_t *v = js_parse(t, strlen(t), err, sizeof(err));
    if (!v)
        printf("FAIL: the test's own JSON: %s: %s\n", err, t), fails++;
    return v;
}

static const char *refusal(const char *rule)
{
    static char err[300];
    js_t *r = j(rule);
    err[0] = '\0';
    int rc = r ? rules_check_rule(r, err, sizeof(err)) : 0;
    js_free(r);
    return rc == 0 ? NULL : err;
}

#define GOOD_NTFY "{\"type\":\"notify\",\"service\":\"ntfy\",\"topic\":\"my-laser\",\"message\":\"done\"}"
#define RULE(on, act) "{\"id\":\"r1\",\"on\":" on ",\"do\":[" act "]}"

int main(void)
{
    char err[300];
    static const char *const good[] = {
        RULE("[\"job.ended\"]", GOOD_NTFY),
        "{\"id\":\"exhaust\",\"name\":\"Exhaust\",\"enabled\":true,\"on\":[\"job.arming\"],\"if\":{\"result\":\"ended\"},\"do\":["
        "{\"type\":\"http\",\"method\":\"POST\",\"url\":\"http://plug.lan/relay/0?turn=on\",\"body\":\"{}\","
        "\"content_type\":\"application/json\",\"auth\":\"Bearer x\"},"
        "{\"type\":\"http\",\"url\":\"http://plug.lan/relay/0?turn=off\",\"after_s\":120,\"cancel_on\":[\"job.arming\"]},"
        "{\"type\":\"hold_until\",\"url\":\"http://plug.lan/status\",\"match\":\"\\\"ison\\\":true\",\"timeout_s\":30},"
        "{\"type\":\"clear_hold\"}]}",
        RULE("[\"*\"]", "{\"type\":\"mqtt\",\"broker\":\"broker.lan:1883\",\"topic\":\"forgefirm/{event}\",\"retain\":true}"),
        RULE("[\"alarm\"]", "{\"type\":\"notify\",\"service\":\"pushover\",\"token\":\"t\",\"user\":\"u\",\"message\":\"{data.code}\","
                            "\"priority\":1}"),
        RULE("[\"alarm\"]", "{\"type\":\"notify\",\"service\":\"telegram\",\"token\":\"123:ABC_d-e\",\"chat_id\":\"42\",\"message\":\"m\"}"),
        RULE("[\"alarm\"]", "{\"type\":\"notify\",\"service\":\"discord\",\"url\":\"https://discord.com/api/webhooks/1/x\",\"message\":\"m\"}"),
        RULE("[\"alarm\"]", "{\"type\":\"notify\",\"service\":\"webhook\",\"url\":\"https://hooks.example.org/x\",\"message\":\"m\","
                            "\"title\":\"t\"}"),
    };
    for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++)
        CHECK(!refusal(good[i]), "refused: %s -> %s", good[i], refusal(good[i]));

    static const struct { const char *rule, *words; } bad[] = {
        { "[]", "a rule is an object" },
        { "{\"id\":\"R1\",\"on\":[\"x\"],\"do\":[" GOOD_NTFY "]}", "lowercase letters" },
        { "{\"id\":\"r1\",\"on\":[],\"do\":[" GOOD_NTFY "]}", "on is a list of 1 to" },
        { "{\"id\":\"r1\",\"on\":[\"Job\"],\"do\":[" GOOD_NTFY "]}", "on names an event" },
        { "{\"id\":\"r1\",\"on\":[\"x\"],\"do\":[]}", "do is a list of 1 to" },
        { "{\"id\":\"r1\",\"on\":[\"x\"],\"do\":[" GOOD_NTFY "],\"then\":1}", "has no field \"then\"" },
        { "{\"id\":\"r1\",\"on\":[\"x\"],\"if\":{\"a\":[1]},\"do\":[" GOOD_NTFY "]}", "if compares" },
        { RULE("[\"x\"]", "{\"type\":\"shell\"}"), "type is notify" },
        { RULE("[\"x\"]", "{\"type\":\"notify\",\"service\":\"email\",\"message\":\"m\"}"), "service is ntfy" },
        { RULE("[\"x\"]", "{\"type\":\"notify\",\"service\":\"ntfy\",\"message\":\"m\"}"), "needs topic" },
        { RULE("[\"x\"]", "{\"type\":\"notify\",\"service\":\"ntfy\",\"topic\":\"a/b\",\"message\":\"m\"}"), "topic is letters" },
        { RULE("[\"x\"]", "{\"type\":\"notify\",\"service\":\"ntfy\",\"topic\":\"t\",\"message\":\"\"}"), "needs message" },
        { RULE("[\"x\"]", "{\"type\":\"notify\",\"service\":\"ntfy\",\"topic\":\"t\",\"message\":\"m\",\"server\":\"file:///etc\"}"),
          "http:// or https://" },
        { RULE("[\"x\"]", "{\"type\":\"notify\",\"service\":\"ntfy\",\"topic\":\"t\",\"message\":\"m\",\"priority\":9}"),
          "priority is a whole number" },
        { RULE("[\"x\"]", "{\"type\":\"notify\",\"service\":\"telegram\",\"token\":\"a b\",\"chat_id\":\"1\",\"message\":\"m\"}"),
          "Telegram bot's token" },
        { RULE("[\"x\"]", "{\"type\":\"http\",\"url\":\"http://user:pw@plug.lan/\"}"), "no user or password" },
        { RULE("[\"x\"]", "{\"type\":\"http\",\"url\":\"http://plug.lan/\",\"method\":\"DELETE\"}"), "method is GET" },
        { RULE("[\"x\"]", "{\"type\":\"http\",\"url\":\"http://plug.lan/ x\"}"), "http:// or https://" },
        { RULE("[\"x\"]", "{\"type\":\"http\",\"url\":\"http://plug.lan/\",\"auth\":\"a\\nb\"}"), "control character" },
        { RULE("[\"x\"]", "{\"type\":\"http\",\"url\":\"http://plug.lan/\",\"after_s\":4000}"), "after_s is a whole number" },
        { RULE("[\"x\"]", "{\"type\":\"http\",\"url\":\"http://plug.lan/\",\"cancel_on\":\"x\"}"), "cancel_on is a list" },
        { RULE("[\"x\"]", "{\"type\":\"mqtt\",\"broker\":\"broker.lan\",\"topic\":\"t\"}"), "broker is host:port" },
        { RULE("[\"x\"]", "{\"type\":\"mqtt\",\"broker\":\"broker.lan:1883\",\"topic\":\"a/#\"}"), "no wildcard" },
        { RULE("[\"x\"]", "{\"type\":\"hold_until\",\"url\":\"http://plug.lan/\",\"match\":\"on\",\"timeout_s\":1}"),
          "timeout_s is a whole number" },
        { RULE("[\"x\"]", "{\"type\":\"hold_until\",\"url\":\"http://plug.lan/\",\"match\":\"on\",\"reason\":\"a\\\"b\"}"),
          "printable ASCII" },
        { RULE("[\"x\"]", "{\"type\":\"clear_hold\",\"url\":\"x\"}"), "has no field \"url\"" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        const char *why = refusal(bad[i].rule);
        CHECK(why && strstr(why, bad[i].words), "%s -> %s, wanted \"%s\"", bad[i].rule, why ? why : "taken", bad[i].words);
    }

    /* the file's form: ids unique, a bound on how many */
    js_t *doc = j("{\"rules\":[" RULE("[\"x\"]", GOOD_NTFY) "," RULE("[\"y\"]", GOOD_NTFY) "]}");
    CHECK(rules_check(doc, err, sizeof(err)) != 0 && strstr(err, "two rules are named r1"), "the same id twice: %s", err);
    js_free(doc);

    /* secrets: never shown, and kept */
    js_t *saved = j("{\"rules\":[{\"id\":\"p\",\"on\":[\"alarm\"],\"do\":["
                    "{\"type\":\"notify\",\"service\":\"pushover\",\"token\":\"TOKEN1\",\"user\":\"USER1\",\"message\":\"m\"},"
                    "{\"type\":\"mqtt\",\"broker\":\"b.lan:1883\",\"topic\":\"t\",\"username\":\"u\",\"password\":\"\"}]}]}");
    js_t *masked = rules_masked(saved);
    char *shown = js_dump(masked);
    CHECK(shown && !strstr(shown, "TOKEN1") && !strstr(shown, "USER1") && strstr(shown, RULES_KEPT)
          && strstr(shown, "\"password\":\"\""), "the page is not shown a secret, and an empty one stays empty: %s", shown ? shown : "(none)");
    free(shown);
    js_t *edited = js_copy(js_at(js_get(masked, "rules"), 0));
    js_set(js_at(js_get(edited, "do"), 0), "message", js_string("changed"));
    CHECK(rules_keep_secrets(edited, saved, err, sizeof(err)) == 0
          && strcmp(js_str(js_get(js_at(js_get(edited, "do"), 0), "token"), ""), "TOKEN1") == 0
          && strcmp(js_str(js_get(js_at(js_get(edited, "do"), 0), "user"), ""), "USER1") == 0,
          "a rule saved with the marker keeps its secrets: %s", err);
    js_free(edited);
    edited = js_copy(js_at(js_get(masked, "rules"), 0));
    js_set(js_at(js_get(edited, "do"), 0), "service", js_string("telegram"));
    CHECK(rules_keep_secrets(edited, saved, err, sizeof(err)) != 0 && strstr(err, "type it again"),
          "a marker in an action of another kind keeps nothing: %s", err);
    js_free(edited);
    js_t *other = j("{\"id\":\"new\",\"on\":[\"alarm\"],\"do\":[{\"type\":\"notify\",\"service\":\"pushover\",\"token\":\""
                    RULES_KEPT "\",\"user\":\"u\",\"message\":\"m\"}]}");
    CHECK(rules_keep_secrets(other, saved, err, sizeof(err)) != 0, "a new rule has nothing to keep: %s", err);
    js_t *sneak = j("{\"id\":\"p\",\"on\":[\"alarm\"],\"do\":[{\"type\":\"notify\",\"service\":\"pushover\",\"token\":\"t\","
                    "\"user\":\"u\",\"message\":\"" RULES_KEPT "\"}]}");
    CHECK(rules_keep_secrets(sneak, saved, err, sizeof(err)) != 0, "the marker in a field that is no secret keeps nothing");
    js_free(sneak);
    js_free(other);
    js_free(masked);
    js_free(saved);

    /* what an event matches */
    js_t *r = j("{\"id\":\"a\",\"on\":[\"job.ended\",\"alarm\"],\"if\":{\"result\":\"ended\"},\"do\":[" GOOD_NTFY "]}");
    js_t *ended = j("{\"result\":\"ended\"}"), *alarmed = j("{\"result\":\"alarm\"}");
    CHECK(rules_match(r, "job.ended", ended) && !rules_match(r, "job.ended", alarmed) && !rules_match(r, "job.armed", ended),
          "the event and the condition");
    js_set(r, "enabled", js_boolean(0));
    CHECK(!rules_match(r, "job.ended", ended), "a rule turned off fires for nothing");
    js_free(r);
    r = j("{\"id\":\"a\",\"on\":[\"*\"],\"do\":[" GOOD_NTFY "]}");
    CHECK(rules_match(r, "lid", NULL), "\"*\" is every event");
    js_free(r);

    /* the text */
    js_t *data = j("{\"code\":9,\"result\":\"alarm\",\"q\":\"a\\\"b\",\"on\":true}");
    char *t = rules_expand("{event}: code {data.code}, {data.result}, {data.none}{data.on} {nope}", "alarm", data, 0);
    CHECK(t && strcmp(t, "alarm: code 9, alarm, true {nope}") == 0, "the text: %s", t ? t : "(none)");
    free(t);
    t = rules_expand("{\"q\":\"{data.q}\",\"all\":{data}}", "x", data, 1);
    CHECK(t && strcmp(t, "{\"q\":\"a\\\"b\",\"all\":{\"code\":9,\"result\":\"alarm\",\"q\":\"a\\\"b\",\"on\":true}}") == 0,
          "escaped for inside a JSON string: %s", t ? t : "(none)");
    free(t);
    js_free(data);
    js_free(ended);
    js_free(alarmed);

    /* the file */
    char path[] = "/tmp/rules-test-XXXXXX";
    int fd = mkstemp(path);
    close(fd);
    unlink(path);
    doc = rules_load(path, err, sizeof(err));
    CHECK(doc && js_len(js_get(doc, "rules")) == 0, "no file is no rules: %s", err);
    js_free(doc);
    doc = j("{\"rules\":[" RULE("[\"x\"]", GOOD_NTFY) "]}");
    CHECK(rules_save(path, doc, err, sizeof(err)) == 0, "written: %s", err);
    js_t *back = rules_load(path, err, sizeof(err));
    CHECK(back && js_len(js_get(back, "rules")) == 1, "and read: %s", err);
    js_free(back);
    js_free(doc);
    FILE *f = fopen(path, "w");
    fputs("{\"rules\":[{\"id\":\"BAD\"}]}", f);
    fclose(f);
    back = rules_load(path, err, sizeof(err));
    CHECK(!back && strstr(err, "does not hold"), "a file that does not hold: %s", err);
    unlink(path);

    /* where a URL goes */
    static const struct { const char *url, *dest; } urls[] = {
        { "http://Plug.LAN/relay/0?turn=on", "plug.lan:80" }, { "https://ntfy.sh/topic", "ntfy.sh:443" },
        { "http://192.0.2.4:8080/x", "192.0.2.4:8080" }, { "http://[fd00::4]:81/", "[fd00::4]:81" },
        { "https://ha.lan:8123", "ha.lan:8123" },
    };
    for (size_t i = 0; i < sizeof(urls) / sizeof(urls[0]); i++) {
        char dest[300];
        CHECK(web_url_dest(urls[i].url, dest, sizeof(dest)) == 0 && strcmp(dest, urls[i].dest) == 0, "%s -> %s", urls[i].url,
              dest);
    }
    static const char *const bad_urls[] = { "ftp://x/", "http://", "http://u:p@x/", "http://x/ y", "javascript:1",
                                            "http://x:0/", "http://x:99999/" };
    for (size_t i = 0; i < sizeof(bad_urls) / sizeof(bad_urls[0]); i++) {
        char dest[300];
        CHECK(web_url_dest(bad_urls[i], dest, sizeof(dest)) != 0, "a URL taken: %s", bad_urls[i]);
    }

    printf("%s: rules_test, %d failure%s\n", fails ? "FAIL" : "PASS", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
