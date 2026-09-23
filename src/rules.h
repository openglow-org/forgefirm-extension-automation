/*
 * rules.h - the automation package's rules: their form, their secrets, and what one event matches
 * Copyright 2026 514 LLC d/b/a OpenGlow
 * Written by Scott Wiederhold
 * SPDX-License-Identifier: MIT
 *
 * A rule is an event (or several), an optional condition on the event's
 * data, and up to eight actions:
 *
 *   {"id": "job-done", "name": "Tell me when a job ends", "enabled": true,
 *    "on": ["job.ended"], "if": {"result": "ended"},
 *    "do": [{"type": "notify", "service": "ntfy", "topic": "my-laser", "message": "Done"}]}
 *
 * An action is notify (ntfy, Pushover, Telegram, Discord, or a webhook),
 * http (a request of the operator's: a smart plug, Home Assistant), mqtt
 * (one publish), hold_until (hold the job until an address answers with a
 * word: the exhaust confirming), or clear_hold. Any of them may wait
 * after_s seconds, and a waiting one is dropped by any event named in its
 * cancel_on: the exhaust's run-on after a job, canceled by the next job.
 * Text may carry {event} and {data.<key>}.
 *
 * The rules file is the service's own, in its data directory. What the
 * page is shown never carries a secret back: a token, a password, a
 * Discord webhook's address is replaced by RULES_KEPT, and a rule saved with
 * RULES_KEPT in that place keeps the value it had.
 */
#ifndef AUTOMATION_RULES_H
#define AUTOMATION_RULES_H

#include <stddef.h>

#include "js.h"

#define RULES_MAX           32
#define RULE_ACTIONS_MAX    8
#define RULE_EVENTS_MAX     8
#define RULE_TEXT_MAX       512
#define RULES_FILE_MAX      (48 * 1024)     /* its page is shown all of it, and a call answers at most 64 KiB */
#define RULES_KEPT          "__kept__"

/* Every action type, for the page. */
extern const char *const rules_action_types[];
/* The events the machine publishes today, for the page; a rule may name
 * any event name, so that one published later needs no new service. */
extern const char *const rules_known_events[];

/* One rule is in form: 0, or -1 with the words. */
int rules_check_rule(const js_t *rule, char *err, size_t elen);

/* The file's whole form: {"rules": [...]}, each in form, the ids unique. */
int rules_check(const js_t *doc, char *err, size_t elen);

/* The rules as the page is shown them: a copy with every secret replaced
 * by RULES_KEPT (an empty secret stays empty). */
js_t *rules_masked(const js_t *doc);

/* A rule from the page: each RULES_KEPT takes the value the saved rule of
 * the same id had in the same action of the same type. 0, or -1 when
 * there is none to keep. */
int rules_keep_secrets(js_t *rule, const js_t *saved_doc, char *err, size_t elen);

/* Does the rule fire for this event: enabled, the event among its "on"
 * (or "*"), and every "if" key equal in the event's data. */
int rules_match(const js_t *rule, const char *event, const js_t *data);

/* The text with {event} and {data.<key>} put in (a missing key is empty),
 * and {data} as the event's data whole, as JSON; malloc'd, at most
 * RULE_TEXT_MAX * 4 bytes. With json set, {event} and {data.<key>} are
 * escaped for inside a JSON string; {data} is a JSON value and never is. */
char *rules_expand(const char *tmpl, const char *event, const js_t *data, int json);

/* The rules file: read (a missing file is no rules) and written whole. */
js_t *rules_load(const char *path, char *err, size_t elen);
int rules_save(const char *path, const js_t *doc, char *err, size_t elen);

#endif
