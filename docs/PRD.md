# Expiry — Product requirements (phase 2 enhancements)

| | |
|---|---|
| Version | 0.1 (draft) — 2026-11-26 |
| Owner | Salim |
| Status | E1 designed in words; mock-ups to approve before building (decision gate DG-E1) |
| Built so far | M1–M9, see `DESIGN.md` (live at https://aufisn.github.io/expiry/) |

This document collects the enhancements after the first build. Each enhancement gets its own
section (E1, E2, …) with its goal, design, requirements, acceptance tests and open questions.
`DESIGN.md` stays the record of what is built; this PRD is the record of what comes next.

**Rules that apply to every enhancement**
- Documents (numbers, images, notes) never leave the phone unencrypted. Only the phone can read them.
- The app repository is public: no secret, token, chat ID, access code or personal data is ever committed.
- Design first: mock-ups for every new screen and message, approved before building.
- Every screen works folded (cover screen) and unfolded (inner screen) on the Galaxy Z Fold.
- Free plans only; no new paid service.

## Enhancement index

| ID | Enhancement | Priority | Status |
|---|---|---|---|
| E0a | Fully automatic sync (no Sync button needed) | — | **Built 2026-11-26** (DESIGN.md §8) |
| E0b | Three Home designs (List · Timeline · Family), chosen in Settings | — | **Built 2026-11-26** (DESIGN.md §8) |
| E1 | Telegram reminders through a Cloudflare Worker | 1 | Designed, awaiting mock-up approval |
| E2 | Trip-readiness check (documents valid for a trip, per traveller) | 2 | Idea (from the benchmark review, 2026-11-06) |
| E3 | Guided renewal checklist and costs per document type | 3 | Idea (from the benchmark review, 2026-11-06) |

---

## E1. Telegram reminders through a Cloudflare Worker

### E1.1 Why

Reminders today reach the user through calendar files (.ics). In use this caused real friction:
- the file has to be opened and imported by hand, and the app can't tell whether it worked;
- Google Calendar's phone app doesn't show events more than about 3 years ahead;
- each change needs a new file, and "start fresh" shows duplicates and crossed-out cancellations;
- a calendar alert fires once, while a renewal takes weeks of follow-up.

Phone notifications from the web app (DESIGN.md section 7, on hold) can't fire reliably on a schedule.
A Telegram bot run by a small server fixes all of these, and the user already runs this pattern for
Market Monitor on Cloudflare.

### E1.2 Goals
- G1. Every reminder reaches the user on its date without any import step, years ahead included.
- G2. A reminder repeats daily until the user acts on it (acknowledge, renewing, snooze).
- G3. Button taps take effect instantly and show up in the app.
- G4. Optionally, a family member gets the reminders for their own documents.
- G5. Privacy is no worse than the calendar route: the server sees only reminder dates and labels.

**Non-goals:** storing documents on a server; showing reference numbers, images or notes in Telegram;
replacing the app's encryption or Gist sync.

### E1.3 Decisions made (2026-11-26)

| Topic | Decision | Reason |
|---|---|---|
| Server | A **separate** Cloudflare Worker for Expiry, on the user's existing account (free plan), with its own D1 database | The account already exists; kept apart from Market Monitor so neither can break the other |
| Bot | A **new** Telegram bot for Expiry (BotFather), not Market Monitor's | Separate chat, sound and mute settings |
| Data on the server | Only the **reminder list**, never documents | Keeps the app's main promise: only the password or fingerprint unlocks documents |
| How the list reaches the server | The app sends it straight to the Worker after save, edit or sync | Simple; no extra key; instant |
| Calendar files | Kept as an optional second channel | Some users still want calendar events |
| Rejected: whole data architecture of Market Monitor (documents in a server database) | Little usability gain, real privacy cost | Gist sync already covers multiple devices |
| Rejected for now: GitHub Actions daily job | Button taps only collected on the next run, taps lost after 24 h, late runs, scheduled jobs in public repos stop after 60 days without commits | Kept as a fallback if Cloudflare is ever unavailable |

### E1.4 How it works

```
 Expiry app (phone)                         Cloudflare Worker (expiry-reminders)          Telegram
 ─────────────────                          ───────────────────────────────────          ────────
 save / edit / sync ──PUT /api/schedule──▶  D1: reminders (replace whole list)
   (access code)                                  │
                                            daily timer ~09:00 Muscat
                                            picks due items ───────────────sendMessage──▶ user's chat
                                                                                           │ taps a button
                                            webhook /tg (secret header) ◀──callback_query──┘
                                            updates state, replies at once
 app opens ──GET /api/status──────────────▶ acknowledged / snoozed / renewing per reminder
 shows "Acknowledged in Telegram"
```

1. **Building the list (phone).** From the same rules that build calendar events today, the app makes one
   item per future reminder: `id` (stable, reused across exports), `date` (YYYY-MM-DD), `kind`
   (reminder | expiry-day | renewal-follow-up), `doc` (an opaque id, not the document number), `owner`
   (profile id) and `label`.
2. **Sending it.** After a save, edit, renewal, archive, delete or sync, the app sends the whole list to
   the Worker. The Worker replaces its copy, so removed reminders disappear by themselves. If the phone is
   offline, the app retries the next time it opens.
3. **Daily run.** Once a day the Worker sends every item that is due (date ≤ today), not acknowledged and
   not snoozed. Items not acted on are sent again the next day, with "reminder 2", "reminder 3"…
4. **Buttons.** Telegram calls the Worker's webhook immediately; the Worker applies the action and edits the
   message to show the result (e.g. "Snoozed until 3 Dec").
5. **Back in the app.** When Expiry opens, it asks the Worker for the state of each reminder and shows it on
   the document and in "Needs attention".

### E1.5 Requirements

**Reminder list and privacy**
- FR-1.1 The list holds only: reminder id, date, kind, opaque document id, owner profile id, label, and
  the time of the last change. Never reference numbers, issuers, notes, images or field values.
- FR-1.2 Label detail is a setting: **Type and person** ("Sara's passport expires 29 Jan 2032", default)
  or **Generic** ("A document expires on 29 Jan 2032").
- FR-1.3 The app sends the whole list each time (replace, not merge), with a version number; the Worker
  ignores an older version than the one it holds (two devices).
- FR-1.4 Archived, deleted and expired documents produce no items; renewing documents produce only the
  follow-up item, as for calendar events today.
- FR-1.5 "Turn off Telegram reminders" in Settings deletes the list on the Worker.

**Messages**
- FR-2.1 A reminder message shows: label, time left ("in 6 months"), kind, reminder number, and buttons:
  **Acknowledge**, **Renewing now**, **Snooze 1 week**, **Open in Expiry** (link to `#doc=<id>`, opens
  after unlock).
- FR-2.2 Several items due on the same day are sent as separate messages, oldest expiry first.
- FR-2.3 Repeats: daily until acknowledged, renewing or snoozed. Snooze options: 1 day, 1 week, 1 month.
- FR-2.4 Expiry-day item: "expires today"; after the expiry date no more repeats (the app's Home shows it).
- FR-2.5 Commands: `/next` (next 90 days), `/person <name>`, `/snoozed`, `/help`. Replies use labels only.
- FR-2.6 Send time: setting in the app (default 09:00, the reminder time already used for calendar events).

**Acknowledgement and state**
- FR-3.1 Acknowledge stops repeats for that reminder only; the next reminder of the same document still
  comes on its own date.
- FR-3.2 "Renewing now" marks the reminder and tells the app, which offers to record the renewal (applied
  on, expected by) the next time it opens. It doesn't change the document by itself.
- FR-3.3 The app shows the Telegram state per document ("Acknowledged in Telegram 2 Dec") and can
  acknowledge from the app too.

**Family recipients (P2)**
- FR-4.1 A profile can have its own Telegram chat; its documents' reminders go to that chat as well as the
  owner's. Each family member starts the bot once to join; the owner approves the link in the app.

**Security (copied from Market Monitor where noted)**
- FR-5.1 Secrets only in the Worker's secret store: bot token, owner chat ID, webhook secret, access code.
  Never in the app's code, the repository or a log.
- FR-5.2 The webhook is registered with a secret token; the Worker rejects any request without the matching
  `X-Telegram-Bot-Api-Secret-Token` header (Market Monitor FR-5.2).
- FR-5.3 The Worker answers only approved chat IDs and silently ignores everyone else.
- FR-5.4 The app's calls to `/api/*` carry a long random access code (32+ characters), typed into Expiry
  once and stored encrypted with the app's data; 10 wrong attempts lock the API for 15 minutes; "sign out
  everywhere" replaces the code (Market Monitor FR-8.10).
- FR-5.5 Logs record counts and ids only, never labels.
- FR-5.6 Telegram bot chats aren't end-to-end encrypted: this is why labels never carry more than type,
  person and date.

**Reliability and limits**
- FR-6.1 If Telegram can't be reached, messages wait in a queue in D1 and are sent on the next run.
- FR-6.2 The Worker writes only when something changes; expected use is a few requests a day, well inside
  the free plan shared with Market Monitor.
- FR-6.3 Health: if the daily run hasn't happened for 2 days, the app shows a warning in Settings; the bot
  sends a weekly "all quiet" note only if the user turns it on.

### E1.6 Screens and messages to design (decision gate DG-E1)
Mock-ups for approval before building, folded and unfolded:
1. Settings → **Telegram reminders**: status (connected · last run · items on the server), label detail,
   send time, test message, turn off.
2. First-time setup flow in the app (paste the Worker address and access code, send a test message).
3. Document detail: Telegram state line, next to the calendar line.
4. The Telegram messages: single reminder, expiry day, renewal follow-up, the result after each button,
   `/next` reply.

### E1.7 Setup the user does (about 10 minutes)
1. Create the bot with BotFather and keep the token.
2. Message the bot once (so it may write to you).
3. Put the secrets into the Worker's secret store (a setup script prompts for each one; nothing is typed
   into chat or saved in files).
4. Type the Worker address and access code into Expiry → Settings → Telegram reminders.
Claude never handles the token, chat ID or access code.

### E1.8 Acceptance tests
- AT-1 Save a document with a reminder due today → a Telegram message arrives within the next daily run.
- AT-2 Tap Acknowledge → the message updates within seconds; no repeat next day; the app shows
  "Acknowledged in Telegram".
- AT-3 Tap Snooze 1 week → no message for 7 days, then it comes back.
- AT-4 A reminder in 2031 is on the Worker and is sent on its date (tested with a fake clock).
- AT-5 Archive a document → its items disappear from the Worker after the next sync.
- AT-6 A message from another Telegram account gets no reply; a webhook call without the secret header gets 401.
- AT-7 No reference number, issuer, note or image appears in any message, log or Worker table (automated scan).
- AT-8 Wrong access code 10 times → the API is locked for 15 minutes.
- AT-9 Two devices: the older list version never overwrites the newer one.
- AT-10 Telegram down for a run → messages are sent on the next run, none lost.

### E1.9 Open questions
- Q1 Should repeats be daily, or every 3 days for reminders more than a month before expiry?
- Q2 Family recipients (FR-4) in the first build, or later?
- Q3 Keep calendar files as they are, or make them optional and hidden once Telegram works?
- Q4 Arabic labels in messages for family members?

### E1.10 Build plan (after DG-E1)
| Step | Delivers |
|---|---|
| E1-a | Worker project (separate repo, code only), D1 schema, secret setup script, webhook security, tests with a fake clock |
| E1-b | Daily run, messages, buttons, commands, queue |
| E1-c | Expiry: reminder list, sync to Worker, Settings screen, state on documents |
| E1-d | Security review (security-reviewer agent: PASS required), Fold check, go live |

---

## E2. Trip-readiness check *(idea, to be designed)*
Add a trip (destination, dates, travellers). Each traveller gets a verdict per document: OK, or renew first
(with the reason, e.g. passport must be valid 6 months after entry), from a small built-in rule list.

## E3. Guided renewal checklist and costs *(idea, to be designed)*
Per document type: what is needed (photos, old document, fees, office or website, typical processing
time). During a renewal: tick items off, record the fee, and start reminders earlier when processing is slow.
