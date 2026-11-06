# Expiry — Design and build plan

A personal app that tracks documents that expire (passports, IDs, bank cards, driver's licences,
vehicle registration, insurance, visas/permits and custom types) for the whole family, reads the key
details from a scan, and reminds you through your calendar before anything runs out.

- **User:** one person (Salim), managing a profile per family member.
- **Device:** Samsung Galaxy Z Fold 8 — every screen designed for folded and unfolded use.
- **Reference app:** Mandoos (`../Mandoos`, see `GITHUB-SYNC-AND-PWA-GUIDE.md`). Security, encryption,
  Gist sync and Fold layout follow Mandoos unless this document says otherwise.

Status: design agreed 2026-11-06. **M1–M9 built** (records, profiles, Fold layouts, app lock,
fingerprint, sensitive vault, auto-lock, encrypted photos and PDFs, scanning and reading details,
calendar reminders and Home summary, renew flow and History, encrypted GitHub sync, backups,
type and field editor, optional document title, list sorted by expiry → type → title, images locked for every type, fingerprint retries, image viewer arrows on the image + swipe, Home calendar view, calendar files confirmed by you, Start fresh for Google Calendar; 327 jsdom checks, `npm test`). Live at aufisn.github.io/expiry; next: test on the Fold.

M2 notes (decisions made while building):
- The app lock is **required** in Expiry (optional in Mandoos): setup asks for a password (8+ characters)
  before anything is stored, and M1 data is encrypted on first launch.
- The sensitive key is an **RSA-OAEP key pair**: the public key seals sensitive values at any time
  (no prompt when saving); only the private key needs a fingerprint or password, at reveal time.
- Editing a sensitive field while it's hidden shows an empty box with "•••• 4021 · leave empty to keep".

M3 notes:
- Photos are resized to max 2000px JPEG (a 4.6 MB test image became 207 KB, thumbnail 10 KB).
- Files live in IndexedDB `expiry_files`, one encrypted record each; sensitive ones are sealed to the vault.
- Each file can be renamed, deleted, or switched between sensitive and normal in the viewer's ⋮ menu.
- "Take photo" opens the phone camera for one photo at a time; the live scanner and text reading are M4.
- PDF viewing uses pdf.js from jsDelivr (cached for offline after first use); PDFs up to 15 MB.

M4 notes:
- Reading starts as soon as a new document's pages are added (scan, photo or file); the form opens at once
  and fills in as text is read. Anything you've typed is never overwritten.
- Tesseract.js 5.1.1 (jsDelivr) does the reading; a second strict pass reads the code strip. PDFs with a
  text layer are read directly. Browser test: a passport page and an insurance certificate each took ~2 s on the Mac.
- Code strip values are "Verified" only when their check digits match; everything else is "Check".
- Owner is preselected when the code strip's first given name matches exactly one profile.
- Unfolded, Check details takes the whole inner screen (image left with highlight, fields right).
- Settings → Reading scans: day-first (default) or month-first dates; unclear dates offer a one-tap swap.
- Not yet tested on the Fold: real camera stream, tabletop layout, reading speed on the phone.

M5 notes:
- One .ics file per export: one event per future reminder at the reminder time (default 09:00, Settings),
  15 minutes long, with an alert at its start and a link back to the document (#doc=<id>, opens after unlock).
- Event UIDs are stable (document + lead time); SEQUENCE rises each export, so re-importing updates events.
  Changed, archived or deleted documents produce STATUS:CANCELLED entries for events that no longer apply.
- Events never contain reference numbers (calendars sync to the cloud): only owner, type and dates.
- Expired and archived documents get no events; the Home "Needs attention" summary covers them.
- Delivery: "Open in calendar app" downloads the file; "Share file…" appears where the phone can share files.
  Whether Samsung Calendar honours cancellations and updates on import still needs checking on the Fold.
- Later fix: each file is named after what's in it and when (`expiry-passport-20261106-1830.ics`,
  `expiry-all-reminders-….ics`). Saving or sharing the file no longer counts as "in your calendar": Expiry
  asks "Did the reminders reach your calendar?" with how to open the file and which event to look for, plus
  the Google Calendar import route if the phone won't open it. Until you confirm, the document says "not
  confirmed" and Home offers "Check". Files sent before this change count as not confirmed.
- Every calendar sheet shows who is in the file (per person: number of reminders and their date range).
  "Check" re-sends all documents' reminders. Settings → "Start fresh in Google Calendar" adds a generation
  to every event ID (`…-g1@expiry.app`), because Google silently skips events whose ID it has seen before,
  even deleted ones; the old IDs are sent as cancellations.
- After saving a new or changed document Expiry offers the calendar; each document shows its calendar status;
  Home shows a nudge when documents aren't up to date; Settings has "Add all reminders to calendar".

M6 notes:
- Renew opens from the document's Renew button, a left swipe on a Home row, or (via the calendar link) the document.
- "I have the new one": scan, photo, file or manual. The form keeps type, owner and unchanged fields; number,
  issue and expiry dates start empty, with "Before: …" underneath and "Same as before" for unchanged numbers.
  Scans fill the empty fields. Saving moves the old values, sealed values and files into History (newest first).
- "Renewal in progress": applied on, application ref., expected by, note. Expiry reminders pause; one calendar
  follow-up on the expected date; Home flags it when the expected date passes.
- "Not renewing": choose a reason (sold, cancelled, replaced, lost or stolen, no longer needed) → Archive.
  The ⋮ menu's Archive uses the same reasons. Archived documents show the reason and a Restore button.
- History versions open read-only, with their files in the viewer and sensitive values behind Reveal;
  a version can be deleted (its files too). Deleting a document deletes every version's files.

M7 notes:
- Settings → Sync: Gist ID + classic token with only the gist scope. First device confirms its password;
  other devices enter the first device's password. If a device has a different password of its own, it is
  asked for that too, and its sensitive values and images are re-sealed to the shared vault (fingerprint
  unlock must then be turned on again on that device).
- Token, sync key and the last-synced copy (merge base) are stored encrypted under the data key.
- Three-way merge per document; edits beat deletes; profiles/types/settings merge silently. A document
  changed differently on two devices opens "Choose which version to keep" (manual sync only; automatic
  sync waits and Home says "Sync needs your decision").
- Automatic sync: 20 s after a change, on unlock, and on returning after 15 minutes. Calendar bookkeeping
  is per device and never synced. Each device's "You" profile is merged into one.
- Changing the password re-wraps the GitHub copy's keys; other devices keep syncing, new devices need the
  new password.
- Tested against a fake GitHub API with three simulated devices; not yet against real GitHub.

M8 notes:
- Settings → Backup: Encrypted backup, Plain backup (warning first), Restore from backup, backup folder
  (computer only: Change / Forget), and when the last backup was made on this device.
- Restore: choose a file (.json or .html). Encrypted → backup password. Then "Restore" (empty phone),
  "Add to this phone" (newer version of a document wins) or "Replace everything on this phone".
  Card numbers and sensitive images are re-sealed to this phone's keys, so its password/fingerprint keep working.
  Afterwards Expiry offers to add the restored reminders to this phone's calendar.
- An empty Home offers "Restore from a backup" and "Connect GitHub sync".
- Home nudges for a backup when there's no GitHub sync, the oldest document is over a week old, and there's
  been no backup on this device for 30 days.

M9 notes:
- Settings → Document types and fields: list of types (fields, documents, hidden) → type editor: name, icon,
  fields (tap to edit, arrows to reorder, Add field), name on the list, default reminders, images locked or not,
  show/hide when adding, and Reset (built-in types) or Delete (your own types, only when no document uses them).
- Field sheet: label (unique in the type), kind (chosen when the field is added: text, long text, date, month and
  year, number, choice), choices for a choice field, example text, Required, Sensitive (text and number only),
  Show on Home list (one per type). Reference no., Expiry date and Note can't be removed; Expiry can switch
  between full date and month-and-year.
- Saving a type changes stored data in one step (worked on copies first, so a failure changes nothing):
  removed fields' values are deleted, including from History (asked first when any document has a value);
  a field made sensitive is sealed in every document and History; a field that stops being sensitive asks for
  the password and stores its values plainly. After a sync, values in fields made sensitive on another device
  are sealed here too.
- Images on a Locked type are always locked, including ones already saved and those in History: Expiry
  re-seals them on unlock, after a sync, after a restore and when a type is switched to Locked. Each gets a new
  file id, so sync uploads the locked copy and deletes the old Gist. Exception: an image you set to "Stop
  treating as sensitive" stays unlocked. Every built-in type, and every new type, starts Locked (M9.1; earlier
  builds left Vehicle registration, Insurance and Other unlocked, and are moved over once).
- Default reminders apply to new documents only.
- Settings → Appearance: how dates are shown (14 Apr 2027, 14/04/2027, 04/14/2027, 2027-04-14). Calendar
  events always use the written-out form, so changing it doesn't make every event out of date.
- Settings stays one scrolling page in the right pane when unfolded, instead of the sections-left /
  section-right layout first sketched in 4.8: the list pane already takes the left side.

---

## 1. Decisions

| Topic | Decision |
|---|---|
| Platform | Installable web app (PWA) on GitHub Pages, added to the Fold home screen — same as Mandoos |
| Users | Single user, one profile per family member, "All" view shows the owner on every item |
| Storage | Encrypted on the phone; synced to an encrypted secret GitHub Gist |
| Security | Mandoos app lock (password + fingerprint passkey, auto-lock) plus a second **sensitive key** for images and sensitive fields |
| Reminders | Calendar events (.ics) with alerts, plus an in-app summary when the app opens |
| Attachments | Kept (including bank card photos); each synced as its own encrypted file in the Gist |
| Backup | Encrypted backup file, plus an optional plain (unencrypted) backup to a location you choose |
| Scanning | On-device only (Tesseract.js + passport/ID code-strip reader). You confirm every field before save |
| Fields | Every document has a Note. Types and fields are editable in Settings so more can be added later |

---

## 2. Core concepts

### Profile
Name, relationship, colour (initials avatar), optional date of birth. Each document has exactly one
owner profile.

### Document
| Field | Notes |
|---|---|
| Type | From the type templates (below) |
| Owner | A profile |
| Reference number | Passport no., policy no., plate, card number (sensitive) |
| Issuer | Country, bank, insurer, authority |
| Issue date, Expiry date | Expiry is required |
| Type-specific fields | Defined by the type template |
| Note | Free long text on every document |
| Reminders | List of lead times → concrete dates |
| Attachments | Pages/images/PDFs, each marked sensitive or not |
| Status | Derived (see below) |
| History | Previous versions after each renewal |
| Renewal | Optional in-progress record (applied on, application ref., expected by, note) |

### Type templates
Each type defines its fields (name, kind: text / long text / date / number / list; flags: required,
sensitive, shown on list row), default reminders and whether images are sensitive by default.

| Type | Default reminders | Images sensitive |
|---|---|---|
| Passport | 9 months, 6 months before (many countries need 6 months' validity to enter) | Yes |
| National ID | 3 months, 1 month | Yes |
| Driver's licence | 2 months, 2 weeks | Yes |
| Bank card | 30 days | Yes |
| Vehicle registration | 30 days, 7 days | No |
| Insurance | 30 days, 7 days | No |
| Visa / permit | 3 months, 1 month | Yes |
| Custom | User defined | User defined |

Editing rules: adding or renaming a field never touches stored data; removing a field hides it
(the stored value is kept).

### Status
| Status | Rule | Colour |
|---|---|---|
| Valid | Expiry beyond the earliest reminder | Green |
| Expiring soon | Inside the reminder window | Amber |
| Expired | Past the expiry date | Red |
| Renewing | Renewal in progress recorded | Blue |
| Archived | Not renewing (sold, cancelled, replaced) | Grey |

### Reminder rules
- Reminder date = expiry − lead time. If that date has already passed, schedule it for tomorrow and
  mark it.
- While Renewing: expiry reminders pause and one follow-up reminder is set on the expected-by date.
- Each reminder has a stable ID reused across renewals so calendars can update instead of duplicate.

---

## 3. Layout: Galaxy Z Fold 8

Breakpoints follow Mandoos §16 (pure CSS media queries; folding never re-renders):

| Mode | Width | Layout |
|---|---|---|
| Folded (cover screen) | < 720px | Single column; list → detail opens full screen |
| Unfolded (inner screen) | 720–1099px | List-detail: list on the left, selected item on the right |
| Desktop (laptop) | ≥ 1100px | Same as unfolded, wider |
| Tabletop (half-folded) | Device posture / viewport segments | Scanning only: camera on top half, fields on bottom half |

---

## 4. Screens

### 4.1 Lock screen
The Mandoos lock screen: password field, fingerprint button, "Forgot password?" escape that erases
this device's keys. Content is never painted while locked.

### 4.2 Home dashboard
- Header: app name, search, settings.
- Profile chips: **All** · each profile. Selected profile filters everything below.
- Three counters: Expired · Expiring soon · Valid (tap to filter). Archive is a filter too.
- Sections in order: **Needs action** (expired, expiring soon) · **In progress** (renewing) · **Valid**.
  Sorted by time left.
- Row: type icon, type name, owner, the field flagged "shown on list" (bank cards show `•••• 1234`
  only), time-left badge.
- Swipe a row → Renew. Floating **Add** button.
- Unfolded: the right pane shows the selected document's detail (4.4).

### 4.3 Add document
1. **Add sheet:** Scan with camera · Choose photo · Import file (PDF or image) · Enter manually.
2. **Capture:** frame guide; front, then optional back, then "+ Add page". Tabletop posture puts the
   camera on top and the live fields underneath.
3. **Check details:**
   - Type detected automatically (code strip → passport/ID, card-number pattern → bank card); changeable.
   - Owner preselected from the profile being viewed on Home.
   - Each field shows its source: **Verified** (code strip with matching check digits),
     **Check** (ordinary text recognition), or blank (not found).
   - Ambiguous dates (e.g. 03/04/2027) follow the date-format setting (day first by default) and are flagged.
   - Reminders shown as concrete dates from the type defaults.
   - Note field.
   - **Save and add to calendar** → saves and hands over the .ics file.
   - Unfolded: image on the left, fields on the right; tapping a field highlights where it was read.
- Manual entry skips straight to Check details with empty fields.

### 4.4 Document detail
- Header: type, owner, issuer, time-left badge.
- Details: all fields; sensitive fields masked (`•••• 4021` + lock icon); copy button after reveal.
- Images: Front / Back / pages shown as locked tiles (lock icon and page name only — no blurred
  copy is stored). Revealed images open full size with pinch-to-zoom.
- Reminders: each date with an "in calendar" mark.
- History: previous versions (revealable the same way).
- Actions: Renew · Edit · More (move to another owner, delete).
- Unfolded: fills the right pane of Home.

### 4.5 Sensitive reveal
- Tap a locked item → fingerprint prompt (or "Use password").
- Releases the **sensitive key** for a **60-second window** that covers all documents.
- Persistent bar: "Revealed · Hides in 0:52 · Hide now".
- Re-hides immediately on leaving the app, screen lock or auto-lock.
- Setting: 60 seconds (default) or ask every time.
- Known limit: a web app can't block screenshots.

### 4.6 Renew
Started from the Renew button, a row swipe, or the link inside a calendar reminder.
1. **I have the new one** → scan/enter with type, owner and issuer prefilled; number and dates
   highlighted. Unfolded shows old vs new side by side; folded shows each old value under the new one.
   **Save renewal** moves the old version (with images) into History, recalculates reminders and
   produces a new calendar file.
2. **Renewal in progress** → applied on, application ref., expected by, note. Status becomes Renewing;
   expiry reminders pause; follow-up reminder on the expected-by date.
3. **Not renewing** → reason; reminders stop; document moves to Archive (restorable).

After saving, if the calendar can't replace old events, the app lists which old events to delete.

### 4.7 Profiles
- List: avatar, name, relationship, document count, one-line status.
- Tap → Home filtered to that person. Long-press → edit.
- Add/edit: name, relationship, colour, optional date of birth.
- Delete: must choose to move that person's documents to another profile or archive them.
- Unfolded: list left, that person's documents right.

### 4.8 Settings
- **Security:** app password and fingerprint, auto-lock (never / on leave / 1 / 5 / 15 / 30 min),
  change password, sensitive reveal window.
- **Document types and fields:** type list → editor (fields, flags, default reminders, images sensitive).
  New custom types.
- **Reminders and calendar:** date format, in-app summary on open, re-export all reminders as one .ics.
- **GitHub sync:** token (gist scope), Gist ID, Sync now, synced status.
- **Backup and restore:** encrypted backup, plain backup (with warning), restore from either.
- Unfolded: sections left, selected section right.

---

## 5. Security and data

### Keys
| Key | Protects | Unlocked by | Lives in memory |
|---|---|---|---|
| Data key (DEK) | App state (documents, profiles, settings) and sync config | Password (PBKDF2-SHA256, 310 000 iterations) or fingerprint passkey (WebAuthn PRF) — as Mandoos §13–14 | While the app is unlocked |
| Sensitive key (SK) | Sensitive images and sensitive field values | Password or fingerprint, asked again at reveal time | Only during the reveal window, then wiped |
| Sync key | The Gist copy | Wrapped under the password inside the Gist envelope (Mandoos §15), so a new device needs only the password | Stored in the encrypted sync config |

Both DEK and SK are random AES-256-GCM keys stored only in wrapped form; changing the password
re-wraps them without re-encrypting data.

### Storage on the phone
- Small state: `localStorage` with `expiry_`-prefixed keys (the origin is shared with Mandoos on
  GitHub Pages), as encrypted `{__enc, iv, ct}` envelopes.
- Images and PDFs: IndexedDB database `expiry_files`, each blob encrypted (DEK or SK), compressed to
  roughly 200–300 KB JPEG.

### Gist layout (changed in M7)
- Your secret Gist holds one file, `expiry-state.json`: the documents, profiles, types and settings,
  AES-GCM encrypted with a random sync key. Its `auth` part holds the sync key and the vault private key,
  each wrapped under your password (PBKDF2), so a new device needs only that password.
- Each photo/PDF lives in **its own small secret Gist** ("Expiry: encrypted file (do not edit)"), created
  and deleted automatically. Reason: the Gist API returns every file's content on every read and update,
  so one Gist with all images would re-download them on every sync. Normal files are re-encrypted with the
  sync key; sensitive ones stay sealed to the vault. Files over ~6.5 MB stay on the device only.

### Backups (as built in M8)
- **Encrypted backup** (`expiry-backup-YYYY-MM-DD.expiry.json`): documents, profiles, types, settings and every
  file, encrypted with a random key that is wrapped (with the vault key) under the password you had when you made
  it. Restoring needs that password, even after a later password change.
- **Plain backup** (`expiry-backup-YYYY-MM-DD-NOT-ENCRYPTED.html`): one self-contained web page, readable and
  printable on any computer, with every document, card numbers, notes, reminders and images inline. Shown only
  after a clear warning and your password. Expiry can restore from it (data embedded as JSON in the page).
- **Where it goes:** on the laptop, "Save to a folder…" picks a folder once and reuses it; Download and (where
  supported) Share also work. On the Fold: Download, or Share to My Files / Google Drive.
- Neither backup ever contains the app password, data key, GitHub token or calendar bookkeeping.

### Calendar reminders
- Generated `.ics` file, one event per reminder with an alarm, stable UID, and a link that opens the
  document in Expiry.
- Target: Samsung Calendar on the Fold. Google Calendar's Android app doesn't import .ics directly —
  verify the best route during M5.

---

## 6. Build plan

### Approach
- **Same stack as Mandoos:** a single `index.html` (vanilla JS, no build step) plus `sw.js`,
  `manifest.json` and icons, hosted on GitHub Pages from a new repo.
- **Reuse from Mandoos:** app lock, fingerprint passkey, auto-lock, encrypted Gist sync and merge,
  Fold breakpoints, PWA shell, jsdom test approach.
- **New libraries** (stored in the repo and cached offline by the service worker):
  - Tesseract.js + English language data — on-device text recognition.
  - pdf.js — render PDF pages for preview and scanning.
  - Own code: passport/ID code-strip parser (ICAO 9303 TD1/TD3 with check digits), card-number
    check (Luhn), date-pattern finder.
- **Tooling on this Mac:** Node, git and GitHub CLI are installed. No Xcode or Android Studio needed.
- **Tests:** jsdom tests per feature, like Mandoos.

### Milestones
Each milestone ends with tests passing and a check on the Fold.

| # | Milestone | Delivers |
|---|---|---|
| M1 | Shell and records ✅ | PWA shell, Fold layouts, profiles, type templates, manual add/edit, Home, Document detail, statuses |
| M2 | Security ✅ | App lock, fingerprint, auto-lock, sensitive key and reveal window |
| M3 | Attachments ✅ | Camera capture, photo/PDF import, compression, encrypted file storage, viewer |
| M4 | Scanning ✅ | Text recognition, code-strip reader, card and date detection, Check details screen, tabletop layout |
| M5 | Reminders ✅ | Calendar file export with document links, in-app summary, re-export all |
| M6 | Renew ✅ | Three renew paths, History, Archive |
| M7 | Sync ✅ | Gist sync of state and per-file attachments, merge, conflict handling |
| M8 | Backup ✅ | Encrypted backup, plain backup, restore |
| M9 | Settings polish ✅ | Type and field editor, date format, remaining settings |

**Rule:** don't enter real documents until M2 (security) is done — M1 stores data unencrypted.

### Open items for the build
- GitHub repo name for the app (it decides the install URL).
- Best calendar import route on the Fold (Samsung Calendar vs Google Calendar).
- Accuracy of on-device text recognition on your actual documents — tune in M4.

---

## 7. M10: Phone notifications (designed, on hold: calendar route preferred for now)

**Goal:** Expiry tells you about a reminder date even if you never imported the calendar file.
The calendar export stays as a second route.

### What you get
| Notification | When | Text (default, nothing sensitive) |
|---|---|---|
| Reminder | On each reminder date (e.g. 6 months before a passport expires) | "Expiry · 1 document needs attention" · "Expires in 6 months. Tap to see it." |
| Expiry day | On the expiry date itself | "Expiry · A document expires today" |
| Renewal follow-up | On the renewal's expected-by date | "Expiry · A renewal was expected today" |
| Several at once | Combined into one notification | "Expiry · 3 documents need attention" |

- Tapping opens Expiry; after unlock it goes straight to the document (one item) or to Home
  filtered to "Expiring soon" (several).
- Buttons on the notification: **Open** · **Tomorrow** (snooze one day).
- Each reminder notifies once per phone (reminders already have stable ids); renewing a document
  creates new reminders automatically.
- Notifications use the reminder time from Settings (default 09:00), as near as Android allows.
- Optional setting **"Show type and person"**: "Passport · Salim expires in 6 months". Off by default
  because notifications show on the lock screen. Reference numbers are never shown.

### How it works on the Fold
- **Permission:** requested only when you tap "Turn on notifications" (Android requires a tap).
- **Daily background check:** Chrome's periodic background sync for installed apps, asked for once a day.
  Chrome decides the actual timing from how often you use the app. It can be later than 09:00, and
  may pause if the phone is in battery saver or the app is unused for weeks.
- **Check on open:** every time Expiry opens (even on the lock screen) it catches up on anything missed.
- **No server:** nothing leaves the phone; there is no push service.
- **Known limit:** a web app cannot schedule an exact alarm; if background checks turn out unreliable on
  the Fold, a later option is a small daily GitHub Action that sends a push (needs a server-side key).

### Data kept for the background check
The service worker can't read the encrypted data, so on each save while unlocked Expiry writes a small
**notification schedule** to IndexedDB (`expiry_notify`): reminder id, date, kind (reminder / expiry /
follow-up), lead text ("6 months"), and, only if "Show type and person" is on, the type name and owner's
first name. No numbers, titles or images. It is cleared when notifications are turned off or the phone's
keys are erased ("Forgot password").

### Screens
- **Home, one-time card** (until turned on or dismissed): "Get reminders as phone notifications?
  [Turn on] [Not now]".
- **Settings → Reminders** (renamed from "Reminders and calendar"):
  - Notifications: On / Off, with status — "On · last checked today 09:12", "Blocked in Android settings
    (how to fix)", or "Background checks not available: you'll be notified when you open Expiry".
  - Show type and person in notifications: Off / On.
  - Send a test notification.
  - Reminder time (existing), "Needs attention" on Home (existing), Add all reminders to calendar (existing).
- Folded and unfolded use the same settings card; the Home card sits above the counters.
