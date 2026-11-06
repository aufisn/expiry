// Expiry tests (jsdom, real WebCrypto, mock fingerprint authenticator). Run: npm test
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');
const { webcrypto } = require('crypto');
const { IDBFactory, IDBKeyRange } = require('fake-indexeddb');
const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');

const results = [];
function record(name, pass, detail){ results.push({ name, pass: !!pass, detail: detail || '' }); }
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const PW = 'correct-horse-1';

/* ---------- mock platform authenticator (shared across reloads) ---------- */
const b64u = buf => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function rawToDer(raw){
  const enc = v => { let i = 0; while (i < v.length - 1 && v[i] === 0) i++; v = v.slice(i); if (v[0] & 0x80) v = Buffer.concat([Buffer.from([0]), v]); return Buffer.concat([Buffer.from([0x02, v.length]), v]); };
  const r = enc(Buffer.from(raw.slice(0, 32))), s = enc(Buffer.from(raw.slice(32)));
  return Buffer.concat([Buffer.from([0x30, r.length + s.length]), r, s]);
}
async function prfOut(secret, salt){
  const k = await webcrypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return await webcrypto.subtle.sign('HMAC', k, salt);
}
function makeAuthenticator(){
  const a = { creds: {}, mode: 'ok', prf: true, calls: [] };
  a.install = (w) => {
    w.PublicKeyCredential = { isUserVerifyingPlatformAuthenticatorAvailable: async () => true };
    Object.defineProperty(w.navigator, 'credentials', { configurable: true, value: {
      async create({ publicKey }){
        a.calls.push('create');
        if (a.mode === 'cancel'){ const e = new Error('cancelled'); e.name = 'NotAllowedError'; throw e; }
        const kp = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
        const spki = await webcrypto.subtle.exportKey('spki', kp.publicKey);
        const id = webcrypto.getRandomValues(new Uint8Array(16));
        const secret = webcrypto.getRandomValues(new Uint8Array(32));
        a.creds[b64u(id)] = { kp, secret };
        const ext = a.prf ? { prf: { enabled: true, results: { first: await prfOut(secret, publicKey.extensions.prf.eval.first) } } } : {};
        return { rawId: id.buffer, response: { getPublicKey: () => spki, getPublicKeyAlgorithm: () => -7 }, getClientExtensionResults: () => ext };
      },
      async get({ publicKey }){
        a.calls.push('get');
        if (a.mode === 'cancel'){ const e = new Error('cancelled'); e.name = 'NotAllowedError'; throw e; }
        const c = a.creds[b64u(publicKey.allowCredentials[0].id)];
        if (!c) throw new Error('unknown credential');
        const cd = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: b64u(publicKey.challenge), origin: a.mode === 'badOrigin' ? 'https://evil.example' : 'https://localhost' }));
        const ad = Buffer.alloc(37); ad[32] = a.mode === 'noUV' ? 0x01 : 0x05;
        const hash = Buffer.from(await webcrypto.subtle.digest('SHA-256', cd));
        let sig = Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, c.kp.privateKey, Buffer.concat([ad, hash])));
        if (a.mode === 'badSig') sig[5] ^= 0xff;
        const ext = { prf: { results: { first: await prfOut(c.secret, publicKey.extensions.prf.eval.first) } } };
        return { response: { clientDataJSON: cd.buffer.slice(cd.byteOffset, cd.byteOffset + cd.length), authenticatorData: ad.buffer, signature: rawToDer(sig) }, getClientExtensionResults: () => ext };
      }
    } });
  };
  return a;
}


/* ---------- fake GitHub Gist API (shared by all simulated devices) ---------- */
function makeGitHub(){
  const g = { gists: {}, n: 0, calls: [], token: 'ghp_test_token_0123456789abcdef', fail: null };
  const view = (gi) => ({ id: gi.id, description: gi.description || '', owner: { login: 'salim' }, updated_at: new Date(1e12 + (++g.n) * 1000).toISOString(),
    files: Object.fromEntries(Object.entries(gi.files).map(([k, v]) => [k, { filename: k, content: v, truncated: false }])) });
  const resp = (status, body) => ({ ok: status >= 200 && status < 300, status, json: async () => JSON.parse(JSON.stringify(body)), text: async () => JSON.stringify(body) });
  g.install = (w) => {
    w.fetch = async (url, opts = {}) => {
      const method = (opts.method || 'GET').toUpperCase();
      g.calls.push(method + ' ' + url);
      if (g.fail) return resp(g.fail, {});
      if ((opts.headers || {}).Authorization !== 'token ' + g.token) return resp(401, { message: 'Bad credentials' });
      const m = /^https:\/\/api\.github\.com\/gists(?:\/([^/?#]+))?$/.exec(url);
      if (!m) return resp(404, {});
      const id = m[1];
      if (method === 'POST' && !id){
        const b = JSON.parse(opts.body); const nid = (++g.n).toString(16).padStart(32, 'b');
        g.gists[nid] = { id: nid, description: b.description, files: Object.fromEntries(Object.entries(b.files).map(([k, v]) => [k, v.content])) };
        return resp(201, view(g.gists[nid]));
      }
      const gi = g.gists[id]; if (!gi) return resp(404, {});
      if (method === 'GET') return resp(200, view(gi));
      if (method === 'PATCH'){ const b = JSON.parse(opts.body); for (const [k, v] of Object.entries(b.files)){ if (v === null) delete gi.files[k]; else gi.files[k] = v.content; } return resp(200, view(gi)); }
      if (method === 'DELETE'){ delete g.gists[id]; return { ok: true, status: 204, json: async () => null }; }
      return resp(405, {});
    };
  };
  g.create = (files) => { const id = (++g.n).toString(16).padStart(32, 'c'); g.gists[id] = { id, files }; return id; };
  return g;
}

/* ---------- harness ---------- */
async function open({ width = 400, today = '2026-11-06', storage = null, auth = null, idb = null, hash = '', gh = null, before = null } = {}){
  const dom = new JSDOM(html, {
    runScripts: 'dangerously', pretendToBeVisual: true, url: 'https://localhost/expiry/' + hash,
    beforeParse(w){
      Object.defineProperty(w, 'crypto', { value: webcrypto, configurable: true });
      w.TextEncoder = TextEncoder; w.TextDecoder = TextDecoder;
      Object.defineProperty(w, 'isSecureContext', { value: true });
      w.EXPIRY_TODAY = today;
      w.EXPIRY_PBKDF2_ITER = 1000; // fast tests; real builds use 310 000
      Object.defineProperty(w, 'innerWidth', { value: width, configurable: true });
      w.matchMedia = (q) => { const m = /min-width:\s*(\d+)px/.exec(q); return { matches: m ? width >= +m[1] : false, media: q, addEventListener(){}, removeEventListener(){} }; };
      w.scrollTo = () => {};
      if (auth) auth.install(w);
      w.EXPIRY_NO_AUTOSYNC = true;
      if (gh) gh.install(w);
      if (before) before(w);
      w.indexedDB = idb || new IDBFactory(); w.IDBKeyRange = IDBKeyRange;
      // simulated text reader: tests set w.__ocr = {text, words, mrz} (and optionally a gate promise or an error)
      w.__ocr = { text: '', words: [] };
      w.Tesseract = { createWorker: async () => ({
        recognize: async (img, opts) => { if (w.__ocrGate) await w.__ocrGate; if (w.__ocrError) throw new Error(w.__ocrError);
          return { data: opts && opts.rectangle ? { text: w.__ocr.mrz || '', words: [] } : { text: w.__ocr.text, words: w.__ocr.words || [] } }; },
        setParameters: async () => {}, terminate: async () => {} }) };
      let n = 0; w.__blobs = []; w.URL.createObjectURL = (b) => { w.__blobs.push(b); return 'blob:test/' + (++n); }; w.URL.revokeObjectURL = () => {};
      if (storage) for (const [k, v] of Object.entries(storage)) w.localStorage.setItem(k, v);
    }
  });
  await sleep(40);
  const w = dom.window, d = w.document;
  const a = {
    w, d,
    $: (s) => d.querySelector(s),
    $$: (s) => [...d.querySelectorAll(s)],
    ev: (code) => w.eval(code),
    keepCal: false,
    click: async (sel) => { const el = typeof sel === 'string' ? d.querySelector(sel) : sel; if (!el) throw new Error('missing ' + sel); el.dispatchEvent(new w.MouseEvent('click', { bubbles: true })); await sleep(8);
      // saving offers "Add to calendar"; older tests aren't about that, so close it unless a test wants it
      if (sel === '[data-act="saveDoc"]' && !a.keepCal){ for (let i = 0; i < 200 && w.eval('_saving'); i++) await sleep(10); await sleep(5);
        if (w.eval('!!(topEntry() && topEntry().calendar)')){ d.querySelector('#sheet [data-act="back"]').dispatchEvent(new w.MouseEvent('click', { bubbles: true })); await sleep(5); } } },
    type: async (sel, value) => { const el = typeof sel === 'string' ? d.querySelector(sel) : sel; if (!el) throw new Error('missing ' + sel); el.value = value; el.dispatchEvent(new w.Event('input', { bubbles: true })); await sleep(2); },
    snapshot: async () => { await w.eval('flushSecureWrites()'); const o = {}; for (let i = 0; i < w.localStorage.length; i++){ const k = w.localStorage.key(i); o[k] = w.localStorage.getItem(k); } return o; },
    text: (s) => (d.querySelector(s) || {}).textContent || '',
    waitFor: async (cond, ms = 6000) => { const end = Date.now() + ms; while (Date.now() < end){ try{ if (cond()) return true; }catch(e){} await sleep(15); } return false; },
    visible: (s) => { const el = d.querySelector(s); return !!el && !el.classList.contains('hidden'); },
  };
  return a;
}
async function setup(a, { name = 'Salim', pw = PW, bio = false } = {}){
  if (a.$('#welcome-name')){ await a.type('#welcome-name', name); await a.click('[data-act="setupName"]'); }
  await a.type('#setup-pw1', pw); await a.type('#setup-pw2', pw);
  await a.click('[data-act="setupPassword"]');
  await a.waitFor(() => a.visible('#app') || a.$('[data-act="setupBioOn"]'));
  if (a.$('[data-act="setupBioOn"]')){
    await a.click(bio ? '[data-act="setupBioOn"]' : '[data-act="setupBioSkip"]');
    await a.waitFor(() => a.visible('#app'));
  }
}
async function unlock(a, pw = PW){
  await a.type('#lock-input', pw);
  await a.click('[data-act="unlock"]');
  await a.waitFor(() => a.visible('#app') || /Incorrect/.test(a.text('#lock-error')));
}
async function addDoc(a, { type = 'passport', fields = {}, month = null }){
  await a.click('[data-act="openAdd"]');
  await a.click('[data-act="addMethod"][data-m="manual"]');
  await a.click(`[data-act="draftType"][data-id="${type}"]`);
  for (const [k, v] of Object.entries(fields)) await a.type(`#f-${k}`, v);
  if (month) await a.type('#f-expiry', month);
  await a.click('[data-act="saveDoc"]');
  await a.waitFor(() => !a.ev('_saving'));
  await sleep(10);
}
async function revealWithPassword(a, pw = PW){
  await a.click('[data-act="reveal"]');
  await a.type('#reveal-pw', pw);
  await a.click('[data-act="revealPwd"]');
  await a.waitFor(() => !a.ev('_revealBusy'));
  await sleep(20);
}

async function main(){
  /* ================= document title ================= */
  {
    const D = await open({ idb: new IDBFactory() });
    await setup(D);
    await D.click('[data-act="openAdd"]'); await D.click('[data-act="addMethod"][data-m="manual"]');
    await D.click('[data-act="draftType"][data-id="vehicle-registration"]');
    const ti = D.$('#f-title');
    record('DT1. Editor has a Document title field, max 25, type name as placeholder', !!ti && ti.getAttribute('maxlength') === '25' && ti.placeholder === 'Vehicle registration');
    await D.type('#f-title', 'Jeeb Registration'); await D.type('#f-ref', '83639/H'); await D.type('#f-expiry', '2027-04-19');
    await D.click('[data-act="saveDoc"]'); await D.waitFor(() => !D.ev('_saving')); await sleep(10);
    const doc = JSON.parse(D.ev('JSON.stringify(state.documents[0])'));
    record('DT2. Title is saved with the document', doc.values.title === 'Jeeb Registration');
    record('DT3. Detail page title is the document title, type name in the line below', /Jeeb Registration/.test(D.text('#side-pane')) && /Vehicle registration · Salim/.test(D.text('#side-pane .detail-head')));
    D.ev('closeAllPanes()'); await sleep(10);
    record('DT4. Home list shows the title', D.$$('#doc-list .row-title').some(e => e.textContent === 'Jeeb Registration'));
    const ev = JSON.parse(D.ev(`JSON.stringify(calendarEvents(state.documents[0]))`));
    record('DT5. Calendar keeps the title as typed', ev.length > 0 && ev.every(e => /Jeeb Registration expires/.test(e.title)));
    D.ev(`ui.search='jeeb'; renderHome()`); await sleep(5);
    record('DT6. Search finds it by title', D.$$('#doc-list .row-title').some(e => e.textContent === 'Jeeb Registration'));
    D.ev(`ui.search=''; renderHome()`);
    D.ev(`draft = renewDraft(state.documents[0])`);
    record('DT7. Renewing keeps the title', D.ev('draft.values.title') === 'Jeeb Registration');
    D.ev(`draft = draftFromDoc(state.documents[0]); draft.values.title=''`);
    D.ev(`nav.push({kind:'pane', screen:'edit'}); renderSide(topPane())`); await sleep(5);
    await D.click('[data-act="saveDoc"]'); await D.waitFor(() => !D.ev('_saving')); await sleep(10);
    record('DT8. Clearing the title falls back to the type name', D.ev('state.documents[0].values.title') === undefined && D.ev('docTitle(state.documents[0])') === 'Vehicle registration');
    record('DT9. Titles longer than 25 characters are cut', D.ev(`docTitle({typeId:'other', values:{title:'A'.repeat(40)}})`).length === 25);
  }
  /* ================= pure logic ================= */
  {
    const a = await open();
    const t = (exp, today) => a.ev(`timeLeftLabel(${JSON.stringify(exp)}, parseISO(${JSON.stringify(today)}))`);
    record('U1. time left: 18 days', t('2026-11-24', '2026-11-06') === '18 days');
    record('U2. time left: today / 1 day', t('2026-11-06', '2026-11-06') === 'Today' && t('2026-11-07', '2026-11-06') === '1 day');
    record('U3. time left: months and years', t('2027-04-14', '2026-11-06') === '5 mo' && t('2029-01-01', '2026-11-06') === '2 yrs');
    record('U4. time left: expired', t('2026-10-25', '2026-11-06') === '12d ago' && t('2026-01-01', '2026-11-06') === '10 mo ago');
    record('U5. month shift clamps to month end', a.ev(`toISO(shiftDate(parseISO('2026-05-31'), -1, 'months'))`) === '2026-04-30');
    record('U6. card expiry month → last day of month (leap year)', a.ev(`lastDayOfMonthISO('2027-02')`) === '2027-02-28' && a.ev(`lastDayOfMonthISO('2028-02')`) === '2028-02-29');
    record('U7. invalid dates rejected', a.ev(`parseISO('2026-02-30')`) === null && a.ev(`parseISO('14/04/2027')`) === null);
    const st = (doc) => a.ev(`docStatus(${JSON.stringify(doc)}, parseISO('2026-11-06'))`);
    const base = { typeId: 'insurance', values: {}, reminders: [{ amount: 30, unit: 'days' }], state: 'active' };
    record('U8. status: expired / soon / valid / expiry day', st({ ...base, values: { expiry: '2026-11-05' } }) === 'expired' && st({ ...base, values: { expiry: '2026-12-01' } }) === 'soon' && st({ ...base, values: { expiry: '2027-03-01' } }) === 'valid' && st({ ...base, values: { expiry: '2026-11-06' } }) === 'soon');
    record('U9. status: renewing and archived override dates', st({ ...base, state: 'renewing', values: { expiry: '2020-01-01' } }) === 'renewing' && st({ ...base, state: 'archived', values: { expiry: '2020-01-01' } }) === 'archived');
  }

  /* ================= first run + setup ================= */
  let saved;
  {
    const a = await open();
    record('S1. First run asks for a name; app hidden', a.visible('#welcome') && !!a.$('#welcome-name') && !a.visible('#app'));
    await a.click('[data-act="setupName"]');
    record('S2. Empty name shows an error', a.text('#welcome-err') === 'Enter your name.');
    await a.type('#welcome-name', 'Salim'); await a.click('[data-act="setupName"]');
    record('S3. Next step is creating a password (no skipping)', !!a.$('#setup-pw1') && /Create your password/.test(a.text('#welcome')) && !a.visible('#app'));
    await a.type('#setup-pw1', 'short'); await a.type('#setup-pw2', 'short'); await a.click('[data-act="setupPassword"]');
    record('S4. Password under 8 characters is refused', /at least 8/.test(a.text('#setup-err')));
    await a.type('#setup-pw1', PW); await a.type('#setup-pw2', PW + 'x'); await a.click('[data-act="setupPassword"]');
    record('S5. Mismatched confirmation is refused', /don’t match/.test(a.text('#setup-err')));
    record('S6. Nothing stored before the password exists', (await a.snapshot()).expiry_state === undefined);
    await setup(a);
    const snap = await a.snapshot();
    const stBlob = JSON.parse(snap.expiry_state);
    record('S7. App opens; state stored encrypted with a lock record', a.visible('#app') && stBlob.__enc === 1 && !!snap.expiry_lock_v1);
    record('S8. Nothing readable in storage (no name, no plain JSON)', !Object.values(snap).some(v => /Salim/.test(v)));
    const rec = JSON.parse(snap.expiry_lock_v1);
    record('S9. Lock record holds only wrapped keys, a verifier and the vault public key', rec.dekWrap && rec.skWrap && rec.skPub && rec.hash && !/correct-horse/.test(snap.expiry_lock_v1));
    record('S10. No storage keys outside the expiry_ prefix', Object.keys(snap).every(k => k.startsWith('expiry_')));
    // add a passport for later tests
    await addDoc(a, { type: 'passport', fields: { ref: 'A1234567', issuer: 'Kenya' } });
    await a.type('#f-expiry', '2027-04-14');
    await a.type('#f-note', 'Bring 2 photos');
    await a.click('[data-act="saveDoc"]'); await sleep(20);
    record('A1. Passport saved, detail shows status, note and passed reminders', /Expiring soon · 5 mo/.test(a.text('#side-pane')) && /Bring 2 photos/.test(a.text('#side-pane')) && a.$$('#side-pane .tag').filter(t => t.textContent === 'passed').length === 2);
    await addDoc(a, { type: 'bank-card', fields: { cardName: 'Visa debit', ref: '4111 2233 4455 4021', issuer: 'Equity Bank' }, month: '2027-01' });
    await sleep(30);
    const card = JSON.parse(a.ev(`JSON.stringify(state.documents.find(d=>d.typeId==='bank-card'))`));
    record('A2. Card number is sealed, never kept in plain values', !card.values.ref && card.sealed.ref && card.sealed.ref.ek && card.masks.ref === '4021');
    record('A3. Month expiry stored as last day of month', card.values.expiry === '2027-01-31');
    record('A4. Detail and Home show only •••• 4021', /•••• 4021/.test(a.text('#side-pane')) && !/4111/.test(a.text('#side-pane')) && /•••• 4021/.test(a.text('#doc-list')));
    saved = await a.snapshot();
    record('A5. Card number and passport number not present in storage', !Object.values(saved).some(v => /4111|A1234567/.test(v)));
  }

  /* ================= lock screen ================= */
  {
    const a = await open({ storage: saved });
    record('L1. Reload shows the lock screen, content hidden from first paint', a.visible('#lock-screen') && a.d.documentElement.classList.contains('is-locked') && !a.visible('#app') && a.$$('#doc-list .row').length === 0);
    await a.click('[data-act="unlock"]');
    record('L2. Empty password → message', /Enter your password/.test(a.text('#lock-error')));
    await unlock(a, 'wrong-password');
    record('L3. Wrong password refused', /Incorrect password/.test(a.text('#lock-error')) && !a.visible('#app'));
    await unlock(a);
    record('L4. Right password opens the app with the documents', a.visible('#app') && a.$$('#doc-list .row').length === 2 && !a.d.documentElement.classList.contains('is-locked'));
    await a.click('#doc-list .row');
    await a.click('[data-act="openSettings"]');
    await a.click('[data-act="lockNow"]'); await sleep(30);
    record('L5. Lock now clears documents from memory and the screen', a.visible('#lock-screen') && a.ev('state.documents.length') === 0 && !/Passport|Visa/.test(a.text('#app')) && a.ev('nav.length') === 0);
    await unlock(a);
    record('L6. Unlock again works', a.visible('#app') && a.ev('state.documents.length') === 2);
    // auto-lock after idle
    a.ev('_lastActive = Date.now() - 6*60000');
    Object.defineProperty(a.d, 'visibilityState', { value: 'visible', configurable: true });
    a.d.dispatchEvent(new a.w.Event('visibilitychange')); await sleep(30);
    record('L7. Auto-lock after 5 idle minutes (default)', a.visible('#lock-screen') && a.ev('_locked') === true);
    await unlock(a);
    a.ev(`setAutoLock('leave')`);
    Object.defineProperty(a.d, 'visibilityState', { value: 'hidden', configurable: true });
    a.d.dispatchEvent(new a.w.Event('visibilitychange')); await sleep(30);
    record('L8. "When I leave the app" locks on leaving', a.ev('_locked') === true);
    Object.defineProperty(a.d, 'visibilityState', { value: 'visible', configurable: true });
  }

  /* ================= reveal ================= */
  {
    const a = await open({ storage: saved });
    await unlock(a);
    const cardRow = a.$$('#doc-list .row').find(r => /Visa debit/.test(r.textContent));
    await a.click(cardRow);
    await a.click('[data-act="reveal"]');
    record('R1. Reveal asks for fingerprint or password', /Unlock sensitive info/.test(a.text('#sheet')) && /card number/.test(a.text('#sheet')));
    await a.type('#reveal-pw', 'nope'); await a.click('[data-act="revealPwd"]'); await a.waitFor(() => !a.ev('_revealBusy'));
    record('R2. Wrong password → not revealed', /Incorrect/.test(a.text('#reveal-err')) && !/4111/.test(a.text('#side-pane')));
    await a.type('#reveal-pw', PW); await a.click('[data-act="revealPwd"]'); await a.waitFor(() => !a.ev('_revealBusy')); await sleep(20);
    record('R3. Right password reveals the full number with a countdown', /4111 2233 4455 4021/.test(a.text('#side-pane')) && a.visible('#reveal-bar') && /hides in/.test(a.text('#reveal-bar')));
    record('R4. Home list still shows only the last 4', !/4111/.test(a.text('#doc-list')));
    await a.click('[data-act="editDoc"]');
    record('R5. Editing while revealed prefills the number', a.$('#f-ref').value === '4111 2233 4455 4021');
    await a.click('[data-act="saveDoc"]'); await a.waitFor(() => !a.ev('_saving')); await sleep(10);
    const sealedBefore = a.ev(`state.documents.find(d=>d.typeId==='bank-card').sealed.ref.ek`);
    await a.click('[data-act="hideReveal"]');
    record('R6. Hide now masks it again and forgets the key', !/4111/.test(a.text('#side-pane')) && a.ev('_skPriv') === null && a.ev('Object.keys(_plain).length') === 0);
    await a.click('[data-act="editDoc"]');
    record('R7. Editing while hidden leaves the number empty with a keep hint', a.$('#f-ref').value === '' && /•••• 4021 · leave empty to keep/.test(a.$('#f-ref').placeholder));
    await a.type('#f-issuer', 'Equity Bank Kenya');
    await a.click('[data-act="saveDoc"]'); await a.waitFor(() => !a.ev('_saving')); await sleep(10);
    record('R8. Saving without retyping keeps the sealed number', a.ev(`state.documents.find(d=>d.typeId==='bank-card').sealed.ref.ek`) === sealedBefore && /•••• 4021/.test(a.text('#side-pane')));
    await a.click('[data-act="editDoc"]');
    await a.type('#f-ref', '5500 0000 0000 9999');
    await a.click('[data-act="saveDoc"]'); await a.waitFor(() => !a.ev('_saving')); await sleep(10);
    record('R9. Typing a new number reseals it with the new last 4', /•••• 9999/.test(a.text('#side-pane')));
    await revealWithPassword(a);
    record('R10. The new number decrypts correctly', /5500 0000 0000 9999/.test(a.text('#side-pane')));
    Object.defineProperty(a.d, 'visibilityState', { value: 'hidden', configurable: true });
    a.ev(`setAutoLock('0')`);
    a.d.dispatchEvent(new a.w.Event('visibilitychange')); await sleep(10);
    record('R11. Leaving the app re-hides sensitive info', !/5500 0000/.test(a.text('#side-pane')) && a.ev('_skPriv') === null);
    Object.defineProperty(a.d, 'visibilityState', { value: 'visible', configurable: true });
    await a.click('[data-act="back"]');
    await a.click('[data-act="toggleSearch"]');
    await a.type('#search-input', '9999');
    record('R12. Search never matches sensitive values', a.$$('#doc-list .row').length === 0);
    await a.type('#search-input', '');
    // ask every time
    await a.click('[data-act="openSettings"]');
    await a.click('[data-act="revealMode"][data-m="each"]');
    await a.click('[data-act="closePanes"]');
    await a.click(a.$$('#doc-list .row').find(r => /Visa debit/.test(r.textContent)));
    await revealWithPassword(a);
    const revealedEach = /5500 0000 0000 9999/.test(a.text('#side-pane'));
    await a.click('[data-act="back"]');
    await a.click(a.$$('#doc-list .row').find(r => /Visa debit/.test(r.textContent)));
    record('R13. "Ask every time": leaving the document hides it again', revealedEach && !/5500 0000/.test(a.text('#side-pane')) && a.ev('_skPriv') === null);
    record('R14. Reveal window lasts 60 seconds', a.ev('(()=>{ return 60; })()') === 60 && /revealUntil = Date.now\(\) \+ 60\*1000/.test(html));
  }

  /* ================= change password ================= */
  {
    const a = await open({ storage: saved });
    await unlock(a);
    await a.click('[data-act="openSettings"]');
    await a.click('[data-act="changePassword"]');
    const fill = async (v) => { for (let i = 0; i < v.length; i++) await a.type('#pwd-in-' + i, v[i]); await a.click('[data-act="pwdOk"]'); await a.waitFor(() => !(a.ev('topEntry()') && a.ev('topEntry()').busy)); await sleep(10); };
    await fill(['wrong-one', 'new-password-9', 'new-password-9']);
    record('C1. Wrong current password refused, dialog stays open', /incorrect/.test(a.text('#pwd-error')) && a.visible('#sheet'));
    await fill([PW, 'new-password-9', 'new-password-9']);
    record('C2. Password changed', !a.visible('#sheet') && /Password changed/.test(a.text('#toast')));
    const snap = await a.snapshot();
    const b = await open({ storage: snap });
    await unlock(b, PW);
    record('C3. Old password no longer works', /Incorrect/.test(b.text('#lock-error')));
    await unlock(b, 'new-password-9');
    record('C4. New password opens the same data', b.visible('#app') && b.ev('state.documents.length') === 2);
    await b.click(b.$$('#doc-list .row').find(r => /Visa debit/.test(r.textContent)));
    await revealWithPassword(b, 'new-password-9');
    record('C5. Sensitive values still reveal with the new password', /4111 2233 4455 4021/.test(b.text('#side-pane')));
  }

  /* ================= M1 data upgrade ================= */
  {
    const m1 = { version: 1, profiles: [{ id: 'p1', name: 'Salim', relation: 'You', color: 'violet', isSelf: true }], types: [], settings: { theme: 'midnight' },
      documents: [{ id: 'd1', typeId: 'bank-card', ownerId: 'p1', values: { cardName: 'Old card', ref: '4000 1111 2222 3333', expiry: '2027-05-31' }, reminders: [{ id: 'r', amount: 30, unit: 'days' }], state: 'active', history: [] }] };
    const a = await open({ storage: { expiry_state: JSON.stringify(m1) } });
    record('M1. Unencrypted M1 data → "Protect your documents" before anything else', /Protect your documents/.test(a.text('#welcome')) && !a.visible('#app'));
    await setup(a);
    const snap = await a.snapshot();
    record('M2. After the password, storage is encrypted and the number sealed', JSON.parse(snap.expiry_state).__enc === 1 && !Object.values(snap).some(v => /4000 1111|Salim/.test(v)));
    record('M3. The old card shows masked', /•••• 3333/.test(a.text('#doc-list')) && a.ev(`state.documents[0].values.ref`) === undefined);
  }

  /* ================= broken + erase ================= */
  {
    const enc = { expiry_state: JSON.parse(saved.expiry_state) ? saved.expiry_state : '' };
    const a = await open({ storage: enc });
    record('B1. Encrypted data without its lock record stays locked and untouched', a.visible('#lock-screen') && /lock settings are missing/.test(a.text('#lock-screen')) && a.w.localStorage.getItem('expiry_state') === saved.expiry_state);
    const b = await open({ storage: saved });
    await b.click('[data-act="lockForgot"]');
    record('B2. Forgot password explains there is no recovery', b.visible('#lock-forgot') && /no way to recover/.test(b.text('#lock-forgot')));
    await b.click('[data-act="eraseDevice"]');
    const snap = await b.snapshot();
    record('B3. Erase removes everything and starts setup again', Object.keys(snap).length === 0 && !!b.$('#welcome-name'));
  }

  /* ================= fingerprint ================= */
  {
    const auth = makeAuthenticator();
    const a = await open({ auth });
    await a.type('#welcome-name', 'Salim'); await a.click('[data-act="setupName"]');
    await a.type('#setup-pw1', PW); await a.type('#setup-pw2', PW); await a.click('[data-act="setupPassword"]');
    await a.waitFor(() => !!a.$('[data-act="setupBioOn"]'));
    record('F1. Setup offers fingerprint when the phone supports it', /Unlock with your fingerprint/.test(a.text('#welcome')));
    await a.click('[data-act="setupBioOn"]'); await a.waitFor(() => a.visible('#app'));
    const bio = JSON.parse(a.w.localStorage.getItem('expiry_bio') || 'null');
    record('F2. Passkey created; both keys wrapped under its PRF secret', !!bio && bio.prf && bio.dekWrap && bio.skWrap && auth.calls.includes('create'));
    await addDoc(a, { type: 'bank-card', fields: { cardName: 'Visa', ref: '4242 4242 4242 4242' }, month: '2028-03' });
    await sleep(20);
    auth.calls.length = 0;
    await a.click('[data-act="reveal"]'); await sleep(60);
    record('F3. Reveal goes straight to the fingerprint and reveals', auth.calls.includes('get') && /4242 4242 4242 4242/.test(a.text('#side-pane')));
    const snap = await a.snapshot();
    const b = await open({ storage: snap, auth });
    await sleep(350);
    record('F4. Reload: fingerprint unlocks automatically', b.visible('#app') && b.ev('state.documents.length') === 1);
    for (const mode of ['badOrigin', 'noUV', 'badSig', 'cancel']){
      auth.mode = mode;
      const c = await open({ storage: snap, auth });
      await sleep(350);
      record(`F5. Fingerprint rejected when ${mode}`, c.visible('#lock-screen') && !c.visible('#app') && c.text('#lock-error').length > 0, c.text('#lock-error'));
    }
    auth.mode = 'ok';
    const c = await open({ storage: snap, auth });
    await sleep(350);
    await c.click('[data-act="openSettings"]');
    await c.click('[data-act="bioOff"]');
    await c.click('#sheet [data-act="sheetChoice"][data-i="0"]');
    record('F6. Turning fingerprint off removes it', c.w.localStorage.getItem('expiry_bio') === null && /Off/.test(c.text('#side-pane')));
  }

  /* ================= attachments (M3) ================= */
  {
    const idb = new IDBFactory();
    const a = await open({ idb });
    await setup(a);
    const file = (name, type, text) => new a.w.File([Buffer.from(text)], name, { type });
    const dbRecords = () => a.w.eval(`idbReq('readonly', st=>st.getAll())`);
    // new document from photos
    await a.click('[data-act="openAdd"]');
    await a.click('[data-act="addMethod"][data-m="photo"]');
    record('I1. Choose photo targets a new document', a.ev('JSON.stringify(_pickTarget)') === '{"mode":"new"}');
    await a.w.onFilesPicked([file('front.jpg', 'image/jpeg', 'FRONT-IMAGE-BYTES-4111'), file('back.jpg', 'image/jpeg', 'BACK-IMAGE-BYTES')]);
    await sleep(20);
    record('I2. Editor opens with Front and Back pages pending', !!a.$('#f-expiry') && a.$$('#side-pane [data-act="removePending"]').length === 2 && /Front/.test(a.text('#side-pane')) && /Back/.test(a.text('#side-pane')));
    await a.click('[data-act="draftType"][data-id="bank-card"]');
    record('I3. Bank card type says images are locked', /images are locked/.test(a.text('#side-pane')));
    record('I4. Nothing stored before saving', (await dbRecords()).length === 0);
    await a.type('#f-cardName', 'Visa'); await a.type('#f-ref', '4111 1111 1111 1111'); await a.type('#f-expiry', '2028-02');
    await a.click('[data-act="saveDoc"]'); await a.waitFor(() => !a.ev('_saving')); await sleep(30);
    const card = JSON.parse(a.ev(`JSON.stringify(state.documents[0].attachments)`));
    let recs = await dbRecords();
    record('I5. Saved: 2 sensitive attachments, sealed in the file store, no thumbnails', card.length === 2 && card.every(x => x.sensitive && !x.hasThumb) && recs.length === 2 && recs.every(r => r.mode === 'vault' && r.ek));
    record('I6. Stored bytes are ciphertext', !recs.some(r => Buffer.from(new Uint8Array(r.ct)).toString().includes('FRONT-IMAGE')));
    record('I7. Detail shows locked tiles', a.$$('#side-pane .tile .ti-lock').length === 2 && /Locked images need your fingerprint/.test(a.text('#side-pane')));
    await a.click('#side-pane .tile[data-act="openAtt"]');
    record('I8. Opening a locked image asks to reveal', /Unlock sensitive info/.test(a.text('#sheet')));
    await a.type('#reveal-pw', PW); await a.click('[data-act="revealPwd"]'); await a.waitFor(() => !a.ev('_revealBusy')); await sleep(30);
    record('I9. After reveal the tiles show the images', a.$$('#side-pane .tile img[data-variant="full"]').length === 2);
    const bytes = await a.w.eval(`readFile(state.documents[0].attachments[0].id).then(b=>Array.from(b))`);
    record('I10. Decrypted bytes match the original', Buffer.from(bytes).toString() === 'FRONT-IMAGE-BYTES-4111');
    await a.click('#side-pane .tile[data-act="openAtt"]'); await sleep(30);
    record('I11. Viewer opens full screen with the image', a.$('#sheet').classList.contains('viewer-mode') && !!a.$('#viewer-body img.viewer-img') && /1 of 2/.test(a.text('#sheet')));
    await a.click('[data-act="viewerStep"][data-d="1"]'); await sleep(30);
    record('I12. Next goes to the Back page', /Back/.test(a.text('.viewer-title')) && /2 of 2/.test(a.text('#sheet')));
    await a.click('[data-act="hideReveal"]'); await sleep(10);
    record('I13. Hiding closes the sensitive viewer and forgets the image URLs', !a.visible('#sheet') && a.ev('Object.keys(_urls).length') === 0);
    // add a non-sensitive document with a PDF via detail
    await a.click('[data-act="back"]');
    await addDoc(a, { type: 'insurance', fields: { ref: 'POL-1' } }); await a.type('#f-expiry', '2027-01-01'); await a.click('[data-act="saveDoc"]'); await a.waitFor(() => !a.ev('_saving')); await sleep(20);
    const insId = a.ev(`state.documents.find(d=>d.typeId==='insurance').id`);
    await a.click(`[data-act="addPages"]`);
    record('I14. Add on the document offers camera, gallery and file', a.$$('#sheet [data-act="pickSource"]').length === 3);
    await a.click('[data-act="pickSource"][data-s="file"]');
    await a.w.onFilesPicked([file('policy.pdf', 'application/pdf', '%PDF-1.4 POLICY'), file('notes.txt', 'text/plain', 'x')]);
    await sleep(40);
    const ins = JSON.parse(a.ev(`JSON.stringify(docById(${JSON.stringify(insId)}).attachments)`));
    recs = await dbRecords();
    record('I15. PDF stored under the data key (not sensitive); non-image files refused', ins.length === 1 && ins[0].kind === 'pdf' && !ins[0].sensitive && ins[0].label === 'policy' && recs.find(r => r.id === ins[0].id).mode === 'dek' && /Added 1 file\. notes\.txt isn’t an image or PDF/.test(a.text('#toast')), a.text('#toast'));
    await a.click('#side-pane .tile[data-act="openAtt"]'); await sleep(60);
    record('I16. Non-sensitive file opens without a prompt (PDF falls back gracefully offline)', a.$('#sheet').classList.contains('viewer-mode') && /PDF viewer couldn’t load|Opening/.test(a.text('#viewer-body')));
    // options: rename, sensitive, delete
    await a.click('[data-act="attMenu"]');
    await a.click('#sheet [data-act="sheetChoice"][data-i="0"]');
    await a.type('#att-label', 'Policy schedule'); await a.click('#sheet [data-act="sheetChoice"][data-i="0"]'); await sleep(10);
    record('I17. Rename', a.ev(`docById(${JSON.stringify(insId)}).attachments[0].label`) === 'Policy schedule' && /Policy schedule/.test(a.text('.viewer-title')));
    await a.click('[data-act="attMenu"]');
    await a.click('#sheet [data-act="sheetChoice"][data-i="1"]'); await sleep(60);
    recs = await dbRecords();
    record('I18. Treat as sensitive re-seals it', a.ev(`docById(${JSON.stringify(insId)}).attachments[0].sensitive`) === true && recs.find(r => r.id === ins[0].id).mode === 'vault' && !a.visible('#sheet'));
    await a.click('#side-pane .tile[data-act="openAtt"]');
    await a.type('#reveal-pw', PW); await a.click('[data-act="revealPwd"]'); await a.waitFor(() => !a.ev('_revealBusy')); await sleep(20);
    await a.click('#side-pane .tile[data-act="openAtt"]'); await sleep(40);
    await a.click('[data-act="attMenu"]');
    await a.click('#sheet [data-act="sheetChoice"][data-i="2"]');
    await a.click('#sheet [data-act="sheetChoice"][data-i="0"]'); await sleep(30);
    recs = await dbRecords();
    record('I19. Delete removes the file from storage', a.ev(`docById(${JSON.stringify(insId)}).attachments.length`) === 0 && !recs.some(r => r.id === ins[0].id));
    await a.click('[data-act="hideReveal"]');
    // big pdf refused
    await a.click('[data-act="addPages"]'); await a.click('[data-act="pickSource"][data-s="file"]');
    const big = new a.w.File([Buffer.alloc(16 * 1024 * 1024)], 'huge.pdf', { type: 'application/pdf' });
    await a.w.onFilesPicked([big]); await sleep(30);
    record('I20. PDFs over 15 MB are refused', /larger than 15 MB/.test(a.text('#toast')) && a.ev(`docById(${JSON.stringify(insId)}).attachments.length`) === 0);
    // discarding a new draft stores nothing
    const before = (await dbRecords()).length;
    record('I20b. Chooser closes even when every file is refused', !a.visible('#sheet'));
    await a.click('#side-pane [data-act="back"]');
    await a.click('[data-act="openAdd"]'); await a.click('[data-act="addMethod"][data-m="photo"]');
    await a.w.onFilesPicked([file('x.jpg', 'image/jpeg', 'DISCARD-ME')]); await sleep(20);
    await a.click('#side-pane [data-act="back"]');
    record('I21a. Leaving a new document with photos asks to discard', /Discard changes/.test(a.text('#sheet')));
    await a.click('#sheet [data-act="sheetChoice"][data-i="0"]'); await sleep(20);
    record('I21. Discarding a new document stores no files', (await dbRecords()).length === before && !a.ev('draft'));
    // persistence across reload + lock
    const snap = await a.snapshot();
    const b = await open({ storage: snap, idb });
    await unlock(b);
    const cardId = b.ev(`state.documents.find(d=>d.typeId==='bank-card').id`);
    await b.click(b.$$('#doc-list .row').find(r => /Visa/.test(r.textContent)));
    await revealWithPassword(b);
    const again = await b.w.eval(`readFile(docById(${JSON.stringify(cardId)}).attachments[1].id).then(x=>Array.from(x))`);
    record('I22. After reload and unlock, files still decrypt', Buffer.from(again).toString() === 'BACK-IMAGE-BYTES');
    await b.click('[data-act="openSettings"]'); await b.click('[data-act="lockNow"]'); await sleep(30);
    let lockedRead = 'ok'; try { await b.w.eval(`readFile(${JSON.stringify(a.ev('state.documents[0].attachments[0].id'))})`); } catch (e) { lockedRead = e.message; }
    record('I23. While locked, files can’t be read and URLs are gone', lockedRead === 'locked' && b.ev('Object.keys(_urls).length') === 0);
    await unlock(b);
    await b.click(b.$$('#doc-list .row').find(r => /Visa/.test(r.textContent)));
    await b.click('[data-act="docMore"]'); await b.click('#sheet [data-act="sheetChoice"][data-i="2"]'); await b.click('#sheet [data-act="sheetChoice"][data-i="0"]'); await sleep(30);
    const left = await b.w.eval(`idbReq('readonly', st=>st.getAll())`);
    record('I24. Deleting a document deletes its files', left.length === 0);
    await a.w.eval('_dbP && _dbP.then(db=>db.close())'); // the earlier window's connection (one window in real use)
    await b.click('[data-act="openSettings"]'); await b.click('[data-act="eraseAll"]'); await b.click('#sheet [data-act="sheetChoice"][data-i="0"]'); await sleep(40);
    const dbs = await idb.databases();
    record('I25. Erase all deletes the file store too', !dbs.some(d => d.name === 'expiry_files'));
  }

  /* ================= scanning (M4) ================= */
  const TD3 = 'P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C36UTO7408122F1204159ZE184226B<<<<<10';
  const TD1 = 'I<UTOD231458907<<<<<<<<<<<<<<<\n7408122F1204159UTO<<<<<<<<<<<6\nERIKSSON<<ANNA<MARIA<<<<<<<<<<';
  {
    const a = await open();
    const J = (code) => JSON.parse(a.ev(`JSON.stringify(${code})`));
    const td3 = J(`findMrz(${JSON.stringify(TD3)})`);
    record('K1. Passport code strip (ICAO sample): number + expiry verified by check digits', td3.type === 'passport' && td3.ref === 'L898902C3' && td3.refOk && td3.expiry === '2012-04-15' && td3.expiryOk && td3.issuer === 'UTO' && td3.names.given === 'ANNA MARIA', JSON.stringify(td3));
    const noisy = TD3.replace('L898902C36UTO7408122F1204159', 'L898902C36UTO74O8122F12O4159').replace(/</g, (c, i) => i % 7 ? '<' : '«');
    const n3 = J(`findMrz(${JSON.stringify(noisy)})`);
    record('K2. Common misreads (O for 0, « for <) are corrected', n3 && n3.expiry === '2012-04-15' && n3.expiryOk && n3.refOk, JSON.stringify(n3));
    const bad = J(`findMrz(${JSON.stringify(TD3.replace('L898902C36', 'L898903C36'))})`);
    record('K3. A wrong document number fails its check digit (marked Check, not Verified)', bad && bad.refOk === false && bad.expiryOk === true);
    const td1 = J(`findMrz(${JSON.stringify(TD1)})`);
    record('K4. ID card code strip (TD1)', td1.type === 'national-id' && td1.ref === 'D23145890' && td1.refOk && td1.expiry === '2012-04-15' && td1.expiryOk, JSON.stringify(td1));
    record('K5. Card numbers need a valid Luhn check digit', a.ev(`luhn('4111111111111111')`) === true && a.ev(`luhn('4111111111111112')`) === false && J(`findCardNumber('EQUITY 4111 1111 1111 1111 VALID')`).value === '4111 1111 1111 1111' && a.ev(`findCardNumber('ref 1234 5678 9012 3456')`) === null);
    record('K6. Card expiry: the later MM/YY wins (valid from vs thru)', J(`findCardExpiry('VALID FROM 09/23 VALID THRU 09/28')`).iso === '2028-09-30');
    const d1 = J(`findDates('Date of expiry 14 APR/AVR 2027', 'DMY')`);
    record('K7. Dates: 14 APR/AVR 2027', d1.length === 1 && d1[0].iso === '2027-04-14');
    const d2 = J(`findDates('valid until 03/04/2027', 'DMY')`);
    const d3 = J(`findDates('valid until 03/04/2027', 'MDY')`);
    record('K8. Ambiguous 03/04/2027: day-first by default, alternative kept; month-first setting flips it', d2[0].iso === '2027-04-03' && d2[0].alt === '2027-03-04' && d3[0].iso === '2027-03-04' && d3[0].alt === '2027-04-03');
    record('K9. Unambiguous 25/11/2025 has no alternative; 2026-11-24 ISO form read', J(`findDates('25/11/2025 and 2026-11-24', 'DMY')`).map(x => x.iso + (x.alt ? '*' : '')).join(',') === '2025-11-25,2026-11-24');
    const ins = J(`analyzeText('JUBILEE INSURANCE COMPANY\\nCertificate of Insurance\\nPolicy No: POL-8841\\nPeriod of cover 25/11/2025 to 24/11/2026\\n', [], {dateFormat:'DMY'})`);
    record('K10. Insurance certificate: type, policy no., insurer, period end as expiry', ins.type === 'insurance' && ins.fields.ref.value === 'POL-8841' && ins.fields.expiry.value === '2026-11-24' && ins.fields.issueDate.value === '2025-11-25' && /Jubilee Insurance/.test(ins.fields.issuer.value), JSON.stringify(ins.fields));
    const veh = J(`analyzeText('REPUBLIC OF KENYA\\nMOTOR VEHICLE LOG BOOK\\nRegistration No. KDA 123X\\nDate of birth 01/01/1980\\nInspection due 01/12/2026', [], {})`);
    record('K11. Logbook: plate number, birth dates ignored', veh.type === 'vehicle-registration' && veh.fields.ref.value === 'KDA 123X' && veh.fields.expiry.value === '2026-12-01', JSON.stringify(veh.fields));
    const pp = J(`analyzeText(${JSON.stringify('PASSPORT\nDate of issue 15 APR 2017\n' + TD3)}, [{text:'L898902C36UTO7408122F1204159ZE184226B<<<<<10', bbox:{x0:10,y0:900,x1:1900,y1:950}, page:0}], {})`);
    record('K12. Passport: code strip values Verified, issue date from text marked Check, box points at the strip', pp.type === 'passport' && pp.fields.ref.source === 'verified' && pp.fields.expiry.source === 'verified' && pp.fields.issueDate.value === '2017-04-15' && pp.fields.issueDate.source === 'check' && pp.fields.expiry.box.bbox.y0 === 900 && pp.fields.issuer.value === 'Utopia');
  }
  {
    const a = await open();
    await setup(a);
    // a second profile whose first name matches the passport's given name
    a.ev(`state.profiles.push({id:'pa', name:'Anna Eriksson', relation:'Spouse', color:'teal'}); save();`);
    const img = (name) => new a.w.File([Buffer.from('IMG-' + name)], name, { type: 'image/jpeg' });
    a.w.__ocr = { text: 'UTOPIA PASSPORT\nDate of issue 15 APR 2017\n' + TD3, words: [] };
    await a.click('[data-act="openAdd"]');
    await a.click('[data-act="addMethod"][data-m="photo"]');
    await a.w.onFilesPicked([img('p.jpg')]);
    await a.waitFor(() => a.ev('draft && draft.scan && draft.scan.status') === 'done');
    await sleep(20);
    record('X1. Photo is read: Check details form, passport chosen, owner matched from the code strip', /Check details/.test(a.text('#side-pane .topbar')) && a.ev('draft.typeId') === 'passport' && a.ev('draft.ownerId') === 'pa');
    record('X2. Fields filled with Verified / Check badges', a.$('#f-ref').value === 'L898902C3' && a.$('#f-expiry').value === '2012-04-15' && a.$('#f-issueDate').value === '2017-04-15' && a.$$('#side-pane .src.ok').length >= 2 && a.$$('#side-pane .field .src.chk').length >= 2);
    record('X3. Status says how many details were found', /Found 4 details/.test(a.text('#scan-status')));
    await a.type('#f-ref', 'L898902C3X');
    record('X4. Editing a field removes its badge (you confirmed it)', !a.$('#f-ref').closest('.field').querySelector('.src'));
    await a.click('[data-act="saveDoc"]'); await a.waitFor(() => !a.ev('_saving')); await sleep(20);
    record('X5. Saves with the image attached', a.ev('state.documents.length') === 1 && a.ev('state.documents[0].attachments.length') === 1 && a.ev('state.documents[0].ownerId') === 'pa');
    // bank card
    a.w.__ocr = { text: 'EQUITY BANK\n4111 1111 1111 1111\nVALID THRU 09/28\nSALIM', words: [{ text: '4111', bbox: { x0: 100, y0: 300, x1: 220, y1: 340 }, page: 0 }, { text: '1111', bbox: { x0: 230, y0: 300, x1: 350, y1: 340 }, page: 0 }] };
    await a.click('[data-act="back"]').catch(() => {});
    await a.click('[data-act="openAdd"]'); await a.click('[data-act="addMethod"][data-m="photo"]');
    await a.w.onFilesPicked([img('card.jpg')]);
    await a.waitFor(() => a.ev('draft && draft.scan && draft.scan.status') === 'done'); await sleep(20);
    record('X6. Bank card read: type, number, month expiry, bank', a.ev('draft.typeId') === 'bank-card' && a.$('#f-ref').value === '4111 1111 1111 1111' && a.$('#f-expiry').value === '2028-09' && a.$('#f-issuer').value === 'Equity Bank');
    record('X7. Read area recorded for the highlight', a.ev('JSON.stringify(draft.scan.boxes.ref.bbox)') === '{"x0":100,"y0":300,"x1":350,"y1":340}');
    await a.type('#f-cardName', 'Equity Visa');
    await a.click('[data-act="saveDoc"]'); await a.waitFor(() => !a.ev('_saving')); await sleep(20);
    const card = JSON.parse(a.ev(`JSON.stringify(state.documents.find(d=>d.typeId==='bank-card'))`));
    record('X8. Scanned card number is sealed like a typed one', !card.values.ref && card.sealed.ref && card.masks.ref === '1111' && card.values.expiry === '2028-09-30');
    // ambiguous date + swap
    a.w.__ocr = { text: 'MADISON INSURANCE\nPolicy No: MI-2201\nExpiry date: 03/04/2027', words: [] };
    await a.click('[data-act="back"]').catch(() => {});
    await a.click('[data-act="openAdd"]'); await a.click('[data-act="addMethod"][data-m="photo"]');
    await a.w.onFilesPicked([img('ins.jpg')]);
    await a.waitFor(() => a.ev('draft && draft.scan && draft.scan.status') === 'done'); await sleep(20);
    record('X9. Ambiguous date is flagged with the other reading', a.$('#f-expiry').value === '2027-04-03' && /could also be 4 Mar 2027/.test(a.text('#side-pane')));
    await a.click('[data-act="swapDate"]');
    record('X10. One tap swaps to the other reading', a.$('#f-expiry').value === '2027-03-04' && /could also be 3 Apr 2027/.test(a.text('#side-pane')));
    await a.click('[data-act="back"]'); await a.click('#sheet [data-act="sheetChoice"][data-i="0"]'); await sleep(10);
    // you type before the reader finishes: never overwritten
    let release; a.w.__ocrGate = new Promise(r => { release = r; });
    a.w.__ocr = { text: 'Policy No: AUTO-1\nExpiry: 24/11/2026\nINSURANCE', words: [] };
    await a.click('[data-act="openAdd"]'); await a.click('[data-act="addMethod"][data-m="photo"]');
    await a.w.onFilesPicked([img('x.jpg')]); await sleep(20);
    record('X11. While reading, a progress message shows', /Reading details on this phone/.test(a.text('#scan-status')));
    await a.click('[data-act="draftType"][data-id="insurance"]');
    await a.type('#f-ref', 'TYPED-BY-ME');
    release(); a.w.__ocrGate = null;
    await a.waitFor(() => a.ev('draft && draft.scan && draft.scan.status') === 'done'); await sleep(30);
    record('X12. What you typed is never overwritten; empty fields still fill', a.$('#f-ref').value === 'TYPED-BY-ME' && a.$('#f-expiry').value === '2026-11-24');
    await a.click('[data-act="back"]'); await a.click('#sheet [data-act="sheetChoice"][data-i="0"]'); await sleep(10);
    // reader failure
    a.w.__ocrError = 'boom';
    await a.click('[data-act="openAdd"]'); await a.click('[data-act="addMethod"][data-m="photo"]');
    await a.w.onFilesPicked([img('y.jpg')]);
    await a.waitFor(() => a.ev('draft && draft.scan && draft.scan.status') === 'failed'); await sleep(20);
    record('X13. If reading fails you can still type the details', /Couldn’t read the details/.test(a.text('#scan-status')) && !!a.$('#f-expiry') && a.$('#f-expiry').value === '');
    a.w.__ocrError = null;
    await a.click('[data-act="back"]'); await a.click('#sheet [data-act="sheetChoice"][data-i="0"]'); await sleep(10);
    // live scanner without a camera
    await a.click('[data-act="openAdd"]'); await a.click('[data-act="addMethod"][data-m="scan"]'); await sleep(30);
    record('X14. Scanner opens full screen; without a camera it offers the camera app instead', a.$('#sheet').classList.contains('viewer-mode') && !!a.$('#scan-video') && /live camera isn’t available/.test(a.text('#scan-msg')) && !!a.$('#scan-msg [data-act="scanFallback"]'));
    await a.click('#sheet [data-act="back"]');
    record('X15. Cancel closes the scanner', !a.visible('#sheet'));
    // settings: date format
    await a.click('[data-act="openSettings"]');
    await a.click('[data-act="dateFormat"][data-f="MDY"]');
    record('X16. Date format setting saved', a.ev('state.settings.dateFormat') === 'MDY');
    // lock stops the reader
    await a.click('[data-act="lockNow"]'); await sleep(20);
    record('X17. Locking stops the camera and the reader', a.ev('_camStream') === null && a.ev('_workerP') === null);
  }

  /* ================= calendar reminders (M5) ================= */
  {
    const a = await open();
    await setup(a);
    a.keepCal = true;
    a.ev(`state.profiles.push({id:'pa', name:'Amina Aufi', relation:'Spouse', color:'teal'}); save();`);
    const lastIcs = async () => { const b = a.w.__blobs.filter(x => x.type === 'text/calendar').pop(); return b ? await b.text() : ''; };
    // passport whose reminder dates have all passed
    await addDoc(a, { type: 'passport', fields: { ref: 'A1234567', issuer: 'Kenya' } });
    await a.type('#f-expiry', '2027-04-14'); await a.click('[data-act="saveDoc"]'); await a.waitFor(() => !a.ev('_saving')); await sleep(20);
    const pid = a.ev(`state.documents[0].id`);
    record('Q1. After adding a document, the calendar is offered', /Add reminders to your calendar/.test(a.text('#sheet')) && /1 reminder at 09:00/.test(a.text('#sheet')));
    const ev1 = JSON.parse(a.ev(`JSON.stringify(calendarEvents(docById(${JSON.stringify(pid)})))`));
    record('Q2. All reminder dates passed → one reminder tomorrow', ev1.length === 1 && ev1[0].date === '2026-11-07' && ev1[0].title === 'Your passport expires 14 Apr 2027' && /6 months’ validity/.test(ev1[0].desc));
    await a.click('[data-act="calDownload"]'); await sleep(20);
    const ics1 = await lastIcs();
    const lines = ics1.split('\r\n');
    record('Q3. Calendar file: valid structure with CRLF, one event with an alert at 09:00', /^BEGIN:VCALENDAR\r\n/.test(ics1) && /END:VCALENDAR\r\n$/.test(ics1) && lines.filter(l => l === 'BEGIN:VEVENT').length === 1 && lines.includes('DTSTART:20261107T090000') && lines.includes('BEGIN:VALARM') && lines.includes('TRIGGER:PT0M') && lines.includes('SEQUENCE:1'));
    record('Q4. No reference numbers go into the calendar; the event links back to the document', !/A1234567/.test(ics1) && ics1.replace(/\r\n /g, '').includes('URL:https://localhost/expiry/#doc=' + pid));
    record('Q5. Every line is at most 75 bytes (folded)', lines.every(l => Buffer.byteLength(l) <= 75));
    record('Q6. Marked as in your calendar', a.ev(`calStatus(docById(${JSON.stringify(pid)}))`) === 'ok' && /In your calendar/.test(a.text('#side-pane')) && !a.visible('#sheet'));
    // insurance for Amina, two future reminders
    await a.click('[data-act="back"]');
    await addDoc(a, { type: 'insurance', fields: { ref: 'POL-9, A;B' } });
    await a.click(`[data-act="draftOwner"][data-id="pa"]`);
    await a.type('#f-expiry', '2026-12-24'); await a.click('[data-act="saveDoc"]'); await a.waitFor(() => !a.ev('_saving')); await sleep(20);
    const iid = a.ev(`state.documents.find(d=>d.typeId==='insurance').id`);
    const ev2 = JSON.parse(a.ev(`JSON.stringify(calendarEvents(docById(${JSON.stringify(iid)})))`));
    record('Q7. Other owner: “Amina’s insurance…”, one event per future reminder', ev2.length === 2 && ev2[0].date === '2026-11-24' && ev2[1].date === '2026-12-17' && ev2[0].title === 'Amina’s insurance expires 24 Dec 2026');
    await a.click('[data-act="calDownload"]'); await sleep(20);
    const ics2 = await lastIcs();
    const uid30 = `UID:exp-${iid}-30days@expiry.app`;
    record('Q8. Stable event IDs per document and lead time', ics2.replace(/\r\n /g, '').includes(uid30));
    // change a reminder: 30 days → 14 days
    await a.click('[data-act="editDoc"]');
    await a.type('[data-bind="ramount"][data-idx="0"]', '14');
    await a.click('[data-act="saveDoc"]'); await a.waitFor(() => !a.ev('_saving')); await sleep(20);
    record('Q9. Changing reminders offers to update the calendar', /Update your calendar/.test(a.text('#sheet')) && /1 old one removed/.test(a.text('#sheet')));
    await a.click('[data-act="calDownload"]'); await sleep(20);
    const ics3 = (await lastIcs()).replace(/\r\n /g, '');
    const blocks = ics3.split('BEGIN:VEVENT').slice(1);
    const cancelled = blocks.filter(b => /STATUS:CANCELLED/.test(b));
    record('Q10. Update file: new event added, the old one cancelled, sequence raised', blocks.length === 3 && cancelled.length === 1 && cancelled[0].includes(uid30) && ics3.includes(`UID:exp-${iid}-14days@expiry.app`) && /SEQUENCE:2/.test(ics3));
    // archive → cancellations only
    await a.click('[data-act="docMore"]'); await a.click('#sheet [data-act="sheetChoice"][data-i="1"]'); await a.click('#sheet [data-act="sheetChoice"][data-i="1"]'); await sleep(10);
    record('Q11. Archiving offers to remove its reminders from the calendar', /Update your calendar/.test(a.text('#sheet')) && /0 reminders.*2 old ones removed/.test(a.text('#sheet')));
    await a.click('#sheet [data-act="back"]');
    // delete the passport → tombstones → Home summary nudges
    await a.click('#side-pane [data-act="back"]');
    await a.click(a.$$('#doc-list .row').find(r => /Passport/.test(r.textContent)));
    await a.click('[data-act="docMore"]'); await a.click('#sheet [data-act="sheetChoice"][data-i="2"]'); await a.click('#sheet [data-act="sheetChoice"][data-i="0"]'); await sleep(10);
    record('Q12. Deleting keeps a note to cancel its calendar events', a.ev('state.calTombstones.length') === 1);
    record('Q13. Home shows the calendar nudge', /up to date in your calendar/.test(a.text('.summary')), a.text('.summary'));
    await a.click('[data-act="calAll"]');
    await a.click('[data-act="calDownload"]'); await sleep(20);
    const ics4 = (await lastIcs()).replace(/\r\n /g, '');
    record('Q14. Update-all file cancels the deleted document’s events; nothing left pending', ics4.includes(`UID:exp-${pid}-soon@expiry.app`) && /STATUS:CANCELLED/.test(ics4) && a.ev('state.calTombstones.length') === 0 && a.ev('calNeedsUpdate().length') === 0);
    // restore the archived insurance so there's something to export
    a.ev(`docById(${JSON.stringify(iid)}).state = 'active'; save();`);
    // share path
    a.w.navigator.canShare = () => true; let shared = null; a.w.navigator.share = async (o) => { shared = o; };
    await a.click('[data-act="openSettings"]');
    await a.click('[data-act="calEverything"]');
    record('Q15. Share is offered when the phone supports sharing files', !!a.$('#sheet [data-act="calShare"]'));
    await a.click('[data-act="calShare"]'); await sleep(20);
    record('Q16. Share hands over the .ics file', shared && shared.files && shared.files[0].name === 'expiry-reminders.ics');
    // reminder time
    const t = a.$('#remtime'); t.value = '07:30'; t.dispatchEvent(new a.w.Event('change', { bubbles: true })); await sleep(10);
    record('Q17. Changing the reminder time marks the calendar out of date', a.ev('state.settings.reminderTime') === '07:30' && a.ev('calNeedsUpdate().length') >= 1);
    await a.click('[data-act="calEverything"]'); await a.click('[data-act="calDownload"]'); await sleep(20);
    record('Q18. New time used in the file', (await lastIcs()).includes('T073000'));
    a.ev(`docById(${JSON.stringify(iid)}).values.expiry = '2026-11-20'; save();`); // inside its reminder window
    const snap = await a.snapshot();
    // summary: dismiss for today
    const b = await open({ storage: snap });
    await unlock(b);
    record('Q19. Home summary lists documents needing attention', /needs attention/.test(b.text('.summary')) && /Insurance/.test(b.text('.summary')));
    await b.click('[data-act="dismissSummary"]');
    record('Q20. Dismissed for today', !b.$('.summary'));
    const snap2 = await b.snapshot();
    const c = await open({ storage: snap2, today: '2026-11-07' });
    await unlock(c);
    record('Q21. Comes back the next day', !!c.$('.summary'));
    // link from a calendar event opens the document after unlocking
    const dl = await open({ storage: snap2, hash: '#doc=' + iid });
    await unlock(dl); await sleep(20);
    record('Q22. Calendar link opens that document after unlock, and the link is cleared', dl.d.body.classList.contains('pane-open') && /Insurance/.test(dl.text('#side-pane .topbar')) && dl.w.location.hash === '');
    const icsE = (s) => a.ev(`icsEscape(${JSON.stringify(s)})`);
    record('Q23. Text is escaped for calendar files', icsE('a,b;c\\d\ne') === 'a\\,b\\;c\\\\d\\ne');
  }

  /* ================= renew (M6) ================= */
  {
    const idb = new IDBFactory();
    const a = await open({ idb });
    await setup(a);
    const img = (name, text) => new a.w.File([Buffer.from(text || ('IMG-' + name))], name, { type: 'image/jpeg' });
    const dbIds = async () => (await a.w.eval(`idbReq('readonly', st=>st.getAll())`)).map(r => r.id);
    // an insurance policy with one image, added to the calendar
    await a.click('[data-act="openAdd"]'); await a.click('[data-act="addMethod"][data-m="photo"]');
    a.w.__ocr = { text: '', words: [] };
    await a.w.onFilesPicked([img('old-policy.jpg', 'OLD-POLICY')]);
    await a.waitFor(() => a.ev('draft && draft.scan && draft.scan.status') !== 'reading');
    await a.click('[data-act="draftType"][data-id="insurance"]');
    await a.type('#f-ref', 'POL-1000'); await a.type('#f-issuer', 'Jubilee'); await a.type('#f-expiry', '2026-11-24');
    a.keepCal = true;
    await a.click('[data-act="saveDoc"]'); await a.waitFor(() => !a.ev('_saving')); await sleep(20);
    await a.click('[data-act="calDownload"]'); await sleep(20);
    a.keepCal = false;
    const id = a.ev('state.documents[0].id');
    const oldAttId = a.ev('state.documents[0].attachments[0].id');
    await a.click('[data-act="renew"]');
    record('N1. Renew offers three paths', /I have the new one/.test(a.text('#sheet')) && /Renewal in progress/.test(a.text('#sheet')) && /Not renewing/.test(a.text('#sheet')));
    await a.click('[data-act="renewNew"]');
    record('N2. New one: scan, photo, file or manual', a.$$('#sheet [data-act="renewMethod"]').length === 4);
    await a.click('[data-act="renewMethod"][data-m="manual"]');
    record('N3. Renew form: same type and owner, changing fields empty, old values shown as Before', /Renew insurance/.test(a.text('#side-pane .topbar')) && !a.$('[data-act="draftType"]') && !a.$('[data-act="draftOwner"]') && a.$('#f-ref').value === '' && a.$('#f-expiry').value === '' && a.$('#f-issuer').value === 'Jubilee' && /Before: POL-1000/.test(a.text('#side-pane')) && /Before: 24 Nov 2026/.test(a.text('#side-pane')));
    await a.type('#f-expiry', '2026-10-01'); a.ev('rerenderEditor()');
    record('N4. Warns when the new expiry is not after the old one', /not after the old one/.test(a.text('#side-pane')));
    await a.click('[data-act="sameAsBefore"][data-key="ref"]');
    record('N5. “Same as before” copies an unchanged number', a.$('#f-ref').value === 'POL-1000');
    await a.type('#f-ref', 'POL-2000'); await a.type('#f-expiry', '2027-11-24');
    a.keepCal = true;
    await a.click('[data-act="saveDoc"]'); await a.waitFor(() => !a.ev('_saving')); await sleep(20);
    const d1 = JSON.parse(a.ev(`JSON.stringify(docById(${JSON.stringify(id)}))`));
    record('N6. Saved: new values current, old version (with its image) first in History', d1.values.ref === 'POL-2000' && d1.values.expiry === '2027-11-24' && d1.history.length === 1 && d1.history[0].values.ref === 'POL-1000' && d1.history[0].attachments[0].id === oldAttId && d1.attachments.length === 0 && d1.state === 'active');
    record('N7. Calendar update offered (same events, new dates)', /Update your calendar/.test(a.text('#sheet')));
    await a.click('[data-act="calDownload"]'); await sleep(10);
    a.keepCal = false;
    record('N8. History list on the document', /Expired 24 Nov 2026/.test(a.text('#side-pane')) && /POL-1000 · 1 file/.test(a.text('#side-pane')));
    await a.click('[data-act="openHistory"]');
    record('N9. Earlier version shows its details and files', /Earlier version/.test(a.text('#side-pane .topbar')) && /POL-1000/.test(a.text('#side-pane')) && a.$$('#side-pane .tile[data-h]').length === 1);
    await a.click('#side-pane .tile[data-h]'); await sleep(30);
    record('N10. Its file opens in the viewer', a.$('#sheet').classList.contains('viewer-mode') && /old-policy|Front/.test(a.text('.viewer-title')));
    await a.click('#sheet [data-act="back"]');
    // renew again from a photo: reading fills the empty fields
    await a.click('#side-pane [data-act="back"]');
    await a.click('[data-act="renew"]'); await a.click('[data-act="renewNew"]'); await a.click('[data-act="renewMethod"][data-m="photo"]');
    a.w.__ocr = { text: 'JUBILEE INSURANCE\nPolicy No: POL-3000\nPeriod 25/11/2027 to 24/11/2028', words: [] };
    await a.w.onFilesPicked([img('new-policy.jpg', 'NEW-POLICY')]);
    await a.waitFor(() => a.ev('draft && draft.scan && draft.scan.status') === 'done'); await sleep(20);
    record('N11. Scanning the new one fills the changed fields; type stays the same', a.ev('draft.mode') === 'renew' && a.ev('draft.typeId') === 'insurance' && a.$('#f-ref').value === 'POL-3000' && a.$('#f-expiry').value === '2028-11-24' && a.$('#f-issuer').value === 'Jubilee' && /Renew insurance/.test(a.text('#side-pane .topbar')));
    await a.click('[data-act="saveDoc"]'); await a.waitFor(() => !a.ev('_saving')); await sleep(20);
    const d2 = JSON.parse(a.ev(`JSON.stringify(docById(${JSON.stringify(id)}))`));
    record('N12. The new scan is the current image; two earlier versions kept, newest first', d2.attachments.length === 1 && d2.history.length === 2 && d2.history[0].values.ref === 'POL-2000' && d2.history[1].values.ref === 'POL-1000');
    // renewal in progress
    await a.click('[data-act="renew"]'); await a.click('[data-act="renewProgress"]');
    a.$('#rn-applied').value = '2026-11-06'; a.$('#rn-expected').value = '2026-11-01';
    await a.click('#sheet [data-act="sheetChoice"][data-i="0"]');
    record('N13. Expected date before applying is refused', /before the date you applied/.test(a.text('#rn-err')));
    a.$('#rn-expected').value = '2026-12-20'; a.$('#rn-ref').value = 'APP-77'; a.$('#rn-note').value = 'Collect at the branch';
    await a.click('#sheet [data-act="sheetChoice"][data-i="0"]'); await sleep(10);
    record('N14. Renewing: card on the document, In progress on Home', a.ev(`docById(${JSON.stringify(id)}).state`) === 'renewing' && /Renewal in progress/.test(a.text('#side-pane')) && /APP-77/.test(a.text('#side-pane')) && /In progress/.test(a.text('#doc-list')) && /Renewing/.test(a.text('#doc-list')));
    const evR = JSON.parse(a.ev(`JSON.stringify(calendarEvents(docById(${JSON.stringify(id)})))`));
    record('N15. Expiry reminders pause; one follow-up on the expected date', evR.length === 1 && evR[0].date === '2026-12-20' && /renewal/.test(evR[0].title) && evR[0].uid.includes('followup'));
    if (a.ev('!!(topEntry() && topEntry().calendar)')) await a.click('#sheet [data-act="back"]');
    await a.click('[data-act="stopRenewal"]');
    record('N16. Stop renewal puts reminders back', a.ev(`docById(${JSON.stringify(id)}).state`) === 'active' && a.ev(`calendarEvents(docById(${JSON.stringify(id)})).length`) >= 1);
    if (a.ev('!!(topEntry() && topEntry().calendar)')) await a.click('#sheet [data-act="back"]');
    await a.click('[data-act="renew"]'); await a.click('[data-act="renewProgress"]');
    a.$('#rn-expected').value = '2026-11-01'; a.$('#rn-applied').value = '2026-10-01';
    await a.click('#sheet [data-act="sheetChoice"][data-i="0"]'); await sleep(10);
    if (a.ev('!!(topEntry() && topEntry().calendar)')) await a.click('#sheet [data-act="back"]');
    record('N17. Overdue renewal flagged on the document and on Home', /Overdue/.test(a.text('#side-pane')) && /renewal expected 1 Nov 2026, not marked as received/.test(a.text('.summary')));
    await a.click('.renew-card [data-act="renewNew"]');
    await a.click('[data-act="renewMethod"][data-m="manual"]');
    await a.type('#f-ref', 'POL-4000'); await a.type('#f-expiry', '2029-11-24');
    await a.click('[data-act="saveDoc"]'); await a.waitFor(() => !a.ev('_saving')); await sleep(20);
    const d3 = JSON.parse(a.ev(`JSON.stringify(docById(${JSON.stringify(id)}))`));
    record('N18. Receiving it ends the renewal; the history entry keeps the application details', d3.state === 'active' && !d3.renewal && d3.history[0].renewal && d3.history[0].renewal.appliedOn === '2026-10-01');
    // not renewing + restore
    await a.click('[data-act="renew"]'); await a.click('[data-act="notRenewing"]');
    record('N19. Not renewing asks for a reason', /Sold/.test(a.text('#sheet')) && /Lost or stolen/.test(a.text('#sheet')));
    await a.click('#sheet [data-act="sheetChoice"][data-i="1"]'); await sleep(10);
    if (a.ev('!!(topEntry() && topEntry().calendar)')) await a.click('#sheet [data-act="back"]');
    record('N20. Archived with the reason; reminders off', a.ev(`docById(${JSON.stringify(id)}).state`) === 'archived' && /Archived: Cancelled/.test(a.text('#side-pane')) && a.ev(`calendarEvents(docById(${JSON.stringify(id)})).length`) === 0);
    await a.click('[data-act="restoreDoc"]');
    if (a.ev('!!(topEntry() && topEntry().calendar)')) await a.click('#sheet [data-act="back"]');
    record('N21. Restore brings it back', a.ev(`docById(${JSON.stringify(id)}).state`) === 'active' && !/Archived:/.test(a.text('#side-pane')));
    // delete an earlier version → its file goes
    let ids = await dbIds();
    record('N22. Every version’s file is still stored', ids.includes(oldAttId));
    const lastH = a.ev(`docById(${JSON.stringify(id)}).history.slice(-1)[0].id`);
    await a.click(`[data-act="openHistory"][data-h="${lastH}"]`);
    await a.click('[data-act="deleteHistory"]'); await a.click('#sheet [data-act="sheetChoice"][data-i="0"]'); await sleep(30);
    ids = await dbIds();
    record('N23. Deleting an earlier version deletes its file', !ids.includes(oldAttId) && a.ev(`docById(${JSON.stringify(id)}).history.length`) === 2 && /Insurance/.test(a.text('#side-pane .topbar')));
    // deleting the document deletes every version's files
    await a.click('[data-act="docMore"]'); await a.click('#sheet [data-act="sheetChoice"][data-i="2"]'); await a.click('#sheet [data-act="sheetChoice"][data-i="0"]'); await sleep(30);
    record('N24. Deleting the document deletes all its files, including History', (await dbIds()).length === 0);
  }
  {
    // sensitive number across a renewal
    const a = await open();
    await setup(a);
    await addDoc(a, { type: 'bank-card', fields: { cardName: 'Visa', ref: '4111 1111 1111 1111' }, month: '2026-12' });
    await sleep(20);
    const id = a.ev('state.documents[0].id');
    const oldEk = a.ev('state.documents[0].sealed.ref.ek');
    await a.click('[data-act="renew"]'); await a.click('[data-act="renewNew"]'); await a.click('[data-act="renewMethod"][data-m="manual"]');
    record('S1. Renewing a card: number box empty with “leave empty to keep”', a.$('#f-ref').value === '' && /•••• 1111/.test(a.text('#side-pane')) && /leave empty to keep it/.test(a.text('#side-pane')));
    await a.type('#f-ref', '5500 0000 0000 0004'); await a.type('#f-expiry', '2030-12');
    await a.click('[data-act="saveDoc"]'); await a.waitFor(() => !a.ev('_saving')); await sleep(20);
    const d = JSON.parse(a.ev(`JSON.stringify(docById(${JSON.stringify(id)}))`));
    record('S2. New number sealed; the old sealed number kept in History', d.masks.ref === '0004' && d.sealed.ref.ek !== oldEk && d.history[0].sealed.ref.ek === oldEk && d.history[0].masks.ref === '1111' && d.values.expiry === '2030-12-31');
    await a.click('[data-act="openHistory"]');
    await a.click('[data-act="reveal"]'); await a.type('#reveal-pw', PW); await a.click('[data-act="revealPwd"]'); await a.waitFor(() => !a.ev('_revealBusy')); await sleep(40);
    record('S3. The old number can be revealed from History', /4111 1111 1111 1111/.test(a.text('#side-pane')));
  }
  {
    // swipe a row left to renew
    const a = await open();
    await setup(a);
    await addDoc(a, { type: 'insurance', fields: { ref: 'P-1' } }); await a.type('#f-expiry', '2027-01-01'); await a.click('[data-act="saveDoc"]'); await sleep(20);
    await a.click('#side-pane [data-act="back"]');
    const row = a.$('#doc-list .row');
    const pe = (type, x, y) => { const e = new a.w.Event(type, { bubbles: true }); Object.defineProperty(e, 'clientX', { value: x }); Object.defineProperty(e, 'clientY', { value: y }); Object.defineProperty(e, 'pointerType', { value: 'touch' }); return e; };
    row.dispatchEvent(pe('pointerdown', 300, 100));
    row.dispatchEvent(pe('pointermove', 250, 102));
    row.dispatchEvent(pe('pointermove', 180, 103));
    record('W5. Row follows the finger and shows it will renew', /translateX\(-1[12]\dpx\)/.test(row.style.transform) && row.classList.contains('swipe-ready'));
    row.dispatchEvent(pe('pointerup', 180, 103));
    row.dispatchEvent(new a.w.MouseEvent('click', { bubbles: true })); await sleep(10);
    record('W6. Releasing opens Renew, not the document', /I have the new one/.test(a.text('#sheet')) && !a.d.body.classList.contains('pane-open') && row.style.transform === '');
  }

  /* ================= GitHub sync (M7) ================= */
  {
    const G = makeGitHub();
    const gid = G.create({ 'expiry-state.json': '{}' });
    const TOKEN = G.token;
    const idbA = new IDBFactory(), idbB = new IDBFactory();
    const A = await open({ gh: G, idb: idbA });
    await setup(A);
    const img = (dev, name, text) => new dev.w.File([Buffer.from(text)], name, { type: 'image/jpeg' });
    const connect = async (dev, gist, token, pws) => {
      await dev.click('[data-act="openSettings"]');
      await dev.type('#sync-gist', gist); await dev.type('#sync-token', token);
      await dev.click('[data-act="syncConnect"]');
      for (const pw of (pws || [])){
        await dev.waitFor(() => dev.$('#pwd-in-0') && !dev.ev('topEntry() && topEntry().busy'));
        await dev.type('#pwd-in-0', pw); await dev.click('[data-act="pwdOk"]');
        await dev.waitFor(() => !dev.ev('topEntry() && topEntry().busy')); await sleep(20);
      }
      await dev.waitFor(() => !dev.ev('_syncing') && (dev.ev('!!(syncCfg && syncCfg.lastSyncedAt)') || dev.text('#sync-err').length > 0 || dev.text('#pwd-error').length > 0));
      await sleep(30);
    };
    const sync = async (dev) => { await dev.w.eval('syncNow({interactive:true})'); await sleep(20); };
    const stateFile = () => G.gists[gid].files['expiry-state.json'];
    const fileGists = () => Object.values(G.gists).filter(g => g.id !== gid);
    // A: a bank card, an insurance policy with a photo, a passport with a (sensitive) photo
    await addDoc(A, { type: 'bank-card', fields: { cardName: 'Visa', ref: '4111 1111 1111 1111' }, month: '2028-01' });
    await A.click('#side-pane [data-act="back"]');
    await A.click('[data-act="openAdd"]'); await A.click('[data-act="addMethod"][data-m="photo"]');
    await A.w.onFilesPicked([img(A, 'pol.jpg', 'POLICY-PHOTO')]); await A.waitFor(() => A.ev('draft && draft.scan && draft.scan.status') !== 'reading');
    await A.click('[data-act="draftType"][data-id="insurance"]'); await A.type('#f-ref', 'POL-1'); await A.type('#f-expiry', '2027-06-30');
    await A.click('[data-act="saveDoc"]'); await A.waitFor(() => !A.ev('_saving')); await sleep(10);
    await A.click('#side-pane [data-act="back"]');
    await A.click('[data-act="openAdd"]'); await A.click('[data-act="addMethod"][data-m="photo"]');
    await A.w.onFilesPicked([img(A, 'pp.jpg', 'PASSPORT-PHOTO-SECRET')]); await A.waitFor(() => A.ev('draft && draft.scan && draft.scan.status') !== 'reading');
    await A.click('[data-act="draftType"][data-id="passport"]'); await A.type('#f-ref', 'A7654321'); await A.type('#f-expiry', '2030-01-01');
    await A.click('[data-act="saveDoc"]'); await A.waitFor(() => !A.ev('_saving')); await sleep(10);
    await A.click('#side-pane [data-act="back"]');
    // wrong token first
    await connect(A, gid, 'ghp_wrongwrongwrongwrongwrong', []);
    record('Y1. A wrong token is reported clearly', /rejected the access token/.test(A.text('#sync-err')) && A.ev('syncCfg') === null);
    await A.click('#side-pane [data-act="back"]');
    await connect(A, gid, TOKEN, [PW]);
    const env = JSON.parse(stateFile());
    record('Y2. First device connects and pushes an encrypted copy', A.ev('!!syncCfg.lastSyncedAt') && env.expiryEncrypted === 1 && !!env.auth && /Up to date/.test(A.text('#sync-status')));
    record('Y3. Nothing readable on GitHub: no names, numbers or file bytes', !/Salim|Visa|POL-1|A7654321|4111|Passport/i.test(stateFile()) && fileGists().length === 2 && !fileGists().some(g => /POLICY-PHOTO|PASSPORT-PHOTO|UE9MSUNZ/.test(JSON.stringify(g.files))));
    record('Y4. Each file has its own secret Gist; ids recorded on the attachments', A.ev('allAtts(state.documents).every(a=>!!a.remote)') && fileGists().every(g => g.description && /Expiry/.test(g.description)));
    const snapA = await A.snapshot();
    record('Y5. Token and sync key are encrypted on the phone', JSON.parse(snapA.expiry_sync).__enc === 1 && !Object.values(snapA).some(v => v.includes(TOKEN)));
    record('Y6. Calendar bookkeeping is never synced', A.ev('syncableState(state).documents.every(d=>d.cal===undefined)'));
    // device B with a different password
    const B = await open({ gh: G, idb: idbB });
    await setup(B, { name: 'Salim', pw: 'other-pass-22' });
    await B.click('[data-act="openSettings"]');
    await B.type('#sync-gist', gid); await B.type('#sync-token', TOKEN);
    await B.click('[data-act="syncConnect"]');
    await B.waitFor(() => !!B.$('#pwd-in-0'));
    record('Y7. Second device asks for the password of the first', /device that set up sync/.test(B.text('#sheet')));
    await B.type('#pwd-in-0', 'not-it-at-all'); await B.click('[data-act="pwdOk"]'); await B.waitFor(() => /Incorrect/.test(B.text('#pwd-error')));
    record('Y8. Wrong password refused, dialog stays', /Incorrect password for the copy on GitHub/.test(B.text('#pwd-error')));
    await B.type('#pwd-in-0', PW); await B.click('[data-act="pwdOk"]');
    await B.waitFor(() => /This phone’s password/.test(B.text('#sheet')));
    record('Y9. Different phone password: asks for it to move this phone to the synced keys', /different password/.test(B.text('#sheet')));
    await B.type('#pwd-in-0', 'other-pass-22'); await B.click('[data-act="pwdOk"]');
    await B.waitFor(() => !B.ev('_syncing') && B.ev('!!(syncCfg && syncCfg.lastSyncedAt)')); await sleep(30);
    record('Y10. B now has A’s documents, using the synced keys', B.ev('state.documents.length') === 3 && B.ev('lockRec.skPub') === A.ev('lockRec.skPub'));
    record('Y10b. Only one “You” profile after connecting a second device', B.ev('activeProfiles().filter(p=>p.isSelf).length') === 1 && B.ev('activeProfiles().length') === 1 && B.ev('state.documents.every(d=>!!profileById(d.ownerId))'));
    const polB = await B.w.eval(`readFile(state.documents.find(d=>d.typeId==='insurance').attachments[0].id).then(b=>Array.from(b))`);
    record('Y11. Normal files downloaded and readable on B', Buffer.from(polB).toString() === 'POLICY-PHOTO');
    await B.click('#side-pane [data-act="back"]').catch(() => {});
    await B.click('[data-act="closePanes"]').catch(() => {});
    await B.click(B.$$('#doc-list .row').find(r => /Visa/.test(r.textContent)));
    await revealWithPassword(B, 'other-pass-22');
    record('Y12. A’s card number reveals on B with B’s own password', /4111 1111 1111 1111/.test(B.text('#side-pane')));
    const ppB = await B.w.eval(`readFile(state.documents.find(d=>d.typeId==='passport').attachments[0].id).then(b=>Array.from(b))`);
    record('Y13. A’s sensitive passport photo opens on B after reveal', Buffer.from(ppB).toString() === 'PASSPORT-PHOTO-SECRET');
    await B.click('[data-act="hideReveal"]');
    // edits on different documents merge silently
    A.ev(`state.documents.find(d=>d.typeId==='insurance').values.note = 'Edited on A'; save();`);
    B.ev(`state.documents.find(d=>d.typeId==='passport').values.issuer = 'Kenya'; save();`);
    await sync(A); await sync(B); await sync(A);
    const both = (dev) => dev.ev(`state.documents.find(d=>d.typeId==='insurance').values.note`) === 'Edited on A' && dev.ev(`state.documents.find(d=>d.typeId==='passport').values.issuer`) === 'Kenya';
    record('Y14. Different documents edited on each device: both edits kept everywhere', both(A) && both(B));
    // same document edited differently → B decides
    A.ev(`state.documents.find(d=>d.typeId==='bank-card').values.cardName = 'Visa Gold'; state.documents.find(d=>d.typeId==='bank-card').updatedAt = new Date().toISOString(); save();`);
    B.ev(`state.documents.find(d=>d.typeId==='bank-card').values.cardName = 'Visa Platinum'; save();`);
    await sync(A);
    const r1 = await B.w.eval('syncNow({interactive:false})');
    record('Y15. Automatic sync never decides a conflict for you; Home asks', r1.conflicts === 1 && /needs your decision/.test(B.text('.summary')));
    const p = B.w.eval('syncNow({interactive:true})');
    await B.waitFor(() => /Choose which version to keep/.test(B.text('#sheet')));
    record('Y16. Conflict sheet shows both versions', /This phone/.test(B.text('#sheet')) && /Visa Platinum/.test(B.text('#sheet')) && /Visa Gold/.test(B.text('#sheet')));
    await B.click('[data-act="conflictPick"][data-v="remote"]');
    await B.click('[data-act="conflictApply"]'); await p; await sleep(20);
    await sync(A);
    record('Y17. Chosen version kept on both devices', B.ev(`state.documents.find(d=>d.typeId==='bank-card').values.cardName`) === 'Visa Gold' && A.ev(`state.documents.find(d=>d.typeId==='bank-card').values.cardName`) === 'Visa Gold' && !B.ev('syncCfg.pendingConflicts'));
    // delete on B → file Gist removed → gone on A (files too)
    const insAtt = A.ev(`state.documents.find(d=>d.typeId==='insurance').attachments[0]`);
    B.ev(`(()=>{ const d = state.documents.find(x=>x.typeId==='insurance'); state.documents = state.documents.filter(x=>x!==d); deleteAttachmentFiles(d.attachments); save(); })()`);
    await sync(B); await sync(A); await sleep(20);
    const aIds = (await A.w.eval(`idbReq('readonly', st=>st.getAll())`)).map(r => r.id);
    record('Y18. Deleted on one device: removed on the other, its file Gist and local file deleted', A.ev(`state.documents.some(d=>d.typeId==='insurance')`) === false && !G.gists[insAtt.remote] && !aIds.includes(insAtt.id));
    // lock and unlock keep the connection
    await A.click('[data-act="openSettings"]').catch(() => {});
    A.ev('lockApp()'); await sleep(30);
    record('Y19. Locking forgets the token in memory', A.ev('syncCfg') === null);
    await unlock(A);
    record('Y20. Unlocking restores the connection', A.ev('syncCfg && syncCfg.gistId') === gid);
    // password change on A → new device needs the new password
    await A.click('[data-act="openSettings"]');
    await A.click('[data-act="changePassword"]');
    for (const [i, v] of [PW, 'brand-new-pass-1', 'brand-new-pass-1'].entries()) await A.type('#pwd-in-' + i, v);
    await A.click('[data-act="pwdOk"]'); await A.waitFor(() => !A.visible('#sheet')); await sleep(20);
    await sync(A);
    const C = await open({ gh: G, idb: new IDBFactory() });
    await setup(C, { name: 'Salim', pw: 'brand-new-pass-1' });
    await connect(C, gid, TOKEN, [PW]);
    record('Y21. After a password change, the old password no longer opens the GitHub copy', /Incorrect password/.test(C.text('#pwd-error')));
    await C.type('#pwd-in-0', 'brand-new-pass-1'); await C.click('[data-act="pwdOk"]');
    await C.waitFor(() => !C.ev('_syncing') && C.ev('!!(syncCfg && syncCfg.lastSyncedAt)')); await sleep(20);
    record('Y22. The new password connects a new device (same password here: no extra prompt)', C.ev('state.documents.length') === 2);
    await sync(B);
    record('Y23. Other devices keep syncing after the password change', B.ev('!syncCfg.lastError') && B.ev('state.documents.length') === 2);
    // a Gist with someone else's content is refused
    const foreign = G.create({ 'notes.md': '# my notes' });
    const D = await open({ gh: G });
    await setup(D);
    await connect(D, foreign, TOKEN, []);
    record('Y24. A Gist with other content is refused', /other content/.test(D.text('#sync-err')) && D.ev('syncCfg') === null);
    // disconnect
    await C.click('[data-act="syncDisconnect"]'); await C.click('#sheet [data-act="sheetChoice"][data-i="0"]'); await sleep(10);
    const snapC = await C.snapshot();
    record('Y25. Disconnect keeps documents and forgets the connection', C.ev('state.documents.length') === 2 && !snapC.expiry_sync && /GitHub sync/.test(C.text('#side-pane')) && !!C.$('#sync-gist'));
  }

  /* ================= backup and restore (M8) ================= */
  {
    const written = []; let picks = 0;
    const dir = { name: 'Expiry backups', queryPermission: async () => 'granted',
      getFileHandle: async (name) => ({ createWritable: async () => ({ write: async (f) => { written.push({ name, f }); }, close: async () => {} }) }) };
    const A = await open({ idb: new IDBFactory(), before: (w) => { w.showDirectoryPicker = async () => { picks++; return dir; }; } });
    await setup(A);
    const img = (dev, name, text) => new dev.w.File([Buffer.from(text)], name, { type: 'image/jpeg' });
    const lastBlob = (dev, type) => dev.w.__blobs.filter(b => !type || b.type === type).pop();
    await addDoc(A, { type: 'bank-card', fields: { cardName: 'Visa', ref: '4111 1111 1111 1111' }, month: '2028-01' });
    await A.click('#side-pane [data-act="back"]');
    for (const [type, ref, exp, file, text] of [['passport', 'A7654321', '2030-01-01', 'pp.jpg', 'PASSPORT-IMG'], ['insurance', 'POL-1', '2027-06-30', 'pol.jpg', 'POLICY-IMG']]){
      await A.click('[data-act="openAdd"]'); await A.click('[data-act="addMethod"][data-m="photo"]');
      await A.w.onFilesPicked([img(A, file, text)]); await A.waitFor(() => A.ev('draft && draft.scan && draft.scan.status') !== 'reading');
      await A.click(`[data-act="draftType"][data-id="${type}"]`); await A.type('#f-ref', ref); await A.type('#f-expiry', exp);
      await A.click('[data-act="saveDoc"]'); await A.waitFor(() => !A.ev('_saving')); await sleep(10);
      await A.click('#side-pane [data-act="back"]');
    }
    await A.click('[data-act="openSettings"]');
    record('BK1. Settings shows backup status: never', /Backup and restore/.test(A.text('#side-pane')) && /haven’t made a backup/.test(A.text('#side-pane')));
    await A.click('[data-act="backupMake"]');
    await A.type('#pwd-in-0', 'wrong-password'); await A.click('[data-act="pwdOk"]'); await A.waitFor(() => /Incorrect/.test(A.text('#pwd-error')));
    record('BK2. Backup needs your password', /Incorrect password/.test(A.text('#pwd-error')));
    await A.type('#pwd-in-0', PW); await A.click('[data-act="pwdOk"]');
    await A.waitFor(() => A.ev('!!(topEntry() && topEntry().backup)'));
    record('BK3. Encrypted backup ready: save to folder (computer), download', /Encrypted backup ready/.test(A.text('#sheet')) && /\.expiry\.json/.test(A.text('#sheet')) && !!A.$('[data-act="backupFolder"]') && !!A.$('[data-act="backupDownload"]'));
    await A.click('[data-act="backupFolder"]'); await sleep(30);
    record('BK4. First save asks for a folder and writes the file there', picks === 1 && written.length === 1 && /expiry-backup-2026-11-06\.expiry\.json/.test(written[0].name));
    const encText = await written[0].f.text();
    const enc = JSON.parse(encText);
    record('BK5. Encrypted file: nothing readable, no keys of this phone', enc.expiryBackup === 1 && enc.kind === 'encrypted' && !/Visa|4111|A7654321|POL-1|Salim|PASSPORT-IMG|POLICY-IMG|UEFTU1BPUlQ/.test(encText) && !/dekWrap|skWrap|token/.test(encText));
    record('BK6. Backup date recorded', A.ev('!!state.settings.lastBackupAt') && /Today/.test(A.text('#side-pane')));
    await A.click('[data-act="backupMake"]'); await A.type('#pwd-in-0', PW); await A.click('[data-act="pwdOk"]'); await A.waitFor(() => A.ev('!!(topEntry() && topEntry().backup)'));
    await A.click('[data-act="backupFolder"]'); await sleep(20);
    record('BK7. Next time it saves to the same folder without asking', picks === 1 && written.length === 2 && /Expiry backups/.test(A.text('#side-pane')));
    // restore on a fresh phone with a different password
    const B = await open({ idb: new IDBFactory() });
    await setup(B, { name: 'Salim', pw: 'phone-b-pass-1' });
    record('BK8. An empty Home offers Restore from a backup', !!B.$('#doc-list [data-act="restorePick"]'));
    const bPub = B.ev('lockRec.skPub');
    B.w.onRestorePicked(new B.w.File([encText], 'backup.expiry.json', { type: 'application/json' }));
    await B.waitFor(() => !!B.$('#pwd-in-0'));
    await B.type('#pwd-in-0', 'phone-b-pass-1'); await B.click('[data-act="pwdOk"]'); await B.waitFor(() => /Incorrect/.test(B.text('#pwd-error')));
    record('BK9. Restoring needs the backup’s password', /Incorrect password for this backup/.test(B.text('#pwd-error')));
    await B.type('#pwd-in-0', PW); await B.click('[data-act="pwdOk"]');
    await B.waitFor(() => /Restore backup/.test(B.text('#sheet')));
    record('BK10. Shows what’s in the backup', /3 documents/.test(B.text('#sheet')) && /3 file|2 file/.test(B.text('#sheet')) && !B.$('[data-act="restoreApply"][data-m="add"]'));
    await B.click('[data-act="restoreApply"][data-m="replace"]');
    await B.waitFor(() => B.ev('state.documents.length') === 3); await sleep(40);
    record('BK11. Restored: documents, one “You” profile, this phone keeps its own keys', B.ev('activeProfiles().length') === 1 && B.ev('lockRec.skPub') === bPub && B.ev('state.documents.every(d=>!!profileById(d.ownerId))'));
    const polB = await B.w.eval(`readFile(state.documents.find(d=>d.typeId==='insurance').attachments[0].id).then(b=>Array.from(b))`);
    record('BK12. Normal files restored', Buffer.from(polB).toString() === 'POLICY-IMG');
    await B.waitFor(() => /Add the restored reminders/.test(B.text('#sheet')), 3000);
    record('BK13. Offers to put the restored reminders in this phone’s calendar', /Add the restored reminders/.test(B.text('#sheet')));
    await B.click('#sheet [data-act="back"]');
    await B.click(B.$$('#doc-list .row').find(r => /Visa/.test(r.textContent)));
    await revealWithPassword(B, 'phone-b-pass-1');
    record('BK14. Card number re-sealed to this phone: reveals with this phone’s password', /4111 1111 1111 1111/.test(B.text('#side-pane')));
    const ppB = await B.w.eval(`readFile(state.documents.find(d=>d.typeId==='passport').attachments[0].id).then(b=>Array.from(b))`);
    record('BK15. Sensitive passport image restored and opens after reveal', Buffer.from(ppB).toString() === 'PASSPORT-IMG');
    // plain backup
    await A.click('[data-act="backupPlain"]');
    record('BK16. Plain backup warns first', /not encrypted/.test(A.text('#sheet')) && /card numbers/.test(A.text('#sheet')));
    await A.click('#sheet [data-act="sheetChoice"][data-i="0"]');
    await A.waitFor(() => !!A.$('#pwd-in-0')); await A.type('#pwd-in-0', PW); await A.click('[data-act="pwdOk"]');
    await A.waitFor(() => A.ev('!!(topEntry() && topEntry().backup)'));
    await A.click('[data-act="backupDownload"]'); await sleep(20);
    const html = await lastBlob(A, 'text/html').text();
    record('BK17. Plain backup is a readable page: names, full card number, images inline', /<h1>Expiry backup<\/h1>/.test(html) && /4111 1111 1111 1111/.test(html) && /A7654321/.test(html) && /<img alt="Front" src="data:image\/jpeg;base64,/.test(html) && /This backup is not encrypted/.test(html));
    record('BK18. …and holds no keys or tokens', !/dekWrap|skWrap|"auth"|keyWrap|token/.test(html));
    record('BK19. The page can’t be broken by its own data (script tag escaped)', (html.match(/<\/script>/g) || []).length === 1);
    // restore the plain page on a phone that already has a document: add
    const C = await open({ idb: new IDBFactory() });
    await setup(C, { name: 'Salim', pw: 'phone-c-pass-1' });
    await addDoc(C, { type: 'other', fields: { ref: 'GYM-1' } }); await C.type('#f-expiry', '2027-02-02'); await C.click('[data-act="saveDoc"]'); await sleep(10);
    await C.w.onRestorePicked(new C.w.File([html], 'backup.html', { type: 'text/html' }));
    await C.waitFor(() => /Restore backup/.test(C.text('#sheet')));
    record('BK20. With documents already here: Add or Replace', !!C.$('[data-act="restoreApply"][data-m="add"]') && /Replace everything/.test(C.text('#sheet')));
    await C.click('[data-act="restoreApply"][data-m="add"]');
    await C.waitFor(() => C.ev('state.documents.length') === 4); await sleep(40);
    const cCard = JSON.parse(C.ev(`JSON.stringify(state.documents.find(d=>d.typeId==='bank-card'))`));
    record('BK21. Added: own document kept; card number from the plain page sealed again', cCard && !cCard.values.ref && !!cCard.sealed.ref && cCard.masks.ref === '1111' && C.ev('activeProfiles().length') === 1);
    const ppC = await C.w.eval(`idbGet(state.documents.find(d=>d.typeId==='passport').attachments[0].id).then(r=>r.mode)`);
    record('BK22. Passport image stored sealed again (sensitive)', ppC === 'vault');
    if (C.ev('!!(topEntry() && topEntry().calendar)')) await C.click('#sheet [data-act="back"]');
    // add mode: newer version of a document wins
    B.ev(`(()=>{ const d = state.documents.find(x=>x.typeId==='insurance'); d.values.note = 'Newer on B'; d.updatedAt = '2099-01-01T00:00:00.000Z'; save(); })()`);
    C.w.onRestorePicked(new C.w.File([encText], 'backup.expiry.json', { type: 'application/json' }));
    await C.waitFor(() => !!C.$('#pwd-in-0')); await C.type('#pwd-in-0', PW); await C.click('[data-act="pwdOk"]');
    await C.waitFor(() => /Restore backup/.test(C.text('#sheet')));
    C.ev(`(()=>{ const d = state.documents.find(x=>x.typeId==='insurance'); d.values.note = 'C is newest'; d.updatedAt = '2099-06-01T00:00:00.000Z'; })()`);
    await C.click('[data-act="restoreApply"][data-m="add"]'); await sleep(60);
    record('BK23. Adding never replaces a newer version already on the phone', C.ev(`state.documents.find(d=>d.typeId==='insurance').values.note`) === 'C is newest' && C.ev('state.documents.length') === 4);
    if (C.ev('!!(topEntry() && topEntry().calendar)')) await C.click('#sheet [data-act="back"]');
    // replace removes what isn't in the backup, files included
    const gymAtt = C.ev(`state.documents.find(d=>d.typeId==='other').id`);
    await C.w.onRestorePicked(new C.w.File([html], 'backup.html', { type: 'text/html' }));
    await C.waitFor(() => /Restore backup/.test(C.text('#sheet')));
    await C.click('[data-act="restoreApply"][data-m="replace"]'); await sleep(60);
    record('BK24. Replace leaves exactly what’s in the backup', C.ev('state.documents.length') === 3 && !C.ev(`docById(${JSON.stringify(gymAtt)})`));
    // not a backup
    await C.w.onRestorePicked(new C.w.File(['hello'], 'notes.txt', { type: 'text/plain' })); await sleep(10);
    record('BK25. Other files are refused', /isn’t an Expiry backup/.test(C.text('#toast')));
    // nudge after a week without a backup (no sync)
    const D = await open(); await setup(D);
    D.ev(`state.documents.push({ id:'old1', typeId:'other', ownerId:state.profiles[0].id, values:{ ref:'X', expiry:'2030-01-01' }, reminders:[], state:'active', history:[], attachments:[], createdAt:'2026-10-01T00:00:00.000Z' }); save(); renderHome();`);
    record('BK26. Home reminds you to back up after a week with no backup', /don’t have a backup yet/.test(D.text('.summary')));
  }

  /* ================= document types and fields (M9) ================= */
  {
    const T = await open({ idb: new IDBFactory() });
    await setup(T);
    const home = async () => { T.ev('draft = null; closeAllPanes()'); await sleep(10); };
    const toTypes = async () => { await home(); await T.click('[data-act="openSettings"]'); await T.click('[data-act="openTypes"]'); };
    const idxOf = (label) => T.$$('#type-fields [data-act="editField"]').findIndex(b => b.textContent.includes(label));
    await addDoc(T, { type: 'insurance', fields: { ref: 'POL-77', issuer: 'Allianz', expiry: '2027-06-30' } });
    await addDoc(T, { type: 'bank-card', fields: { cardName: 'Visa', ref: '4111 1111 1111 1111' }, month: '2028-01' });
    await toTypes();
    record('T1. Types list: every type with its fields and documents', T.$$('#side-pane [data-act="editType"]').length === 8 && /6 fields · 1 document/.test(T.text('#side-pane')));
    await T.click('[data-act="editType"][data-id="insurance"]');
    record('T2. Type editor shows name, icon and fields', T.$('#t-name').value === 'Insurance' && T.$$('#type-fields [data-act="editField"]').length === 6 && !!T.$('.icon-opt.on'));
    await T.click('[data-act="addField"]'); await T.click('[data-act="fdDone"]');
    record('T3. A field needs a label', /Enter a label/.test(T.text('#sheet')));
    await T.type('#fd-label', 'policy no.'); await T.click('[data-act="fdDone"]');
    record('T4. Labels are unique within a type', /already has a field called that/.test(T.text('#sheet')));
    await T.type('#fd-label', 'Membership no.'); await T.click('[data-act="fdDone"]');
    record('T5. New field goes just before Note', T.$$('#type-fields .row-title').map(e => e.textContent).slice(-2).join('|') === 'Membership no.|Note');
    await T.click('[data-act="addField"]'); await T.type('#fd-label', 'Plan'); await T.click('[data-act="fdKind"][data-k="list"]'); await T.click('[data-act="fdDone"]');
    record('T6. A choice field needs choices', /Add at least one choice/.test(T.text('#sheet')) && T.$('#fd-label').value === 'Plan');
    await T.type('#fd-opts', 'Gold\nSilver\n\nGold'); await T.click('[data-act="fdDone"]');
    await T.click('[data-act="editField"][data-i="0"]');
    record('T7. Reference no. can be renamed but not removed', !!T.$('#fd-label') && !T.$('[data-act="fdDelete"]'));
    await T.click('[data-act="fdFlag"][data-k="sensitive"]');
    record('T8. Making a field sensitive says what happens to saved values', /1 document with a value will be protected/.test(T.text('#sheet')));
    await T.click('[data-act="fdDone"]');
    await T.click(`[data-act="editField"][data-i="${idxOf('Insurer')}"]`); await T.click('[data-act="fdDelete"]');
    record('T9. Removing a field that has values asks first', /1 document has a value in this field/.test(T.text('#sheet')));
    await T.click('#sheet [data-act="sheetChoice"][data-i="0"]');
    await T.click(`[data-act="moveField"][data-i="${idxOf('Membership')}"][data-d="-1"]`);
    await T.click('[data-act="tAddRem"]');
    await T.type('[data-bind="tramount"][data-idx="2"]', '3');
    const unit = T.$('[data-bind="trunit"][data-idx="2"]'); unit.value = 'months'; unit.dispatchEvent(new T.w.Event('change', { bubbles: true })); await sleep(5);
    await T.click('#side-pane [data-act="back"]');
    record('T10. Leaving with unsaved changes asks first', /Discard changes/.test(T.text('#sheet')));
    await T.click('#sheet [data-act="back"]');
    await T.click('[data-act="saveType"]'); await T.waitFor(() => !T.ev('_typeSaving')); await sleep(20);
    const ins = JSON.parse(T.ev(`JSON.stringify(state.documents.find(d=>d.typeId==='insurance'))`));
    const tIns = JSON.parse(T.ev(`JSON.stringify(typeById('insurance'))`));
    record('T11. Saved: policy no. sealed in the document, insurer value deleted', !ins.values.ref && !!ins.sealed.ref && ins.masks.ref === 'L-77' && !('issuer' in ins.values) && !tIns.fields.some(f => f.key === 'issuer'));
    record('T12. Field order, choices and default reminders saved', tIns.fields.map(f => f.label).join('|') === 'Policy no.|Cover|Start date|Membership no.|Expiry date|Plan|Note'
      && JSON.stringify(tIns.fields.find(f => f.label === 'Plan').options) === '["Gold","Silver"]' && tIns.reminders.length === 3 && tIns.reminders[2].amount === 3 && tIns.reminders[2].unit === 'months');
    record('T13. Home masks the now-sensitive policy no.', /•••• L-77/.test(T.text('#doc-list')) && !/POL-77/.test(T.text('#doc-list')));
    const memKey = tIns.fields.find(f => f.label === 'Membership no.').key, planKey = tIns.fields.find(f => f.label === 'Plan').key;
    await home();
    await T.click('[data-act="openAdd"]'); await T.click('[data-act="addMethod"][data-m="manual"]'); await T.click('[data-act="draftType"][data-id="insurance"]');
    record('T14. Adding a document shows the new fields (choice as a list) and reminders', !!T.$('#f-' + memKey) && T.$('#f-' + planKey).tagName === 'SELECT' && T.$$('#f-' + planKey + ' option').length === 3 && T.$$('.rem-row').length === 3 && !T.$('#f-issuer'));
    await T.type('#f-ref', 'POL-88'); await T.type('#f-' + memKey, 'M-123');
    const plan = T.$('#f-' + planKey); plan.value = 'Gold'; plan.dispatchEvent(new T.w.Event('input', { bubbles: true }));
    await T.type('#f-expiry', '2028-03-01'); await T.click('[data-act="saveDoc"]'); await T.waitFor(() => !T.ev('_saving')); await sleep(20);
    record('T15. New fields shown on the document', /Membership no\./.test(T.text('#side-pane')) && /M-123/.test(T.text('#side-pane')) && /Gold/.test(T.text('#side-pane')));
    await toTypes();
    await T.click('[data-act="editType"][data-id="bank-card"]');
    await T.click('[data-act="editField"][data-i="1"]'); await T.click('[data-act="fdFlag"][data-k="sensitive"]'); await T.click('[data-act="fdDone"]');
    await T.click('[data-act="saveType"]'); await T.waitFor(() => !!T.$('#pwd-in-0'));
    record('T16. A field that stops being sensitive needs your password', /stop protecting “Card number”/.test(T.text('#sheet')));
    await T.type('#pwd-in-0', 'nope-nope-1'); await T.click('[data-act="pwdOk"]'); await T.waitFor(() => /Incorrect/.test(T.text('#pwd-error')));
    await T.type('#pwd-in-0', PW); await T.click('[data-act="pwdOk"]'); await T.waitFor(() => !T.ev('_typeSaving')); await sleep(20);
    const card = JSON.parse(T.ev(`JSON.stringify(state.documents.find(d=>d.typeId==='bank-card'))`));
    record('T17. …then its values are stored like other fields', card.values.ref === '4111 1111 1111 1111' && !card.sealed.ref);
    await T.click('[data-act="addType"]'); await T.click('[data-act="saveType"]');
    record('T18. A new type needs a name', /Enter a name/.test(T.text('#side-pane')));
    await T.type('#t-name', 'passport'); await T.click('[data-act="saveType"]');
    record('T19. Type names are unique', /already a type called that/.test(T.text('#side-pane')));
    await T.type('#t-name', 'Gym membership'); await T.click('[data-act="tIcon"][data-ic="heart"]');
    await T.click('[data-act="addField"]'); await T.type('#fd-label', 'Club'); await T.click('[data-act="fdDone"]');
    const clubKey = T.ev(`tdraft.fields.find(f=>f.label==='Club').key`);
    await T.click(`[data-act="tTitle"][data-k="${clubKey}"]`);
    await T.click('[data-act="saveType"]'); await sleep(20);
    const gymId = T.ev(`(state.types.find(t=>t.name==='Gym membership')||{}).id`);
    record('T20. New type saved and listed', !!gymId && /Gym membership/.test(T.text('#side-pane')) && T.ev(`typeById(${JSON.stringify(gymId)}).icon`) === 'heart');
    await home();
    await addDoc(T, { type: gymId, fields: { ref: 'G-1', [clubKey]: 'FitClub', expiry: '2027-01-31' } });
    record('T21. A document of your own type, named by its Club field', T.ev(`state.documents.some(d=>d.typeId===${JSON.stringify(gymId)})`) && /FitClub/.test(T.text('#doc-list')));
    await toTypes(); await T.click(`[data-act="editType"][data-id="${gymId}"]`);
    await T.click('[data-act="tDelete"]');
    record('T22. A type in use can’t be deleted', /1 document uses this type/.test(T.text('#toast')) && T.ev(`state.types.some(t=>t.id===${JSON.stringify(gymId)})`));
    await T.click('[data-act="tHidden"][data-v="1"]'); await T.click('[data-act="saveType"]'); await sleep(20);
    await home();
    await T.click('[data-act="openAdd"]'); await T.click('[data-act="addMethod"][data-m="manual"]');
    record('T23. Hidden types aren’t offered when adding; their documents stay', !T.$(`[data-act="draftType"][data-id="${gymId}"]`) && !!T.$('[data-act="draftType"][data-id="passport"]') && /FitClub/.test(T.text('#doc-list')));
    await toTypes();
    await T.click('[data-act="addType"]'); await T.type('#t-name', 'Temp'); await T.click('[data-act="saveType"]'); await sleep(20);
    const tmpId = T.ev(`state.types.find(t=>t.name==='Temp').id`);
    await T.click(`[data-act="editType"][data-id="${tmpId}"]`); await T.click('[data-act="tDelete"]'); await T.click('#sheet [data-act="sheetChoice"][data-i="0"]'); await sleep(10);
    record('T24. An unused type of your own can be deleted', !T.ev(`state.types.some(t=>t.name==='Temp')`) && T.$$('#side-pane [data-act="editType"]').length === 9);
    await T.click('[data-act="editType"][data-id="insurance"]'); await T.click('[data-act="tReset"]');
    record('T25. Reset warns about your fields that have values', /“Membership no\.”/.test(T.text('#sheet')) && /“Plan”/.test(T.text('#sheet')));
    await T.click('#sheet [data-act="sheetChoice"][data-i="0"]'); await T.click('[data-act="saveType"]');
    await T.waitFor(() => !!T.$('#pwd-in-0')); await T.type('#pwd-in-0', PW); await T.click('[data-act="pwdOk"]'); await T.waitFor(() => !T.ev('_typeSaving')); await sleep(20);
    const ins2 = JSON.parse(T.ev(`JSON.stringify(state.documents.filter(d=>d.typeId==='insurance'))`));
    record('T26. Reset: original fields back, your fields’ values gone, policy numbers readable', T.ev(`typeById('insurance').fields.map(f=>f.key).join()`) === 'ref,issuer,cover,issueDate,expiry,note'
      && ins2.every(d => !d.values[memKey] && !d.values[planKey] && !d.sealed.ref) && ins2.some(d => d.values.ref === 'POL-88'));
    await home(); await T.click('[data-act="openSettings"]'); await T.click('[data-act="dateDisplay"][data-f="iso"]');
    await home(); await T.click(T.$$('#doc-list .row').find(r => /POL-77/.test(r.textContent)));
    record('T27. Dates follow the display setting', /2027-06-30/.test(T.text('#side-pane')) && !/30 Jun 2027/.test(T.text('#side-pane')));
    const evs = JSON.parse(T.ev(`JSON.stringify(calendarEvents(state.documents.find(d=>d.values.ref==='POL-77')))`));
    record('T28. Calendar events keep the written-out date', evs.length > 0 && evs.every(e => /expires 30 Jun 2027/.test(e.title)));
    T.ev(`(()=>{ const m = { profiles:clone(state.profiles), types:clone(state.types), settings:clone(state.settings), documents:clone(state.documents) }; m.types.find(t=>t.id==='insurance').fields[0].sensitive = true; applyMerged(m); })()`);
    await T.waitFor(() => T.ev(`state.documents.filter(d=>d.typeId==='insurance').every(d=>!d.values.ref && !!d.sealed.ref)`), 2000).catch(() => {});
    record('T29. A field made sensitive on another device is protected here after sync', T.ev(`state.documents.filter(d=>d.typeId==='insurance').every(d=>!d.values.ref && !!d.sealed.ref)`));
  }

  /* ================= profiles, editor, archive, layout (M1 behaviour still holds) ================= */
  {
    const a = await open({ storage: saved });
    await unlock(a);
    await a.click('[data-act="openProfiles"]');
    await a.click('[data-act="addProfile"]');
    await a.type('#p-name', 'Amina <b>x</b>'); await a.type('#p-rel', 'Spouse');
    await a.click('[data-act="saveProfile"]');
    record('P1. Profile saved; names escaped', /Spouse · 0 documents/.test(a.text('#side-pane')) && !a.$('#list-pane .chips b'));
    await a.click('[data-act="back"]');
    const amina = a.ev(`state.profiles.find(p=>p.name.startsWith('Amina')).id`);
    const salim = a.ev(`state.profiles.find(p=>p.name==='Salim').id`);
    await a.click('[data-act="openProfiles"]');
    await a.click(`[data-act="editProfile"][data-id="${salim}"]`);
    await a.click('[data-act="deleteProfile"]');
    record('P2. Deleting a profile with documents asks move or archive', /has 2 documents/.test(a.text('#sheet')) && /Move to Amina/.test(a.text('#sheet')));
    await a.click('#sheet [data-act="sheetChoice"][data-i="0"]');
    record('P3. Documents moved to the other profile', a.ev(`state.documents.every(d=>d.ownerId===${JSON.stringify(amina)})`));
  }
  {
    const a = await open({ storage: saved });
    await unlock(a);
    await a.click(a.$$('#doc-list .row').find(r => /Passport/.test(r.textContent)));
    await a.click('[data-act="editDoc"]');
    await a.type('#f-issuer', 'Changed');
    await a.click('[data-act="back"]');
    record('E1. Leaving a changed editor asks to discard', /Discard changes/.test(a.text('#sheet')));
    await a.click('#sheet [data-act="sheetChoice"][data-i="0"]');
    record('E2. Discard keeps the original', /Kenya/.test(a.text('#side-pane')));
    await a.click('[data-act="docMore"]');
    await a.click('#sheet [data-act="sheetChoice"][data-i="1"]');
    record('E3a. Archiving asks why (not renewing)', /Not renewing/.test(a.text('#sheet')) && /Sold/.test(a.text('#sheet')));
    await a.click('#sheet [data-act="sheetChoice"][data-i="0"]');
    record('E3. Archive moves it out of the main list with its reason', /Show archived \(1\)/.test(a.text('#doc-list')) && /Archived: Sold/.test(a.text('#side-pane')));
    await a.click('[data-act="docMore"]');
    await a.click('#sheet [data-act="sheetChoice"][data-i="2"]');
    await a.click('#sheet [data-act="sheetChoice"][data-i="0"]');
    record('E4. Delete removes it', a.ev(`state.documents.length`) === 1 && !a.d.body.classList.contains('pane-open'));
  }
  {
    const a = await open({ storage: saved, width: 900 });
    await unlock(a);
    record('W1. Unfolded: layout mode fold, placeholder in the right pane', a.d.documentElement.getAttribute('data-layout') === 'fold' && /Select a document/.test(a.text('#side-pane')));
    await a.click(a.$$('#doc-list .row')[0]);
    await a.click(a.$$('#doc-list .row')[1]);
    record('W2. Picking another document replaces the right pane', a.ev('nav.length') === 1 && a.$$('#doc-list .row.sel').length === 1);
  }
  {
    const css = html.slice(html.indexOf('<style>') + 7, html.indexOf('</style>'));
    const start = css.indexOf('Unfolded / wide layout');
    const wide = css.slice(start).replace(/^[^*]*\*\//, '').replace(/\/\*[\s\S]*?\*\//g, '');
    const stmts = []; let depth = 0, s = 0;
    for (let i = 0; i < wide.length; i++){ if (wide[i] === '{') depth++; else if (wide[i] === '}'){ depth--; if (!depth){ stmts.push(wide.slice(s, i + 1).trim()); s = i + 1; } } }
    record('W3. Every wide-layout rule sits inside a media query', stmts.length >= 2 && stmts.every(x => /^@media/.test(x)));
    record('W4. Real builds use 310 000 PBKDF2 iterations', /window\.EXPIRY_PBKDF2_ITER \|\| 310000/.test(html));
    const mainScript = html.slice(html.lastIndexOf('<script>') + 8);
    record('W5b. No stray </script> inside the app script', mainScript.indexOf('</script>') === mainScript.lastIndexOf('</script>'));
  }

  const failed = results.filter(r => !r.pass);
  for (const r of results) console.log((r.pass ? 'PASS ' : 'FAIL ') + r.name + (r.pass || !r.detail ? '' : '  → ' + r.detail));
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  process.exit(failed.length ? 1 : 0);
}
main().catch(e => { for (const r of results) console.log((r.pass ? 'PASS ' : 'FAIL ') + r.name + (r.pass || !r.detail ? '' : '  → ' + r.detail)); console.error(e); process.exit(1); });
