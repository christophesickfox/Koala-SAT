/* app.js — Version finale fusionnée & chiffrée
   - AES-GCM-256 pour state.* (people, activities, backgrounds)
   - clé dérivée via PBKDF2(password, encSalt)
   - compatible SQLite (settings) + JSON export/import (chiffré)
   - conserve UI/admin/dnd existants
*/

/* =========================
   BLOC 1 — Helpers, sécurité & DB
   ================================ */

let db = null;
let state = {
  people: [],
  activities: [],
  backgrounds: {},
  settings: { bubbleSize: 72 }
};

const STORAGE = { LS_KEY: "sat_state", DB_KEY: "sat_db" };
const ICONS = ['🎨','⚽','🎵','📚','🍳','🚲','🖍️','🎤','🎬','🧩','🚀','🌳','🎯','🧪','🧱','🧘','🏊','🧺','🖼️','🎮','🧵','🎭','🎲','🏸','🏕️','🎈'];

function UID(){ return "_" + Math.random().toString(36).substr(2,9); }
function colorFrom(s){ if(!s) return '#999'; let h=0; for(let i=0;i<s.length;i++) h=(h*31+s.charCodeAt(i))%360; return `hsl(${h} 70% 48%)`; }

function ab2b64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function b642ab(b64){ const bin = atob(b64); return Uint8Array.from(bin, c => c.charCodeAt(0)).buffer; }
function buf2b64(buf){ return ab2b64(buf); }
function b642buf(b64){ return new Uint8Array(b642ab(b64)); }

/* PBKDF2 hash helper used for admin password storage (returns base64 bits) */
const PBKDF2_ITER = 100000;
async function hashPassword(password, saltBase64){
  const enc = new TextEncoder();
  const salt = b642ab(saltBase64);
  const key = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' }, key, 256);
  return ab2b64(bits);
}
function genSalt(){ const arr=new Uint8Array(16); crypto.getRandomValues(arr); return ab2b64(arr); }

/* AES key derive from password (for encrypt/decrypt) */
async function deriveAESKeyFromPassword(password, encSaltBase64){
  // encSaltBase64 is base64
  const enc = new TextEncoder();
  const salt = b642ab(encSaltBase64);
  const passKey = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' },
    passKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt','decrypt']
  );
  return key;
}

/* AES-GCM encrypt / decrypt helpers that operate on JS objects.
   They return/expect base64-encoded ciphertext + iv so easy to JSON-store.
*/
async function encryptObject(aesKey, obj){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext);
  return {
    iv: ab2b64(iv.buffer),
    data: ab2b64(ct)
  };
}
async function decryptObject(aesKey, payload){
  if(!payload || !payload.iv || !payload.data) throw new Error("invalid payload");
  const ivBuf = b642ab(payload.iv);
  const ctBuf = b642ab(payload.data);
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(ivBuf) }, aesKey, ctBuf);
  const dec = new TextDecoder();
  return JSON.parse(dec.decode(plainBuf));
}

/* masterKey is the CryptoKey for the session once admin unlocks or creates password.
   If null, we cannot encrypt/decrypt automatically and will prompt at restore if needed.
*/
let masterKey = null;

/* --- SQLite DB helpers (sql-wasm.wasm is local) --- */
async function initDB(){
  if(db) return db;
  try {
    const SQL = await initSqlJs({ locateFile: file => "sql-wasm.wasm" });
    db = new SQL.Database();
    db.run("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);");
    return db;
  } catch (err) {
    console.error("initDB error:", err);
    throw err;
  }
}

function persistDB(){
  if(!db) return;
  try {
    const data = db.export();
    const b64 = ab2b64(data);
    localStorage.setItem(STORAGE.DB_KEY, b64);
  } catch (err) { console.warn("persistDB failed:", err); }
}

/* restoreDB: will load DB from LS and attempt to restore state.
   If an encrypted state is present and no masterKey, it will prompt for password to decrypt.
*/
async function restoreDB(){
  try {
    const b64 = localStorage.getItem(STORAGE.DB_KEY);
    if(!b64) return;
    const SQL = await initSqlJs({ locateFile: file => "sql-wasm.wasm" });
    const data = b642ab(b64);
    db = new SQL.Database(new Uint8Array(data));

    // Try to read state_enc first (encrypted)
    const encRow = db.exec("SELECT value FROM settings WHERE key='state_enc'");
    if(encRow && encRow[0]){
      const payloadStr = encRow[0].values[0][0];
      try {
        const payload = JSON.parse(payloadStr);
        // If we have masterKey already, decrypt now
        if(masterKey){
          const s = await decryptObject(masterKey, payload);
          // loaded decrypted object expected to contain people/activities/backgrounds/settings
          if(s) {
            state.people = s.people || [];
            state.activities = s.activities || [];
            state.backgrounds = s.backgrounds || {};
            state.settings = s.settings || (state.settings || {});
          }
        } else {
          // attempt to prompt user for password to decrypt (transparent)
          const admin = getAdminRecord();
          if(admin && admin.encSalt){
            const pass = prompt("Entrez le mot de passe administrateur pour déchiffrer les données :");
            if(pass !== null && pass !== ''){
              try {
                const key = await deriveAESKeyFromPassword(pass, admin.encSalt);
                const s = await decryptObject(key, payload);
                masterKey = key; // keep for this session
                if(s){
                  state.people = s.people || [];
                  state.activities = s.activities || [];
                  state.backgrounds = s.backgrounds || {};
                  state.settings = s.settings || (state.settings || {});
                }
              } catch(err){
                console.warn("restoreDB: decrypt failed with provided password", err);
                // leave state as default (empty) — user can unlock later
              }
            }
          }
        }
      } catch(err) {
        console.warn("restoreDB: malformed state_enc", err);
      }
    } else {
      // fallback: read plaintext 'state' if present (older installs)
      const row = db.exec("SELECT value FROM settings WHERE key='state'");
      if(row && row[0] && row[0].values && row[0].values[0]){
        try {
          const s = JSON.parse(row[0].values[0][0]);
          state = Object.assign(state, s);
        } catch(e){ console.warn("restoreDB parse state failed", e); }
      }
    }
  } catch (err) {
    console.error("restoreDB error:", err);
  }
}

/* saveStateToDB: if masterKey available -> save encrypted payload into 'state_enc',
   otherwise save plaintext into 'state' key (legacy / during initial setup).
*/
async function saveStateToDB(){
  if(!db) return;
  try {
    if(masterKey){
      const payload = await encryptObject(masterKey, { people: state.people, activities: state.activities, backgrounds: state.backgrounds, settings: state.settings });
      db.run("DELETE FROM settings WHERE key='state_enc'");
      db.run("INSERT INTO settings (key,value) VALUES (?,?)", ["state_enc", JSON.stringify(payload)]);
      // remove plaintext fallback if any
      db.run("DELETE FROM settings WHERE key='state'");
      persistDB();
    } else {
      // plaintext fallback
      db.run("DELETE FROM settings WHERE key='state'");
      db.run("INSERT INTO settings (key,value) VALUES (?,?)", ["state", JSON.stringify(state)]);
      persistDB();
    }
  } catch (err) { console.error("saveStateToDB error:", err); }
}

function saveQuickState(){
  try { localStorage.setItem(STORAGE.LS_KEY, JSON.stringify(state)); } catch(e){ console.warn("saveQuickState failed", e); }
}

/* Admin record helpers (adminPass record will include:
    { salt: <base64>, hash: <base64>, encSalt: <base64> }
   - salt: used to produce stored hash (hashPassword)
   - encSalt: used to derive AES encryption key for data
*/
function getAdminRecord(){
  if(!db) return null;
  try {
    const row = db.exec("SELECT value FROM settings WHERE key='adminPass'");
    if(!row || !row[0]) return null;
    return JSON.parse(row[0].values[0][0]);
  } catch (err) {
    console.warn("getAdminRecord parse failed", err);
    return null;
  }
}

function saveAdminRecord(rec){
  if(!db) return;
  try {
    db.run("DELETE FROM settings WHERE key='adminPass'");
    db.run("INSERT INTO settings (key,value) VALUES (?,?)", ["adminPass", JSON.stringify(rec)]);
    persistDB();
  } catch (err) { console.error("saveAdminRecord error:", err); }
}

function policyCheck(pass){
  const reasons = [];
  if(!pass || pass.length < 12) reasons.push("au moins 12 caractères");
  let types = 0;
  if(/[a-z]/.test(pass)) types++;
  if(/[A-Z]/.test(pass)) types++;
  if(/[0-9]/.test(pass)) types++;
  if(/[^A-Za-z0-9]/.test(pass)) types++;
  if(types < 3) reasons.push("au moins 3 types de caractères différents");
  return { ok: reasons.length === 0, reasons };
}

/* ==============
   BLOC 2 — Render & helpers (unchanged logic, but ensure data-* IDs are set)
   ============== */

function renderBackground(){
  const d = new Date().toISOString().slice(0,10);
  if(state.backgrounds && state.backgrounds[d]) {
    const b = state.backgrounds[d];
    if(typeof b === 'string' && b.startsWith('data:image/')) document.body.style.backgroundImage = `url(${b})`;
    else document.body.style.backgroundImage = '';
  } else {
    document.body.style.backgroundImage = '';
  }
}

function renderCounter(){
  const el = document.getElementById("counterInfo");
  if(!el) return;
  el.textContent = `${(state.people||[]).length} enfants — ${(state.activities||[]).length} activités`;
}

function renderNamesAdmin(){
  const list = document.getElementById("namesAdminList");
  if(!list) return;
  list.innerHTML = "";
  (state.people || []).forEach(p=>{
    const row = document.createElement('div'); row.className='row';
    const who = document.createElement('div'); who.className='who';
    const bub = document.createElement('div'); bub.className='bubble'; bub.style.background = p.color || colorFrom(p.name); bub.textContent = (p.name||'')[0] || '?';
    // ensure admin panel bubbles do have data-id (useful)
    bub.dataset.id = p.id;
    const span = document.createElement('span'); span.textContent = p.name || '';
    who.appendChild(bub); who.appendChild(span);
    const actions = document.createElement('div');
    const edit = document.createElement('button'); edit.className='small'; edit.textContent='Édit';
    edit.addEventListener('click', ()=>{ const nv = prompt('Modifier nom', p.name); if(nv!==null){ const t = nv.trim(); if(t){ p.name=t; p.color=colorFrom(t); saveStateToDB(); saveQuickState(); renderAll(); } } });
    const del = document.createElement('button'); del.className='small'; del.textContent='Suppr';
    del.addEventListener('click', ()=>{ if(confirm('Supprimer '+p.name+' ?')){ state.people = state.people.filter(x=>x.id!==p.id); saveStateToDB(); saveQuickState(); renderAll(); } });
    actions.appendChild(edit); actions.appendChild(del);
    row.appendChild(who); row.appendChild(actions);
    list.appendChild(row);
  });
}

function renderChildNames() {
  const wrap = document.getElementById('childNames');
  if (!wrap) return;
  wrap.innerHTML = '';

  const container = document.createElement('div');
  container.style.display = 'flex';
  container.style.flexWrap = 'wrap';
  container.style.gap = '8px';

  (state.people || []).forEach(p => {
    if (p.activityId) return; // seulement les enfants non assignés
    const b = document.createElement('div');
    b.className = 'bubble';
    b.textContent = (p.name || '').split(' ')[0] || '?';
    b.title = p.name;
    b.dataset.id = p.id; // indispensable pour le drag
    b.style.background = p.color || colorFrom(p.name);
    b.style.minWidth = (state.settings.bubbleSize || 72) + 'px';
    b.style.height = (state.settings.bubbleSize || 72) + 'px';
    container.appendChild(b);
  });

  wrap.appendChild(container);
  // attachBubbleEvents and adjustBubbleSizes are called by renderAll after all renders
}

function renderActivities(){
  const wrap = document.getElementById("activities");
  if(!wrap) return;
  wrap.innerHTML = "";
  (state.activities || []).forEach(act=>{
    const card = document.createElement('div'); card.className='activity-card';
    if(act.type === 'image' && typeof act.data === 'string' && act.data.startsWith('data:image/')) {
      card.style.background = `url(${act.data}) center/cover`; card.style.backgroundSize = 'cover';
      card.style.backgroundPosition = 'center';
    } else {
      card.style.background = act.data || '#c7d2fe';
    }
    const title = document.createElement('div'); title.className='act-title';
    const left = document.createElement('div'); left.className='act-left';
    const ic = document.createElement('div'); ic.className='act-ic'; ic.textContent = act.icon || '🎯';
    // attach clickable icon handler (open icon chooser)
    ic.addEventListener('click', (ev) => {
      ev.stopPropagation();
      openIconMenu(ev, act);
    });
    const name = document.createElement('div'); name.className='act-name'; name.textContent = act.title || 'Activité';
    left.appendChild(ic); left.appendChild(name);
    const del = document.createElement('button'); del.className='small'; del.textContent='✕';
    del.addEventListener('click', ()=>{ if(confirm('Supprimer activité ?')){ state.activities = state.activities.filter(a=>a.id!==act.id); state.people.forEach(p=>{ if(p.activityId===act.id) p.activityId=null; }); saveStateToDB(); saveQuickState(); renderAll(); }});
    title.appendChild(left); title.appendChild(del);
    card.appendChild(title);
    const dz = document.createElement('div'); dz.className='dropzone'; dz.dataset.id = act.id;
    card.appendChild(dz);
    wrap.appendChild(card);
  });
  renderMembers();
}

/* renderMembers() — places assigned bubbles inside dropzones (with data-id) */
function renderMembers(){
  document.querySelectorAll('.dropzone').forEach(dz => dz.innerHTML = '');
  (state.people || []).forEach(p=>{
    if(!p.activityId) return;
    const dz = document.querySelector(`.dropzone[data-id='${p.activityId}']`);
    if(!dz) return;
    const bub = document.createElement('div'); bub.className='bubble';
    // show a short label (first name)
    bub.textContent = (p.name||'').split(' ')[0] || (p.name||'?');
    bub.title = p.name;
    bub.dataset.id = p.id; // important
    bub.style.background = p.color || colorFrom(p.name);
    bub.style.minWidth = (state.settings.bubbleSize||72)+'px';
    bub.style.height = (state.settings.bubbleSize||72)+'px';
    dz.appendChild(bub);
  });
}

/* renderAll — Rendu global de l’application
   (corrigé pour rattacher les événements après DOM update)
*/
function renderAll() {
  try {
    renderNamesAdmin();      // panneau admin
    renderChildNames();      // liste enfants libres
    renderActivities();      // cartes d’activités
    renderBackground();      // fond décoratif
    renderCounter();         // compteur si existant

    // Attacher events après mise à jour du DOM
    setTimeout(() => {
      attachBubbleEvents();   // rend les bulles draggables
      adjustBubbleSizes();    // adapte la taille après insertion
      console.log("✅ renderAll → bulles prêtes :", document.querySelectorAll(".bubble").length);
    }, 0);

  } catch (err) {
    console.error("Erreur dans renderAll :", err);
  }
}

/* ======================================================
   BLOC 3 — Drag & Drop handlers (stable, non intrusif)
   ====================================================== */
let dragging = null;

function onPointerDown(e) {
  // only start drag for bubble elements
  const el = e.currentTarget;
  if (!el || !el.classList.contains('bubble')) return;

  // don't start drag if pointer started on an input inside a bubble (safety)
  if (e.target.closest('input,button,textarea')) return;

  e.preventDefault();
  e.stopPropagation();

  const rect = el.getBoundingClientRect();

  // create clone
  const clone = el.cloneNode(true);
  clone.classList.add('dragging-clone');
  // initial position matches original
  clone.style.position = 'fixed';
  clone.style.left = rect.left + 'px';
  clone.style.top = rect.top + 'px';
  clone.style.width = rect.width + 'px';
  clone.style.height = rect.height + 'px';
  clone.style.pointerEvents = 'none';
  clone.style.zIndex = '99999';
  clone.style.opacity = '0.95';

  document.body.appendChild(clone);
  el.style.visibility = 'hidden';

  dragging = {
    el,
    clone,
    pid: el.dataset.id,
    offsetX: e.clientX - rect.left,
    offsetY: e.clientY - rect.top
  };

  window.addEventListener('pointermove', onPointerMove);
  window.addEventListener('pointerup', onPointerUp);

  // debug
  console.debug('drag:start', dragging && dragging.pid);
}

function onPointerMove(e) {
  if (!dragging) return;
  // update clone position so it follows pointer
  const x = e.clientX - dragging.offsetX;
  const y = e.clientY - dragging.offsetY;
  if (dragging.clone) {
    dragging.clone.style.left = x + 'px';
    dragging.clone.style.top = y + 'px';
  }

  // highlight dropzone under pointer
  document.querySelectorAll('.dropzone').forEach(z => z.classList.remove('highlight'));
  const under = document.elementFromPoint(e.clientX, e.clientY);
  const dz = under && under.closest ? under.closest('.dropzone') : null;
  if (dz) dz.classList.add('highlight');
}

function onPointerUp(e) {
  if (!dragging) return;

  // compute drop target
  const under = document.elementFromPoint(e.clientX, e.clientY);
  const dz = under && under.closest ? under.closest('.dropzone') : null;

  // restore original visibility and remove clone asap
  try { if (dragging.el) dragging.el.style.visibility = ''; } catch(err){}
  try { if (dragging.clone && dragging.clone.remove) dragging.clone.remove(); } catch(err){}

  // remove visual highlights
  document.querySelectorAll('.dropzone').forEach(z => z.classList.remove('highlight'));

  // if dropped on a valid dropzone, assign activityId BEFORE render
  if (dz && dragging.pid) {
    const person = (state.people || []).find(p => p.id === dragging.pid);
    if (person) {
      person.activityId = dz.dataset.id || null;
      console.debug(`assigned ${person.name} -> ${person.activityId}`);
      try { saveStateToDB(); } catch(e){ console.warn(e); }
      try { saveQuickState(); } catch(e) {}
    }
  } else {
    // if dropped outside, unassign only when dropped back on names area
    const back = under && under.closest ? (under.closest('#namesAdminList') || under.closest('#childNames') || under.closest('.names-admin')) : null;
    if (back && dragging.pid) {
      const person = (state.people || []).find(p => p.id === dragging.pid);
      if (person) {
        person.activityId = null;
        try { saveStateToDB(); } catch(e){ console.warn(e); }
        try { saveQuickState(); } catch(e) {}
        console.debug(`unassigned ${person.name}`);
      }
    }
  }

  // cleanup listeners
  window.removeEventListener('pointermove', onPointerMove);
  window.removeEventListener('pointerup', onPointerUp);

  dragging = null;

  // refresh UI after persistence
  try { renderAll(); } catch(err){ console.error('renderAll error after drop:', err); }
}

function attachBubbleEvents() {
  const bubbles = document.querySelectorAll('.bubble');
  bubbles.forEach(b => {
    // ensure no duplicate listeners
    b.style.touchAction = 'none';
    b.removeEventListener('pointerdown', onPointerDown);
    b.addEventListener('pointerdown', onPointerDown);
  });
  console.debug('attachBubbleEvents →', bubbles.length);
}

function adjustBubbleSizes() {
  const base = (state.settings && state.settings.bubbleSize) ? state.settings.bubbleSize : 72;
  document.querySelectorAll('.bubble').forEach(bubble => {
    const txt = (bubble.textContent || '').trim();
    const extra = Math.min(80, Math.max(0, txt.length - 6) * 6);
    const width = base + extra;
    bubble.style.minWidth = width + 'px';
    bubble.style.height = base + 'px';
    bubble.style.lineHeight = base + 'px';
    bubble.style.fontSize = (base * 0.28) + 'px';
    bubble.style.borderRadius = (base / 2) + 'px';
  });
}

/* ==============
   BLOC 4 — showPasswordSetup + admin UI builder
   ============== */

/* showPasswordSetup modal: creates admin password and stores salt+hash+encSalt */
function showPasswordSetup(opts = {}) {
  const existing = document.getElementById("passwordSetupModal");
  if (existing) existing.remove();

  const modal = document.createElement("div");
  modal.id = "passwordSetupModal";
  modal.style = "position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.5);z-index:99999";
  modal.innerHTML = `
    <div style="background:#fff;padding:18px;border-radius:10px;max-width:420px;width:92%;">
      <h3 style="margin:0 0 8px 0">${opts.title || "Créer un mot de passe administrateur"}</h3>
      <p style="margin:0 0 8px 0">Choisissez un mot de passe fort (12 caractères minimum, 3 types).</p>
      <input id="newAdminPass" type="password" placeholder="Nouveau mot de passe" style="width:100%;padding:8px;margin-bottom:8px"/>
      <input id="confirmAdminPass" type="password" placeholder="Confirme le mot de passe" style="width:100%;padding:8px;margin-bottom:8px"/>
      <div style="display:flex;justify-content:flex-end;gap:8px">
        <button id="cancelAdminPass">Annuler</button>
        <button id="saveAdminPass" style="background:#2563eb;color:#fff;border:none;padding:8px 12px;border-radius:6px">Enregistrer</button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);

  modal.querySelector("#cancelAdminPass").addEventListener("click", () => modal.remove());
  modal.querySelector("#saveAdminPass").addEventListener("click", async () => {
    const p1 = (document.getElementById("newAdminPass").value || "").trim();
    const p2 = (document.getElementById("confirmAdminPass").value || "").trim();
    if (!p1 || !p2) { alert("Remplissez les deux champs."); return; }
    if (p1 !== p2) { alert("Les mots de passe ne correspondent pas."); return; }
    const chk = policyCheck(p1);
    if (!chk.ok) { alert("Mot de passe non conforme : " + chk.reasons.join(", ")); return; }
    try {
      const salt = genSalt();      // used for stored password hash
      const encSalt = genSalt();   // used to derive AES key
      const hash = await hashPassword(p1, salt);
      saveAdminRecord({ salt, hash, encSalt });
      // derive masterKey for session so we can immediately encrypt future saves
      masterKey = await deriveAESKeyFromPassword(p1, encSalt);
      // persist current state encrypted now
      await saveStateToDB();
      modal.remove();
      alert("Mot de passe enregistré.");
      renderAll();
    } catch (err) {
      console.error("save admin pass error:", err);
      alert("Erreur technique lors de l'enregistrement.");
    }
  });
}

/* buildAdminUIIfMissing: safe builder that won't throw if HTML already contains parts */
function buildAdminUIIfMissing(){
  // Ensure adminPanel exists in HTML (original HTML had <section id="adminPanel">)
  const adminPanel = document.getElementById("adminPanel");
  if(!adminPanel) {
    const ap = document.createElement("section");
    ap.id = "adminPanel";
    ap.style.display = "block";
    ap.innerHTML = `<div id="adminArea" class="stack"></div>`;
    document.body.appendChild(ap);
  }

  let adminArea = document.getElementById("adminArea");
  if(!adminArea){
    adminArea = document.createElement("div");
    adminArea.id = "adminArea";
    adminArea.className = "stack";
    adminArea.style.display = "none";
    document.getElementById("adminPanel")?.appendChild(adminArea);
  }

  // If already inited, return
  if(adminArea.dataset.inited === "1") return;
  adminArea.dataset.inited = "1";

  // Build admin controls (match PoC fields)
  adminArea.innerHTML = `
    <h2>Prénoms (max 150)</h2>
    <div class="form-row search">
      <input id="newName" class="field" placeholder="Prénom Nom" />
      <button id="addName" class="small">Ajouter</button>
    </div>
    <div class="form-row">
      <label class="chip">Taille des bulles: <input id="bubbleSize" type="range" min="52" max="120" value="${state.settings.bubbleSize||72}" /> <span id="bubbleSizeVal">${state.settings.bubbleSize||72}</span>px</label>
      <button id="sortAZ" class="small">Trier A→Z</button>
    </div>
    <div id="namesAdminList" class="names-admin"></div>

    <h2>Créer activité</h2>
    <div class="form-row"><input id="actTitle" class="field" placeholder="Titre activité" /></div>
    <div class="form-row">
      <select id="actType" class="field"><option value="image">Image</option><option value="color">Couleur</option></select>
      <input id="actColor" class="field" type="color" value="#ff7f50" />
    </div>
    <div class="form-row">
      <input id="actFile" class="field" type="file" accept="image/*" />
      <button id="addAct" class="small">Ajouter activité</button>
    </div>

    <h2>Fonds journaliers</h2>
    <div class="form-row">
      <input id="bgDate" class="field" type="date" />
      <input id="bgFile" class="field" type="file" accept="image/*" />
      <button id="addBg" class="small">Ajouter fond</button>
    </div>

    <h2>Options</h2>
    <div class="form-row">
      <button id="resetDay" class="small">Réinitialiser la journée</button>
      <button id="exportBtn" class="small">Exporter JSON</button>
      <input id="importFile" class="field" type="file" accept="application/json" />
    </div>
    <div class="form-row">
      <button id="changePassBtn" class="small">Changer mot de passe</button>
    </div>
  `;

  // Hook admin controls safely (check existence before binding)
  const addNameBtn = document.getElementById("addName");
  const newNameInput = document.getElementById("newName");
  if(addNameBtn && newNameInput){
    addNameBtn.addEventListener("click", ()=>{
      const v = (newNameInput.value||"").trim();
      if(!v) return alert("Prénom vide.");
      if((state.people||[]).length>=150) return alert("Limite atteinte (150).");
      if((state.people||[]).some(p=>p.name.toLowerCase()===v.toLowerCase())) return alert("Ce prénom existe déjà.");
      state.people.push({ id: UID(), name: v, activityId: null, color: colorFrom(v) });
      saveStateToDB(); saveQuickState(); newNameInput.value=''; renderAll();
    });
    newNameInput.addEventListener("keydown", e=>{ if(e.key==='Enter') addNameBtn.click(); });
  }

  const sortAZBtn = document.getElementById("sortAZ");
  if(sortAZBtn){ sortAZBtn.addEventListener("click", ()=>{ state.people.sort((a,b)=>a.name.localeCompare(b.name,'fr')); saveStateToDB(); saveQuickState(); renderAll(); }); }

  const bubbleSizeInput = document.getElementById("bubbleSize");
  const bubbleSizeVal = document.getElementById("bubbleSizeVal");
  if(bubbleSizeInput && bubbleSizeVal){
    bubbleSizeInput.addEventListener("input", ()=>{
      state.settings.bubbleSize = parseInt(bubbleSizeInput.value, 10);
      bubbleSizeVal.textContent = bubbleSizeInput.value;
      saveStateToDB(); saveQuickState(); renderAll();
    });
  }

  const addActBtn = document.getElementById("addAct");
  const actTitle = document.getElementById("actTitle");
  const actType = document.getElementById("actType");
  const actColor = document.getElementById("actColor");
  const actFile = document.getElementById("actFile");
  if(addActBtn && actTitle && actType && actColor && actFile){
    addActBtn.addEventListener("click", ()=>{
      const title = (actTitle.value||"").trim();
      if(!title) return alert("Titre requis");
      if(actType.value === 'image'){
        const f = actFile.files && actFile.files[0];
        if(!f) return alert("Choisis une image");
        if(f.size > 2_000_000) return alert("Fichier trop volumineux (max 2 Mo)");
        const r = new FileReader();
        r.onload = () => { state.activities.push({ id: UID(), title, type:'image', data: r.result, icon:'🖼️' }); saveStateToDB(); saveQuickState(); renderAll(); actTitle.value=''; actFile.value=''; };
        r.readAsDataURL(f);
      } else {
        state.activities.push({ id: UID(), title, type:'color', data: actColor.value, icon:'🎨' });
        saveStateToDB(); saveQuickState(); renderAll(); actTitle.value='';
      }
    });
  }

  const addBgBtn = document.getElementById("addBg");
  const bgDate = document.getElementById("bgDate");
  const bgFile = document.getElementById("bgFile");
  if(addBgBtn && bgDate && bgFile){
    addBgBtn.addEventListener("click", ()=>{
      const date = bgDate.value;
      if(!date) return alert("Choisis une date");
      const f = bgFile.files && bgFile.files[0];
      if(!f) return alert("Choisis un fichier");
      if(f.size > 2_000_000) return alert("Fichier trop volumineux (max 2 Mo)");
      const r = new FileReader();
      r.onload = () => {
        state.backgrounds = state.backgrounds || {};
        state.backgrounds[date] = r.result;
        saveStateToDB(); saveQuickState(); renderAll();
        bgDate.value=''; bgFile.value='';
      };
      r.readAsDataURL(f);
    });
  }

  const resetDayBtn = document.getElementById("resetDay");
  if(resetDayBtn){ resetDayBtn.addEventListener("click", ()=>{ if(!confirm('Réinitialiser la journée ?')) return; state.people.forEach(p=>p.activityId=null); saveStateToDB(); saveQuickState(); renderAll(); }); }

  const exportBtn = document.getElementById("exportBtn");
  if(exportBtn){
    exportBtn.addEventListener("click", async ()=>{
      // export encrypted if masterKey available, else ask password to produce encrypted export
      try {
        let payload;
        if(masterKey){
          payload = await encryptObject(masterKey, { people: state.people, activities: state.activities, backgrounds: state.backgrounds, settings: state.settings });
          payload.type = "encrypted";
        } else {
          // try to get admin rec and ask password to export encrypted
          const admin = getAdminRecord();
          if(admin && admin.encSalt){
            const pass = prompt("Entrez le mot de passe admin pour exporter les données chiffrées (ou annulez pour exporter en clair) :");
            if(pass){
              const key = await deriveAESKeyFromPassword(pass, admin.encSalt);
              payload = await encryptObject(key, { people: state.people, activities: state.activities, backgrounds: state.backgrounds, settings: state.settings });
              payload.type = "encrypted";
            } else {
              // export plain JSON
              payload = { type: "plain", people: state.people, activities: state.activities, backgrounds: state.backgrounds, settings: state.settings };
            }
          } else {
            payload = { type: "plain", people: state.people, activities: state.activities, backgrounds: state.backgrounds, settings: state.settings };
          }
        }
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a'); a.href = url; a.download = 'centre_loisirs_export.json'; a.click(); URL.revokeObjectURL(url);
      } catch(err){ console.error("export error:", err); alert("Erreur lors de l'export"); }
    });
  }

  const importFile = document.getElementById("importFile");
  if(importFile){
    importFile.addEventListener("change", (ev)=>{
      const f = ev.target.files[0];
      if(!f) return;
      const r = new FileReader();
      r.onload = async ()=>{
        try {
          const imported = JSON.parse(r.result);
          if(imported.type === "encrypted" && imported.iv && imported.data){
            // ask password to decrypt or use masterKey
            try {
              let key = masterKey;
              if(!key){
                const admin = getAdminRecord();
                if(!admin || !admin.encSalt) throw new Error("Aucun admin encSalt");
                const pass = prompt("Mot de passe admin pour déchiffrer l'import :");
                if(!pass) throw new Error("Mot de passe absent");
                key = await deriveAESKeyFromPassword(pass, admin.encSalt);
                // do not automatically set masterKey from import
              }
              const s = await decryptObject(key, imported);
              if(confirm('Importer va remplacer l’état actuel. Continuer ?')){
                state = Object.assign(state, s);
                await saveStateToDB();
                saveQuickState();
                renderAll();
                alert('Import OK');
              }
            } catch(err){ console.error("import decrypt failed", err); alert("Impossible de déchiffrer l'import"); }
          } else {
            // plain import
            if(confirm('Importer va remplacer l’état actuel. Continuer ?')){
              state = Object.assign(state, imported);
              saveStateToDB();
              saveQuickState();
              renderAll();
              alert('Import OK');
            }
          }
        } catch(e){ console.error("import parse error", e); alert('Fichier invalide'); }
      };
      r.readAsText(f);
    });
  }

  const changePassBtn = document.getElementById("changePassBtn");
  if(changePassBtn){
    changePassBtn.addEventListener("click", async ()=>{
      const current = prompt('Mot de passe actuel :');
      if(current===null) return;
      const admin = getAdminRecord();
      if(!admin){ alert('Aucun mot de passe enregistré'); return; }
      const ok = (await hashPassword(current, admin.salt)) === admin.hash;
      if(!ok){ alert('Mot de passe actuel incorrect'); return; }

      const np = prompt('Nouveau mot de passe :'); if(!np) return;
      const np2 = prompt('Confirmer nouveau mot de passe :'); if(np !== np2){ alert('Les mots de passe ne correspondent pas'); return; }
      const chk = policyCheck(np);
      if(!chk.ok){ alert("Mot de passe non conforme : " + chk.reasons.join(", ")); return; }

      // re-encrypt with new encSalt derived from new password
      try {
        const newSalt = genSalt();
        const newEncSalt = genSalt();
        const newHash = await hashPassword(np, newSalt);
        const newKey = await deriveAESKeyFromPassword(np, newEncSalt);

        // decrypt current encrypted stored state (if any) with old masterKey or ask current password
        // get encrypted blob
        const row = db.exec("SELECT value FROM settings WHERE key='state_enc'");
        let currentStateObj = { people: state.people, activities: state.activities, backgrounds: state.backgrounds, settings: state.settings };
        if(row && row[0]){
          try {
            const payload = JSON.parse(row[0].values[0][0]);
            // try to decrypt with current masterKey or current password
            let decryptKey = masterKey;
            if(!decryptKey){
              decryptKey = await deriveAESKeyFromPassword(current, admin.encSalt);
            }
            currentStateObj = await decryptObject(decryptKey, payload);
          } catch(e){ console.warn("changePass: unable to decrypt existing state, will re-encrypt current in-memory state", e); }
        }
        // store new admin record
        saveAdminRecord({ salt: newSalt, hash: newHash, encSalt: newEncSalt });
        // set masterKey to newKey and persist state encrypted with it
        masterKey = newKey;
        state.people = currentStateObj.people || [];
        state.activities = currentStateObj.activities || [];
        state.backgrounds = currentStateObj.backgrounds || {};
        state.settings = currentStateObj.settings || state.settings || {};
        await saveStateToDB();
        alert('Mot de passe changé et données ré-encryptées.');
        renderAll();
      } catch(err){ console.error("changePass error", err); alert('Erreur lors du changement de mot de passe'); }
    });
  }
}

/* icon menu (simple) */
const iconMenuEl = document.getElementById("iconMenu");
function openIconMenu(ev, act){
  if(!iconMenuEl) return;
  iconMenuEl.innerHTML = '';
  ICONS.forEach(sym=>{
    const span=document.createElement('span'); span.textContent=sym;
    span.addEventListener('click', ()=>{
      act.icon = sym;
      saveStateToDB(); saveQuickState(); renderAll();
      iconMenuEl.style.display = 'none';
    });
    iconMenuEl.appendChild(span);
  });
  iconMenuEl.style.display = 'flex';
  iconMenuEl.style.left = Math.min(ev.clientX + 6, window.innerWidth - iconMenuEl.offsetWidth - 8) + 'px';
  iconMenuEl.style.top = Math.min(ev.clientY + 6, window.innerHeight - iconMenuEl.offsetHeight - 8) + 'px';
}
document.addEventListener('click', (ev) => {
  if(!ev.target.closest('#iconMenu') && !ev.target.classList.contains('act-ic')) {
    const el = document.getElementById('iconMenu');
    if(el) el.style.display = 'none';
  }
});

/* ==============
   BLOC 5 — single DOMContentLoaded + init wiring
   ============== */

document.addEventListener("DOMContentLoaded", async () => {
  try {
    // Ensure sqlite resources available and DB init
    await initDB();
    await restoreDB();

    // Build admin UI (safe)
    buildAdminUIIfMissing();

    // If no admin record -> ask for password creation
    const admin = getAdminRecord();
    if(!admin || !admin.hash || !admin.salt){
      // small delay to let DOM settle
      setTimeout(()=> showPasswordSetup({ title: "Initialiser le mot de passe administrateur" }), 150);
    }

    // Wire top controls if present in original HTML
    document.getElementById("enterFull")?.addEventListener("click", ()=> {
      if(document.fullscreenElement) document.exitFullscreen().catch(()=>{});
      else document.documentElement.requestFullscreen?.().catch(()=>{});
    });

    document.getElementById("openAdmin")?.addEventListener("click", ()=>{
      const ap = document.getElementById("adminPanel"); if(ap) ap.style.display = 'block';
      const aa = document.getElementById("adminArea"); if(aa) aa.style.display = 'block';
      buildAdminUIIfMissing();
    });

    document.getElementById("hideUI")?.addEventListener("click", ()=>{
      const ap = document.getElementById("adminPanel"); if(ap) ap.style.display = 'none';
    });

    // unlock button handler (safe)
    const unlockBtn = document.getElementById("unlockBtn");
    if(unlockBtn){
      unlockBtn.addEventListener("click", async ()=>{
        const passInput = document.getElementById("adminPassInput");
        const pass = passInput && passInput.value ? passInput.value.trim() : "";
        if(!pass){ alert("Veuillez entrer le mot de passe."); return; }
        const adminRec = getAdminRecord();
        if(!adminRec){ alert("Aucun mot de passe configuré. Merci de le définir."); return; }
        try {
          const ok = (await hashPassword(pass, adminRec.salt)) === adminRec.hash;
          if(ok){
            // derive AES master key for session
            try {
              masterKey = await deriveAESKeyFromPassword(pass, adminRec.encSalt);
            } catch(e){
              console.warn("derive masterKey failed", e);
              masterKey = null;
            }
            document.getElementById("adminArea") && (document.getElementById("adminArea").style.display = 'block');
            if(passInput) passInput.value = '';
            // After unlocking, if an encrypted state existed, ensure it's decrypted and applied
            // restoreDB would have attempted decrypt earlier; but if decrypt deferred, try now
            const encRow = db.exec("SELECT value FROM settings WHERE key='state_enc'");
            if(encRow && encRow[0]){
              try {
                const payload = JSON.parse(encRow[0].values[0][0]);
                const s = await decryptObject(masterKey, payload);
                if(s){
                  state.people = s.people || [];
                  state.activities = s.activities || [];
                  state.backgrounds = s.backgrounds || {};
                  state.settings = s.settings || state.settings || {};
                }
              } catch(e){ console.warn("post-unlock decrypt failed", e); }
            }
            renderAll();
          } else {
            alert("Mot de passe incorrect.");
          }
        } catch (err) {
          console.error("unlock error:", err);
          alert("Erreur lors de la vérification du mot de passe.");
        }
      });
    }

    // seed demo content if empty
    if((state.activities||[]).length === 0 && (state.people||[]).length === 0){
      state.activities.push({ id: UID(), title:'Peinture', type:'color', data:'#ff7f50', icon:'🎨' });
      state.activities.push({ id: UID(), title:'Jeux Extérieurs', type:'color', data:'#4caf50', icon:'⚽' });
      state.activities.push({ id: UID(), title:'Atelier Cuisine', type:'color', data:'#2196f3', icon:'🍳' });
      ['Albert Einstein','Nicolas Tesla','Jeveuxpas Faireactivite','Alain Turing','Isaac N'].forEach(n=> state.people.push({ id: UID(), name: n, activityId: null, color: colorFrom(n) }));
      await saveStateToDB(); saveQuickState();
    }

    // final render
    renderAll();

  } catch (err) {
    console.error("Erreur d'init:", err);
    alert("Erreur lors de l'initialisation : " + (err && err.message ? err.message : String(err)));
  }
});
