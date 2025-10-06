/* 
   Bloc 1 complet — Helpers, sécurité, SQLite
   ========================================== */

const STORAGE = 'cl_pro_v2';        // clé pour état non-SQLite (ui, settings légers)
const SQLITE_KEY = 'sqliteDB';     // clé localStorage pour la DB SQLite exportée

// Icônes utilitaires
const ICONS = ["🎨","⚽","🎵","📚","🍳","🚲","🖍️","🎤","🎬","🧩","🚀","🌳","🎯","🧪","🧱","🧘","🏊","🧺","🖼️","🎮","🧵","🎭","🎲","🏸","🏕️","🎈"];

// État mémoire (utile avant/à côté de la SQLite)
let state = { people: [], activities: [], backgrounds: {}, settings: { bubbleSize: 72 } };

// restore quick state (non-SQLite)
try {
  const raw = localStorage.getItem(STORAGE);
  if (raw) state = JSON.parse(raw);
} catch (e) {
  console.warn("Impossible de lire STORAGE", e);
}

// petits utils
const UID = () => Date.now().toString(36) + Math.random().toString(36).slice(2,8);
const todayISO = (d = new Date()) => d.toISOString().slice(0,10);
const colorFrom = (s) => { let h=0; for (let i=0;i<s.length;i++) h=(h*31+s.charCodeAt(i))%360; return `hsl(${h} 70% 48%)`; };
const saveQuickState = () => localStorage.setItem(STORAGE, JSON.stringify(state));

// === base64 <-> ArrayBuffer helpers ===
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i=0;i<bytes.byteLength;i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i=0;i<len;i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// === PBKDF2 helpers (Web Crypto) ===
// pbkdf2(password, saltUint8) => ArrayBuffer derived bits (32 bytes)
async function pbkdf2(password, saltUint8) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltUint8, iterations: 100000, hash: "SHA-256" },
    key,
    256
  );
  return derived; // ArrayBuffer
}

// hashPasswordB64(password, saltB64) -> base64 hash
async function hashPasswordB64(password, saltB64) {
  const saltBuf = base64ToArrayBuffer(saltB64);
  const derived = await pbkdf2(password, new Uint8Array(saltBuf));
  return arrayBufferToBase64(derived);
}

// verifyPasswordRecord(password, record) where record = { salt: base64, hash: base64 }
async function verifyPasswordRecord(password, record) {
  if (!record || !record.salt || !record.hash) return false;
  const h = await hashPasswordB64(password, record.salt);
  return h === record.hash;
}

// generateSaltB64()
function generateSaltB64(len = 16) {
  const arr = crypto.getRandomValues(new Uint8Array(len));
  return arrayBufferToBase64(arr.buffer);
}

// === Image sanitization: convert to PNG DataURL (no SVG allowed) ===
async function sanitizeFileToPNGDataURL(file) {
  if (!file || !file.type) throw new Error("Fichier invalide");
  if (file.type === "image/svg+xml" || /\.svg$/i.test(file.name)) throw new Error("SVG interdit pour des raisons de sécurité");
  const bitmap = await createImageBitmap(file);
  const MAX = 2048;
  const ratio = Math.min(1, MAX / Math.max(bitmap.width, bitmap.height));
  const w = Math.max(1, Math.round(bitmap.width * ratio));
  const h = Math.max(1, Math.round(bitmap.height * ratio));
  const c = document.createElement("canvas");
  c.width = w; c.height = h;
  const ctx = c.getContext("2d");
  ctx.drawImage(bitmap, 0, 0, w, h);
  bitmap.close?.();
  return c.toDataURL("image/png");
}

// === SQLite DB management ===
let db = null;

/**
 * initDB()
 * - initialise la DB et crée les tables si besoin
 * - NE met PAS de mot de passe par défaut
 */
async function initDB() {
  if (typeof initSqlJs !== "function") {
    throw new Error("initSqlJs (sql.js) non disponible — vérifie l'inclusion de sql-wasm.min.js");
  }
  const SQL = await initSqlJs({ locateFile: file => `sql-wasm.wasm` });
  db = new SQL.Database();
  // tables utiles : settings, people, activities, backgrounds
  db.run("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)");
  db.run("CREATE TABLE IF NOT EXISTS people (id TEXT PRIMARY KEY, name TEXT, activityId TEXT, color TEXT)");
  db.run("CREATE TABLE IF NOT EXISTS activities (id TEXT PRIMARY KEY, title TEXT, type TEXT, data TEXT, icon TEXT)");
  db.run("CREATE TABLE IF NOT EXISTS backgrounds (day TEXT PRIMARY KEY, url TEXT)");
}

/**
 * persistDB()
 * - exporte la DB et sauvegarde en base64 dans localStorage (clé SQLITE_KEY)
 */
function persistDB() {
  if (!db) return;
  try {
    const data = db.export();
    const b64 = arrayBufferToBase64(data);
    localStorage.setItem(SQLITE_KEY, b64);
  } catch (e) {
    console.error("persistDB error", e);
  }
}

/**
 * restoreDB()
 * - restaure la DB depuis localStorage si présente, sinon initDB()
 */
async function restoreDB() {
  if (typeof initSqlJs !== "function") {
    throw new Error("initSqlJs (sql.js) non disponible — vérifie l'inclusion de sql-wasm.min.js");
  }
  const SQL = await initSqlJs({ locateFile: file => `sql-wasm.wasm` });
  const b64 = localStorage.getItem(SQLITE_KEY);
  if (b64) {
    try {
      const u8 = new Uint8Array(base64ToArrayBuffer(b64));
      db = new SQL.Database(u8);
    } catch (e) {
      console.warn("restoreDB: erreur, on re-init la DB", e);
      db = new SQL.Database();
      db.run("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)");
      db.run("CREATE TABLE IF NOT EXISTS people (id TEXT PRIMARY KEY, name TEXT, activityId TEXT, color TEXT)");
      db.run("CREATE TABLE IF NOT EXISTS activities (id TEXT PRIMARY KEY, title TEXT, type TEXT, data TEXT, icon TEXT)");
      db.run("CREATE TABLE IF NOT EXISTS backgrounds (day TEXT PRIMARY KEY, url TEXT)");
      persistDB();
    }
  } else {
    // pas de DB sauvegardée → init propre
    db = new SQL.Database();
    db.run("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS people (id TEXT PRIMARY KEY, name TEXT, activityId TEXT, color TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS activities (id TEXT PRIMARY KEY, title TEXT, type TEXT, data TEXT, icon TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS backgrounds (day TEXT PRIMARY KEY, url TEXT)");
    persistDB();
  }
  // charger l'état depuis la DB dans la variable state (optionnel)
  loadStateFromDB();
}

/**
 * loadStateFromDB()
 * - charge people/activities/backgrounds/settings dans state depuis la DB
 */
function loadStateFromDB() {
  if (!db) return;
  state.people = [];
  let s = db.prepare("SELECT id,name,activityId,color FROM people");
  while (s.step()) state.people.push(s.getAsObject());
  s.free();

  state.activities = [];
  s = db.prepare("SELECT id,title,type,data,icon FROM activities");
  while (s.step()) state.activities.push(s.getAsObject());
  s.free();

  state.backgrounds = {};
  s = db.prepare("SELECT day,url FROM backgrounds");
  while (s.step()) {
    const r = s.getAsObject();
    state.backgrounds[r.day] = r.url;
  }
  s.free();

  // settings: try parse JSON values
  const settings = {};
  s = db.prepare("SELECT key,value FROM settings");
  while (s.step()) {
    const r = s.getAsObject();
    try { settings[r.key] = JSON.parse(r.value); } catch { settings[r.key] = r.value; }
  }
  s.free();
  state.settings = Object.assign({ bubbleSize: 72 }, settings);
  // also persist quick state (so UI pieces relying on localStorage get the same state)
  saveQuickState();
}

/**
 * saveStateToDB()
 * - synchronise 'state' vers les tables sqlite
 */
function saveStateToDB() {
  if (!db) return;
  db.run("BEGIN TRANSACTION");
  db.run("DELETE FROM people");
  let ins = db.prepare("INSERT INTO people (id,name,activityId,color) VALUES (?,?,?,?)");
  for (const p of state.people) ins.run([p.id, p.name, p.activityId || null, p.color || null]);
  ins.free();

  db.run("DELETE FROM activities");
  ins = db.prepare("INSERT INTO activities (id,title,type,data,icon) VALUES (?,?,?,?,?)");
  for (const a of state.activities) ins.run([a.id, a.title, a.type, a.data || null, a.icon || null]);
  ins.free();

  db.run("DELETE FROM backgrounds");
  ins = db.prepare("INSERT INTO backgrounds (day,url) VALUES (?,?)");
  for (const d in state.backgrounds) ins.run([d, state.backgrounds[d]]);
  ins.free();

  // settings (we store each key as JSON string)
  db.run("DELETE FROM settings");
  ins = db.prepare("INSERT INTO settings (key,value) VALUES (?,?)");
  for (const k of Object.keys(state.settings || {})) {
    ins.run([k, JSON.stringify(state.settings[k])]);
  }
  ins.free();

  db.run("COMMIT");
  persistDB();
}

// === helpers admin record ===
function getAdminRecord() {
  if (!db) return null;
  try {
    const s = db.prepare("SELECT value FROM settings WHERE key = ?");
    s.bind(["adminPass"]);
    if (s.step()) {
      const row = s.getAsObject();
      s.free();
      return JSON.parse(row.value); // { salt: base64, hash: base64 }
    }
    s.free();
    return null;
  } catch (e) {
    console.error("getAdminRecord error", e);
    return null;
  }
}

function saveAdminRecord(obj) {
  if (!db) return false;
  try {
    const json = JSON.stringify(obj);
    const stmt = db.prepare("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)");
    stmt.run(["adminPass", json]);
    stmt.free();
    persistDB();
    return true;
  } catch (e) {
    console.error("saveAdminRecord error", e);
    return false;
  }
}

/* ===== Password policy helpers ===== */

/**
 * policyCheck(password)
 * - retourne { valid: bool, reasons: [], score: number }
 */
function policyCheck(pw) {
  const reasons = [];
  if (!pw || pw.length < 12) reasons.push("Au moins 12 caractères requis");
  const hasLower = /[a-z]/.test(pw);
  const hasUpper = /[A-Z]/.test(pw);
  const hasDigit = /[0-9]/.test(pw);
  const hasSymbol = /[^A-Za-z0-9]/.test(pw);
  const categories = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
  if (categories < 3) reasons.push("Utiliser au moins 3 types de caractères (majuscule/minuscule/chiffre/symbole)");
  const score = (pw ? Math.min(4, Math.floor(pw.length/4)) : 0) + categories;
  return { valid: reasons.length === 0, reasons, score, categories, hasLower, hasUpper, hasDigit, hasSymbol };
}

/* ===== UI : Set up / change admin password (modal) ===== */

/**
 * showPasswordSetup(options)
 * - affiche un modal de création/modification de mot de passe
 * - options.title : texte du header
 * - stocke { salt: base64, hash: base64 } via saveAdminRecord()
 */
function showPasswordSetup(options = {}) {
  if (!db) {
    alert("Erreur interne : base de données non initialisée");
    return;
  }

  // si déjà présent, focus
  if (document.getElementById("pwSetupModal")) {
    document.getElementById("pwNew").focus();
    return;
  }

  const title = options.title || "Définir / Modifier le mot de passe administrateur";

  const overlay = document.createElement("div");
  overlay.id = "pwSetupModal";
  overlay.style.position = "fixed";
  overlay.style.inset = "0";
  overlay.style.display = "flex";
  overlay.style.alignItems = "center";
  overlay.style.justifyContent = "center";
  overlay.style.background = "rgba(0,0,0,0.35)";
  overlay.style.zIndex = "9999";
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-modal", "true");

  const panel = document.createElement("div");
  panel.style.background = "#fff";
  panel.style.padding = "18px";
  panel.style.borderRadius = "10px";
  panel.style.maxWidth = "520px";
  panel.style.width = "100%";
  panel.style.boxShadow = "0 6px 24px rgba(0,0,0,0.25)";
  panel.style.fontFamily = "system-ui,Segoe UI,Roboto,Arial";

  panel.innerHTML = `
    <h3 style="margin-top:0;margin-bottom:8px">${title}</h3>
    <div style="margin-bottom:8px;color:#444">Choisissez un mot de passe fort. Il ne sera jamais affiché à nouveau.</div>
    <label style="display:block;margin:8px 0;font-size:13px;color:#222">Nouveau mot de passe</label>
    <input id="pwNew" type="password" autocomplete="new-password" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:6px" />
    <label style="display:block;margin:8px 0;font-size:13px;color:#222">Confirmer mot de passe</label>
    <input id="pwConfirm" type="password" autocomplete="new-password" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:6px" />
    <div id="pwFeedback" style="margin-top:8px;font-size:13px;color:#b00;min-height:18px"></div>
    <div style="display:flex;gap:8px;margin-top:12px;justify-content:flex-end">
      <button id="pwCancel" style="padding:8px 12px;border-radius:6px;border:1px solid #ccc;background:#fff">Annuler</button>
      <button id="pwSave" style="padding:8px 12px;border-radius:6px;border:0;background:#0b79f7;color:#fff">Enregistrer</button>
    </div>
  `;

  overlay.appendChild(panel);
  document.body.appendChild(overlay);

  const inpNew = document.getElementById("pwNew");
  const inpConfirm = document.getElementById("pwConfirm");
  const fb = document.getElementById("pwFeedback");
  const btnSave = document.getElementById("pwSave");
  const btnCancel = document.getElementById("pwCancel");

  function updateFeedback() {
    const pw = inpNew.value || "";
    const check = policyCheck(pw);
    if (!pw) { fb.style.color = "#b00"; fb.textContent = "Le mot de passe est requis"; return; }
    if (!check.valid) {
      fb.style.color = "#b00";
      fb.textContent = check.reasons.join(" — ");
      return;
    }
    fb.style.color = "#0a7"; fb.textContent = "Mot de passe conforme ✔︎";
  }

  inpNew.addEventListener("input", updateFeedback);
  inpConfirm.addEventListener("input", updateFeedback);

  btnCancel.addEventListener("click", () => overlay.remove());

  btnSave.addEventListener("click", async () => {
    const a = inpNew.value || "";
    const b = inpConfirm.value || "";
    if (a !== b) { fb.style.color = "#b00"; fb.textContent = "Les mots de passe ne correspondent pas"; return; }
    const check = policyCheck(a);
    if (!check.valid) { fb.style.color = "#b00"; fb.textContent = check.reasons.join(" — "); return; }

    try {
      const saltB64 = generateSaltB64();
      const hashB64 = await hashPasswordB64(a, saltB64);
      const rec = { salt: saltB64, hash: hashB64 };
      const ok = saveAdminRecord(rec);
      if (!ok) throw new Error("Impossible d'enregistrer");
      fb.style.color = "#0a7"; fb.textContent = "Mot de passe enregistré ✔︎";
      setTimeout(() => overlay.remove(), 600);
    } catch (err) {
      console.error("Erreur save pw", err);
      fb.style.color = "#b00"; fb.textContent = "Erreur lors de l'enregistrement";
    }
  });

  // focus accessibility
  setTimeout(() => inpNew.focus(), 20);
}

/* 
   Bloc 2 corrigé — attachAdminHandlers
   ==================================== */

function attachAdminHandlers() {
  // éléments injectés dans showAdminInterface()
  const newNameInput = document.getElementById("newName");
  const addNameBtn = document.getElementById("addName");
  const namesAdminList = document.getElementById("namesAdminList");
  const bubbleSizeInput = document.getElementById("bubbleSize");
  const bubbleSizeVal = document.getElementById("bubbleSizeVal");
  const sortAZBtn = document.getElementById("sortAZ");

  const actTitle = document.getElementById("actTitle");
  const actType = document.getElementById("actType");
  const actColor = document.getElementById("actColor");
  const actFile = document.getElementById("actFile");
  const addActBtn = document.getElementById("addAct");

  const bgDate = document.getElementById("bgDate");
  const bgFile = document.getElementById("bgFile");
  const addBgBtn = document.getElementById("addBg");

  const resetDayBtn = document.getElementById("resetDay");
  const exportBtn = document.getElementById("exportBtn");
  const importFile = document.getElementById("importFile");

// Sécurité : changer le mot de passe
// =========================
const setNewPassBtn = document.getElementById("setNewPassBtn");
if (setNewPassBtn) {
  setNewPassBtn.addEventListener("click", () => {
    showPasswordSetup({ title: "Modifier le mot de passe administrateur" });
  });
}

  /* ---------- Ajout d'un prénom ---------- */
  if (addNameBtn && newNameInput) {
    addNameBtn.addEventListener("click", () => {
      const v = (newNameInput.value || "").trim();
      if (!v) return alert("Nom requis");
      if (state.people.some(p => p.name.toLowerCase() === v.toLowerCase())) return alert("Ce prénom existe déjà.");
      if (state.people.length >= 150) return alert("Limite 150 atteinte");

      const p = { id: UID(), name: v, activityId: null, color: colorFrom(v) };
      state.people.push(p);

      // sauvegarde
      saveStateToDB();
      saveQuickState();

      // rafraîchir affichages
      newNameInput.value = "";
      renderNamesAdmin();
      renderChildNames();
    });

    // Enter → ajouter
    newNameInput.addEventListener("keydown", e => { if (e.key === "Enter") addNameBtn.click(); });
  }

  /* ---------- Taille des bulles ---------- */
  if (bubbleSizeInput && bubbleSizeVal) {
    // initialiser valeur dans l'input si absent
    bubbleSizeInput.value = state.settings?.bubbleSize || 72;
    bubbleSizeVal.textContent = bubbleSizeInput.value;

    bubbleSizeInput.addEventListener("input", () => {
      const v = parseInt(bubbleSizeInput.value, 10) || 72;
      state.settings = state.settings || {};
      state.settings.bubbleSize = v;
      bubbleSizeVal.textContent = v;
      document.documentElement.style.setProperty('--bubble-size', v + 'px');
      saveStateToDB();
      saveQuickState();
    });
  }

  /* ---------- Tri A→Z ---------- */
  if (sortAZBtn) {
    sortAZBtn.addEventListener("click", () => {
      state.people.sort((a,b) => a.name.localeCompare(b.name, 'fr'));
      saveStateToDB();
      saveQuickState();
      renderNamesAdmin();
      renderChildNames();
    });
  }

  /* ---------- Ajouter une activité ---------- */
  if (addActBtn && actTitle && actType && actColor && actFile) {
    addActBtn.addEventListener("click", async () => {
      const t = (actTitle.value || "").trim();
      if (!t) return alert("Titre requis");
      try {
        if (actType.value === "image") {
          const f = actFile.files[0];
          if (!f) return alert("Choisis une image");
          const dataUrl = await sanitizeFileToPNGDataURL(f);
          state.activities.push({ id: UID(), title: t, type: 'image', data: dataUrl, icon: ICONS[Math.floor(Math.random()*ICONS.length)] });
        } else {
          state.activities.push({ id: UID(), title: t, type: 'color', data: actColor.value, icon: ICONS[Math.floor(Math.random()*ICONS.length)] });
        }

        // sauvegarde et rendu
        saveStateToDB();
        saveQuickState();
        actTitle.value = "";
        actFile.value = "";
        renderActivities();
      } catch (err) {
        alert("Image non autorisée : " + err.message);
      }
    });
  }

  /* ---------- Ajouter un fond journalier ---------- */
  if (addBgBtn && bgDate && bgFile) {
    addBgBtn.addEventListener("click", async () => {
      const d = bgDate.value;
      if (!d) return alert("Date requise");
      const f = bgFile.files[0];
      if (!f) return alert("Fichier requis");
      try {
        const dataUrl = await sanitizeFileToPNGDataURL(f);
        state.backgrounds = state.backgrounds || {};
        state.backgrounds[d] = dataUrl;
        saveStateToDB();
        saveQuickState();
        renderBackground();
        bgDate.value = "";
        bgFile.value = "";
      } catch (err) {
        alert("Fichier non autorisé : " + err.message);
      }
    });
  }

  /* ---------- Réinitialiser la journée ---------- */
  if (resetDayBtn) {
    resetDayBtn.addEventListener("click", () => {
      if (!confirm("Réinitialiser la journée ?")) return;
      state.people.forEach(p => p.activityId = null);
      // si tu avais stocké des membres dans activities, on vide aussi
      (state.activities || []).forEach(a => { if (a.members) a.members = []; });
      saveStateToDB();
      saveQuickState();
      renderActivities();
      renderNamesAdmin();
      renderChildNames();
    });
  }

  /* ---------- Export JSON ---------- */
  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      const data = {
        people: state.people,
        activities: state.activities,
        backgrounds: state.backgrounds,
        settings: state.settings
      };
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "centre_loisirs_export.json";
      a.click();
      URL.revokeObjectURL(url);
    });
  }

  /* ---------- Import JSON (remplace l'état) ---------- */
  if (importFile) {
    importFile.addEventListener("change", (ev) => {
      const f = ev.target.files[0];
      if (!f) return;
      const r = new FileReader();
      r.onload = () => {
        try {
          const obj = JSON.parse(r.result);
          if (!Array.isArray(obj.people) || !Array.isArray(obj.activities)) throw new Error("Format invalide");
          if (!confirm("Importer va remplacer l'état actuel. Continuer ?")) return;
          state.people = obj.people;
          state.activities = obj.activities;
          state.backgrounds = obj.backgrounds || {};
          state.settings = obj.settings || { bubbleSize: 72 };
          saveStateToDB();
          saveQuickState();
          renderAll();
          alert("Import OK");
        } catch (e) {
          alert("Fichier invalide : " + e.message);
        }
      };
      r.readAsText(f);
      importFile.value = "";
    });
  }

  /* ---------- Bouton sécurité : définir/modifier le mot de passe ---------- */
  if (setNewPassBtn) {
    setNewPassBtn.addEventListener("click", () => {
      showPasswordSetup({ title: "Définir / Modifier le mot de passe administrateur" });
    });
  }

  /* ---------- applique la taille des bulles au démarrage ---------- */
  const bubbleSize = (state.settings && state.settings.bubbleSize) ? state.settings.bubbleSize : 72;
  document.documentElement.style.setProperty('--bubble-size', bubbleSize + 'px');
}

/* 
  Render names & children bubbles
   ============================ */

function renderNamesAdmin() {
  const list = document.getElementById("namesAdminList");
  if (!list) return;
  list.innerHTML = "";
  state.people.forEach(p => {
    const row = document.createElement("div");
    row.className = "row";

    const who = document.createElement("div");
    who.className = "who";
    const bub = document.createElement("div");
    bub.className = "bubble";
    bub.style.background = p.color || colorFrom(p.name);
    bub.textContent = p.name[0].toUpperCase();
    const span = document.createElement("span");
    span.textContent = p.name;
    who.appendChild(bub);
    who.appendChild(span);

    const del = document.createElement("button");
    del.className = "small";
    del.textContent = "✕";
    del.addEventListener("click", () => {
      if (!confirm("Supprimer " + p.name + " ?")) return;
      state.people = state.people.filter(x => x.id !== p.id);
      save();
      renderNamesAdmin();
      renderChildNames();
    });

    row.appendChild(who);
    row.appendChild(del);
    list.appendChild(row);
  });
}

function renderChildNames() {
  const container = document.getElementById("childNames");
  if (!container) return;

  container.innerHTML = "";

  state.people.forEach(p => {
    const bubble = document.createElement("div");
    bubble.className = "bubble";
    bubble.textContent = p.name;
    bubble.dataset.id = p.id;

    // Rendre la bulle draggable !!!
    bubble.draggable = true;
    bubble.addEventListener("dragstart", e => {
      e.dataTransfer.setData("text/plain", p.id);
    });

    container.appendChild(bubble);
  });

  // Préparer les dropzones des activités
  document.querySelectorAll(".dropzone").forEach(dz => {
    if (dz.__dragPatched) return; // éviter doublons
    dz.addEventListener("dragover", e => e.preventDefault());
    dz.addEventListener("drop", e => {
      e.preventDefault();
      const id = e.dataTransfer.getData("text/plain");
      const person = state.people.find(pp => pp.id === id);
      if (person) {
        person.activityId = dz.dataset.id;
        save();
        renderAll();
      }
    });
    dz.__dragPatched = true;
  });
}

/* 
   Activities & Drag/Drop
   ====================== */

function renderActivities() {
  const wrap = document.getElementById("activities");
  if (!wrap) return;
  wrap.innerHTML = "";

  state.activities.forEach(act => {
    const card = document.createElement("div");
    card.className = "activity-card";
    if (act.type === "color") card.style.background = act.data;
    if (act.type === "image") card.style.background = `url(${act.data}) center/cover`;

    const title = document.createElement("div"); title.className = "act-title";
    const left = document.createElement("div"); left.className = "act-left";
    const ic = document.createElement("div"); ic.className = "act-ic"; ic.textContent = act.icon || '🎯';
    const name = document.createElement("div"); name.className = "act-name"; name.textContent = act.title;
    left.appendChild(ic); left.appendChild(name);

    const del = document.createElement("button"); del.className = "small del-act"; del.textContent = "✕";
    del.addEventListener("click", () => {
      if (!confirm("Supprimer activité ?")) return;
      state.activities = state.activities.filter(a => a.id !== act.id);
      state.people.forEach(p => { if (p.activityId === act.id) p.activityId = null; });
      save();
      renderActivities();
      renderChildNames();
    });

    title.appendChild(left); title.appendChild(del);
    card.appendChild(title);

    const dz = document.createElement("div"); dz.className = "dropzone"; dz.dataset.id = act.id;
    card.appendChild(dz);
    wrap.appendChild(card);
  });

  renderMembers();
  initDragAndDrop();
}

function renderMembers() {
  document.querySelectorAll(".dropzone").forEach(dz => dz.innerHTML = "");
  state.people.forEach(p => {
    if (!p.activityId) return;
    const act = state.activities.find(a => a.id === p.activityId);
    if (!act) return;
    const dz = document.querySelector(`.dropzone[data-id='${act.id}']`);
    if (!dz) return;
    const bub = document.createElement("div");
    bub.className = "bubble";
    bub.style.background = p.color || colorFrom(p.name);
    bub.textContent = p.name[0].toUpperCase();
    bub.draggable = true;
    bub.dataset.id = p.id;

    bub.addEventListener("dragstart", e => {
      e.dataTransfer.setData("text/plain", p.id);
    });

    dz.appendChild(bub);
  });
}

function initDragAndDrop() {
  // draggable children
  document.querySelectorAll(".bubble").forEach(b => {
    b.addEventListener("dragstart", ev => {
      ev.dataTransfer.setData("text/plain", b.dataset.id);
    });
  });

  // dropzones
  document.querySelectorAll(".dropzone").forEach(dz => {
    dz.addEventListener("dragover", ev => { ev.preventDefault(); dz.classList.add('highlight'); });
    dz.addEventListener("dragleave", () => dz.classList.remove('highlight'));
    dz.addEventListener("drop", ev => {
      ev.preventDefault();
      dz.classList.remove('highlight');
      const id = ev.dataTransfer.getData("text/plain");
      const p = state.people.find(x => x.id === id);
      if (!p) return;
      p.activityId = dz.dataset.id;
      save();
      renderMembers();
      renderChildNames();
    });
  });
}
/* =========================
   Bloc 4 — rendu global et init
   ========================= */

function renderBackground() {
  const d = new Date().toISOString().slice(0,10);
  if (state.backgrounds && state.backgrounds[d]) {
    document.body.style.backgroundImage = `url(${state.backgrounds[d]})`;
    document.body.style.backgroundSize = "cover";
  } else {
    document.body.style.backgroundImage = "";
  }
}

function renderCounter() {
  const el = document.getElementById("counterInfo");
  if (!el) return;
  el.textContent = `${state.people.length} enfants — ${state.activities.length} activités`;
}

function renderAll() {
  renderNamesAdmin();
  renderChildNames();
  renderActivities();
  renderBackground();
  renderCounter();
}

/* =========================
   UI controls
   ========================= */

document.getElementById("enterFull").addEventListener("click", () => {
  if (document.fullscreenElement) {
    document.exitFullscreen();
  } else {
    document.documentElement.requestFullscreen();
  }
});

document.getElementById("openAdmin").addEventListener("click", () => {
  document.getElementById("adminPanel").style.display = "block";
});
document.getElementById("hideUI").addEventListener("click", () => {
  document.getElementById("adminPanel").style.display = "none";
});

// =========================
// Handler connexion admin
// =========================
document.getElementById("unlockBtn").addEventListener("click", async () => {
  const passInput = document.getElementById("adminPassInput");
  const pass = passInput.value.trim();

  if (!pass) {
    alert("Veuillez entrer le mot de passe.");
    return;
  }

  try {
const admin = getAdminRecord();  // pas besoin de await
    if (!admin || !admin.hash || !admin.salt) {
    alert("Aucun mot de passe admin configuré. Merci de le définir.");
    return;
}

const ok = await verifyPasswordRecord(pass, admin);
    if (ok) {
      document.getElementById("adminArea").style.display = "block";
      passInput.value = ""; // efface le champ pour sécurité
    } else {
      alert("Mot de passe incorrect.");
    }
  } catch (err) {
    console.error("Erreur lors de la vérification du mot de passe:", err);
    alert("Erreur interne lors de la connexion.");
  }
});

/* =========================
   Initialisation
   ========================= */

document.addEventListener("DOMContentLoaded", async () => {
  try {
    // 1. Initialise la base (crée les tables si elles n'existent pas)
    await initDB();

    // 2. Restaure l'état depuis la base
    await restoreDB();

    // 3. Vérifie si un mot de passe admin existe
    const admin = getAdminRecord(); // await supprimé donc synchrone  
    if (!admin || !admin.hash) {
      showPasswordSetup({ title: "Initialiser le mot de passe administrateur" });
    }

    // 4. Affiche tout
    renderAll();

  } catch (err) {
    console.error("Erreur d'init:", err);
    alert("Erreur lors de l'initialisation : " + err.message);
  }
});
