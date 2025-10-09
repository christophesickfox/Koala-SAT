/* 
   BLOC 1 — Helpers, sécurité & DB
   ================================ */

let db = null;
let state = {
  people: [],
  activities: [],
  backgrounds: {},
  settings: {}
};

const STORAGE = {
  LS_KEY: "sat_state",
  DB_KEY: "sat_db"
};

const ICONS = ["🎲", "⚽", "🎨", "🎵", "🎯", "🎬", "🍴", "🎉", "🌳"];

function UID() {
  return "_" + Math.random().toString(36).substr(2, 9);
}

function colorFrom(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  const c = (hash & 0x00FFFFFF).toString(16).toUpperCase();
  return "#" + "00000".substring(0, 6 - c.length) + c;
}

function ab2b64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function b642ab(b64) {
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0)).buffer;
}

// --- PBKDF2 Hash
async function hashPassword(password, saltBase64) {
  const enc = new TextEncoder();
  const salt = b642ab(saltBase64);
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
    key, 256
  );
  return ab2b64(bits);
}

async function verifyPasswordRecord(password, record) {
  const hashed = await hashPassword(password, record.salt);
  return hashed === record.hash;
}

function genSalt() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return ab2b64(arr);
}

// --- SQLite DB
async function initDB() {
  if (db) return;
  const SQL = await initSqlJs({ locateFile: file => `sql-wasm.wasm` });
  db = new SQL.Database();
  db.run(`
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
  `);
}

function persistDB() {
  const data = db.export();
  const b64 = ab2b64(data);
  localStorage.setItem(STORAGE.DB_KEY, b64);
}

async function restoreDB() {
  const b64 = localStorage.getItem(STORAGE.DB_KEY);
  if (!b64) return;
  const SQL = await initSqlJs({ locateFile: file => `sql-wasm.wasm` });
  const data = b642ab(b64);
  db = new SQL.Database(new Uint8Array(data));
  // recharge state
  const row = db.exec("SELECT value FROM settings WHERE key='state'");
  if (row[0]) {
    state = JSON.parse(row[0].values[0][0]);
  }
}

function saveStateToDB() {
  if (!db) return;
  db.run("DELETE FROM settings WHERE key='state'");
  db.run("INSERT INTO settings (key,value) VALUES (?,?)", ["state", JSON.stringify(state)]);
  persistDB();
}

function saveQuickState() {
  localStorage.setItem(STORAGE.LS_KEY, JSON.stringify(state));
}

function getAdminRecord() {
  if (!db) return null;
  const row = db.exec("SELECT value FROM settings WHERE key='adminPass'");
  if (!row[0]) return null;
  return JSON.parse(row[0].values[0][0]);
}

function saveAdminRecord(record) {
  db.run("DELETE FROM settings WHERE key='adminPass'");
  db.run("INSERT INTO settings (key,value) VALUES (?,?)", ["adminPass", JSON.stringify(record)]);
  persistDB();
}

function policyCheck(pass) {
  const reasons = [];
  if (pass.length < 12) reasons.push("au moins 12 caractères");
  let types = 0;
  if (/[a-z]/.test(pass)) types++;
  if (/[A-Z]/.test(pass)) types++;
  if (/[0-9]/.test(pass)) types++;
  if (/[^A-Za-z0-9]/.test(pass)) types++;
  if (types < 3) reasons.push("au moins 3 types de caractères différents");
  return { ok: reasons.length === 0, reasons };
}

/* 
   BLOC 2 — Password Setup + Handlers Admin
   ========================================= */

function showPasswordSetup({ title }) {
  // supprimer un ancien modal s'il existe
  const old = document.getElementById("pw-setup-modal");
  if (old) old.remove();

  const modal = document.createElement("div");
  modal.id = "pw-setup-modal";
  modal.innerHTML = `
    <div class="pw-modal-backdrop">
      <div class="pw-modal-box">
        <h2>${title}</h2>
        <div>
          <label>Nouveau mot de passe :</label>
          <input type="password" id="pw1">
        </div>
        <div>
          <label>Confirmer le mot de passe :</label>
          <input type="password" id="pw2">
        </div>
        <div id="pw-msg" style="color:red; font-size:0.9em; margin:4px 0;"></div>
        <div style="margin-top:8px;">
          <button id="pw-save">Enregistrer</button>
          <button id="pw-cancel">Annuler</button>
        </div>
      </div>
    </div>
  `;
  document.body.appendChild(modal);

  // styles minimaux pour le rendre visible
  const style = document.createElement("style");
  style.textContent = `
    .pw-modal-backdrop {
      position: fixed; inset: 0;
      background: rgba(0,0,0,0.6);
      display: flex; align-items: center; justify-content: center;
      z-index: 10000;
    }
    .pw-modal-box {
      background: #fff; padding: 20px; border-radius: 10px;
      width: 300px; max-width: 90%;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    .pw-modal-box h2 { margin-top:0; font-size:1.2em; }
    .pw-modal-box input { width:100%; margin:4px 0; padding:6px; }
    .pw-modal-box button { margin-right:6px; }
  `;
  document.head.appendChild(style);

  // gestion des boutons
  const saveBtn = modal.querySelector("#pw-save");
  const cancelBtn = modal.querySelector("#pw-cancel");
  const msg = modal.querySelector("#pw-msg");

  saveBtn.addEventListener("click", async () => {
    const p1 = modal.querySelector("#pw1").value;
    const p2 = modal.querySelector("#pw2").value;
    if (p1 !== p2) {
      msg.textContent = "Les mots de passe ne correspondent pas.";
      return;
    }
    if (p1.length < 12) {
      msg.textContent = "Mot de passe trop court (12 caractères mini).";
      return;
    }

    //  ici utilisation des helpers du Bloc 1
    const salt = genSalt();               // en base64 ? normalement oui
    const hash = await hashPassword(p1, salt); // en base64

    saveAdminRecord({ salt, hash });
    alert("Mot de passe enregistré !");
    modal.remove();
  });

  cancelBtn.addEventListener("click", () => modal.remove());
}

function attachAdminHandlers() {
  const setPassBtn = document.getElementById("setNewPassBtn");
  if (setPassBtn) {
    setPassBtn.onclick = () => showPasswordSetup({ title: "Modifier le mot de passe" });
  }
}


/* 
   BLOC 3 — Render & Drag & Drop
   ============================== */

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
    bubble.draggable = true;
    bubble.addEventListener("dragstart", e => {
      e.dataTransfer.setData("text/plain", p.id);
    });
    container.appendChild(bubble);
  });
}

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
  document.querySelectorAll(".bubble").forEach(b => {
    b.addEventListener("dragstart", ev => {
      ev.dataTransfer.setData("text/plain", b.dataset.id);
    });
  });
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

/* 
   BLOC 4 — Rendu global + UI + Connexion + Init
   ============================================== */

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

function save() {
  saveStateToDB();
  saveQuickState();
}

// === UI controls ===
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

// === Connexion admin ===
document.getElementById("unlockBtn").addEventListener("click", async () => {
  const passInput = document.getElementById("adminPassInput");
  const pass = passInput.value.trim();
  if (!pass) {
    alert("Veuillez entrer le mot de passe.");
    return;
  }
  try {
    const admin = getAdminRecord();
    if (!admin || !admin.hash || !admin.salt) {
      alert("Aucun mot de passe admin configuré. Merci de le définir.");
      return;
    }
    const ok = await verifyPasswordRecord(pass, admin);
    if (ok) {
      document.getElementById("adminArea").style.display = "block";
      attachAdminHandlers();   // branche tous les boutons admin
      passInput.value = "";
    } else {
      alert("Mot de passe incorrect.");
    }
  } catch (err) {
    console.error("Erreur lors de la vérification du mot de passe:", err);
    alert("Erreur interne lors de la connexion.");
  }
});

// === Initialisation ===
document.addEventListener("DOMContentLoaded", async () => {
  try {
    await initDB();
    await restoreDB();

    const admin = getAdminRecord();
    console.log("Admin record:", admin); // debug

    //  si aucun mot de passe n’existe → forcer setup au démarrage
    if (!admin || !admin.hash || !admin.salt) {
      setTimeout(() => {
        showPasswordSetup({ title: "Initialiser le mot de passe administrateur" });
      }, 100);
    }

    renderAll();
  } catch (err) {
    console.error("Erreur d'init:", err);
    alert("Erreur lors de l'initialisation : " + err.message);
  }
});

