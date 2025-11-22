/* app.js — Version finale fusionnée & corrigée
   - sqlite local via sql-wasm.wasm (local)
   - admin password: PBKDF2(salt) -> hash stored in SQLite
   - UI admin builder safe
   - showPasswordSetup modal included
   - pointer-based drag & drop (clone + elementFromPoint)
   - single DOMContentLoaded
   
   Reste code a consolidé. Chiffrement AES.  
*/

/* BLOC 1 — Helpers, sécurité & DB
   ================================ */

let db = null;
let state = {
  people: [],
  activities: [],
  backgrounds: {},
  settings: { bubbleSize: 72 }
};

const STORAGE = { LS_KEY: "sat_state", DB_KEY: "sat_db" };

function UID(){ return "_" + Math.random().toString(36).substr(2,9); }
function colorFrom(s){ if(!s) return '#999'; let h=0; for(let i=0;i<s.length;i++) h=(h*31+s.charCodeAt(i))%360; return `hsl(${h} 70% 48%)`; }

function ab2b64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function b642ab(b64){ const bin = atob(b64); return Uint8Array.from(bin, c => c.charCodeAt(0)).buffer; }

/* PBKDF2 hash (returns base64 of derived bits) */
const PBKDF2_ITER = 100000;
async function hashPassword(password, saltBase64){
  const enc = new TextEncoder();
  const salt = b642ab(saltBase64);
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' }, baseKey, 256);
  return ab2b64(bits);
}
function genSalt(){ const arr = new Uint8Array(16); crypto.getRandomValues(arr); return ab2b64(arr); }

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
  } catch (err) {
    console.warn("persistDB failed:", err);
  }
}

async function restoreDB(){
  try {
    const b64 = localStorage.getItem(STORAGE.DB_KEY);
    if(!b64) return;
    const SQL = await initSqlJs({ locateFile: file => "sql-wasm.wasm" });
    const data = b642ab(b64);
    db = new SQL.Database(new Uint8Array(data));
    const row = db.exec("SELECT value FROM settings WHERE key='state'");
    if(row && row[0] && row[0].values && row[0].values[0]){
      try { state = JSON.parse(row[0].values[0][0]); } catch(e){ console.warn("restoreDB: failed parse state", e); }
    }
  } catch (err) {
    console.error("restoreDB error:", err);
  }
}

function saveStateToDB(){
  if(!db) return;
  try {
    db.run("DELETE FROM settings WHERE key='state'");
    db.run("INSERT INTO settings (key,value) VALUES (?,?)", ["state", JSON.stringify(state)]);
    persistDB();
  } catch (err) {
    console.error("saveStateToDB error:", err);
  }
}

function saveQuickState(){
  try { localStorage.setItem(STORAGE.LS_KEY, JSON.stringify(state)); } catch(e){ console.warn("saveQuickState failed", e); }
}

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
  } catch (err) {
    console.error("saveAdminRecord error:", err);
  }
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

/* BLOC 2 — Render functions
   ========================= */

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
    const bub = document.createElement('div'); bub.className='bubble';
    bub.style.background = p.color || colorFrom(p.name);
    bub.textContent = (p.name||'')[0] || '?';
    bub.dataset.id = p.id; // <-- ensure id
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

  const inner = document.createElement('div');
  inner.style.display = 'flex';
  inner.style.flexWrap = 'wrap';
  inner.style.gap = '8px';

  (state.people || []).forEach(p => {
    if (p.activityId) return; // seulement les enfants non assignés
    const b = document.createElement('div');
    b.className = 'bubble';
    b.textContent = ( (p.name || '').split(' ')[0] ) || '?';
    b.title = p.name;
    b.dataset.id = p.id; // indispensable pour le drag - sinon ne fonctionne pas
    b.style.background = p.color || colorFrom(p.name);
    b.style.minWidth = (state.settings.bubbleSize || 72) + 'px';
    b.style.height = (state.settings.bubbleSize || 72) + 'px';
    inner.appendChild(b);
  });

  wrap.appendChild(inner);
}

function renderActivities() {
  const wrap = document.getElementById("activities");
  if (!wrap) return;
  wrap.innerHTML = "";

  (state.activities || []).forEach(act => {
    const card = document.createElement('div');
    card.className = 'activity-card';

    // Gérer l'arrière-plan de l'activité
    if (act.type === 'image' && typeof act.data === 'string' && act.data.startsWith('data:image/')) {
      card.style.background = `url(${act.data}) center/cover`;
      card.style.backgroundSize = 'cover';
      card.style.backgroundPosition = 'center';
    } else {
      card.style.background = act.data || '#c7d2fe';
    }

    // Créer le titre et l'icône de l'activité
    const title = document.createElement('div');
    title.className = 'act-title';
    const left = document.createElement('div');
    left.className = 'act-left';
    const ic = document.createElement('div');
    ic.className = 'act-ic';
    ic.textContent = act.icon || '🎯';  // Icône de l'activité (par défaut une cible 🎯)

    // Lorsque l'icône est cliquée, afficher une liste de pictogrammes à choisir
    ic.addEventListener('click', () => {
      showIconSelectionMenu(ic, act);  // Afficher le menu de sélection des pictogrammes
    });

    const name = document.createElement('div');
    name.className = 'act-name';
    name.textContent = act.title || 'Activité';

    left.appendChild(ic);
    left.appendChild(name);

    // Bouton de suppression de l'activité
    const del = document.createElement('button');
    del.className = 'small';
    del.textContent = '✕';
    del.addEventListener('click', () => {
      if (confirm('Supprimer cette activité ?')) {
        state.activities = state.activities.filter(a => a.id !== act.id);
        state.people.forEach(p => {
          if (p.activityId === act.id) p.activityId = null;
        });
        saveStateToDB();
        saveQuickState();
        renderAll();
      }
    });

    title.appendChild(left);
    title.appendChild(del);
    card.appendChild(title);

    // Zone de dépôt (Dropzone)
    const dz = document.createElement('div');
    dz.className = 'dropzone';
    dz.dataset.id = act.id;
    card.appendChild(dz);

    wrap.appendChild(card);
  });

  renderMembers();
}

// Afficher le menu de sélection des pictogrammes
function showIconSelectionMenu(iconElement, activity) {
  // Créer une fenêtre contextuelle avec une liste d'icônes à choisir
  const iconMenu = document.createElement('div');
  iconMenu.className = 'icon-menu';
  iconMenu.style.position = 'absolute';
  iconMenu.style.left = `${iconElement.getBoundingClientRect().left}px`;
  iconMenu.style.top = `${iconElement.getBoundingClientRect().bottom}px`;
  iconMenu.style.backgroundColor = '#fff';
  iconMenu.style.border = '1px solid #ccc';
  iconMenu.style.padding = '10px';
  iconMenu.style.borderRadius = '5px';
  iconMenu.style.zIndex = 10000;

  const icons = ['🎨','⚽','🎵','📚','🍳','🚲','🖍️','🎤','🎬','🧩','🚀','🌳','🎯','🧪','🧱','🧘','🏊','🧺','🖼️','🎮','🧵','🎭','🎲','🏸','🏕️','🎈'];  // Liste d'icônes à choisir
  icons.forEach(icon => {
    const iconButton = document.createElement('button');
    iconButton.textContent = icon;
    iconButton.style.fontSize = '20px';
    iconButton.style.margin = '5px';
    iconButton.addEventListener('click', () => {
      activity.icon = icon;  // Mettre à jour l'icône de l'activité
      saveStateToDB();       // Sauvegarder l'état
      saveQuickState();      // Sauvegarder rapidement
      renderAll();           // Rafraîchir l'interface
      document.body.removeChild(iconMenu);  // Fermer le menu après sélection
    });
    iconMenu.appendChild(iconButton);
  });

  // Ajouter le menu au body
  document.body.appendChild(iconMenu);

  // Fermer le menu si on clique en dehors
  document.addEventListener('click', (event) => {
    if (!iconMenu.contains(event.target) && event.target !== iconElement) {
      document.body.removeChild(iconMenu);
    }
  }, { once: true });
}


function renderMembers(){
  document.querySelectorAll('.dropzone').forEach(dz => dz.innerHTML = '');
  (state.people || []).forEach(p=>{
    if(!p.activityId) return;
    const dz = document.querySelector(`.dropzone[data-id='${p.activityId}']`);
    if(!dz) return;
    const bub = document.createElement('div'); bub.className='bubble'; bub.textContent = (p.name||'')[0] || '?'; bub.title = p.name;
    bub.dataset.id = p.id; // ensure id
    bub.style.background = p.color || colorFrom(p.name);
    bub.style.minWidth = (state.settings.bubbleSize||72)+'px';
    bub.style.height = (state.settings.bubbleSize||72)+'px';
    dz.appendChild(bub);
  });
}

/* renderAll — Rendu global de l’application
   (rattache les événements après DOM update)
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

/* BLOC 3 — Drag & Drop handlers (stable)
   ====================================== */

let dragging = null;

function onPointerDown(e) {

  const el = e.currentTarget;
  if (!el || !el.classList.contains('bubble')) return;

  if (e.target.closest('input,button,textarea')) return;

  e.preventDefault();
  e.stopPropagation();

  const rect = el.getBoundingClientRect();

  const clone = el.cloneNode(true);
  clone.classList.add('dragging-clone');

  Object.assign(clone.style, {
    position: 'fixed',
    left: rect.left + 'px',
    top: rect.top + 'px',
    width: rect.width + 'px',
    height: rect.height + 'px',
    pointerEvents: 'none',
    zIndex: '99999',
    opacity: '0.95',
    transform: 'translate(-50%, -50%)'
  });

  document.body.appendChild(clone);
  el.style.visibility = 'hidden';

  dragging = {
    el,
    clone,
    pid: el.dataset.id,
    offsetX: (e.clientX - rect.left),
    offsetY: (e.clientY - rect.top)
  };

  window.addEventListener('pointermove', onPointerMove);
  window.addEventListener('pointerup', onPointerUp);

  console.debug("drag:start", dragging && dragging.pid);
}

function onPointerMove(e) {
  if (!dragging) return;
  const x = e.clientX - dragging.offsetX;
  const y = e.clientY - dragging.offsetY;
  dragging.clone.style.left = x + 'px';
  dragging.clone.style.top = y + 'px';

  document.querySelectorAll('.dropzone').forEach(z => z.classList.remove('highlight'));
  const under = document.elementFromPoint(e.clientX, e.clientY);
  const dz = under && under.closest ? under.closest('.dropzone') : null;
  if (dz) dz.classList.add('highlight');
}

function onPointerUp(e) {
  if (!dragging) return;

  const under = document.elementFromPoint(e.clientX, e.clientY);
  const dz = under && under.closest ? under.closest('.dropzone') : null;

  try { if (dragging.el) dragging.el.style.visibility = ''; } catch (err) {}
  try { if (dragging.clone && dragging.clone.remove) dragging.clone.remove(); } catch (err) {}

  document.querySelectorAll('.dropzone').forEach(z => z.classList.remove('highlight'));

  if (dz && dragging.pid) {
    const person = (state.people || []).find(p => p.id === dragging.pid);
    if (person) {
      person.activityId = dz.dataset.id || null;
      try { saveStateToDB(); } catch(e){ console.warn(e); }
      try { saveQuickState(); } catch(e) {}
      console.debug(`assigned ${person.name} -> ${person.activityId}`);
    }
  } else {
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

  // cleanup
  window.removeEventListener('pointermove', onPointerMove);
  window.removeEventListener('pointerup', onPointerUp);

  dragging = null;

  // refresh UI
  try { renderAll(); } catch (err) { console.error("renderAll after drop error:", err); }
}


function attachBubbleEvents() {
  const bubbles = document.querySelectorAll('.bubble');
  bubbles.forEach(b => {
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

/* BLOC 4 — showPasswordSetup + buildAdminUIIfMissing
   ================================================== */

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
      const salt = genSalt();
      const hash = await hashPassword(p1, salt);
      saveAdminRecord({ salt, hash });
      modal.remove();
      alert("Mot de passe enregistré.");
    } catch (err) {
      console.error("save admin pass error:", err);
      alert("Erreur technique lors de l'enregistrement.");
    }
  });
}

function buildAdminUIIfMissing(){
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

  if(adminArea.dataset.inited === "1") return;
  adminArea.dataset.inited = "1";

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
  if(exportBtn){ exportBtn.addEventListener("click", ()=>{ const blob = new Blob([JSON.stringify(state,null,2)], {type:'application/json'}); const url = URL.createObjectURL(blob); const a=document.createElement('a'); a.href=url; a.download='centre_loisirs_export.json'; a.click(); URL.revokeObjectURL(url); }); }

  const importFile = document.getElementById("importFile");
  if(importFile){ importFile.addEventListener("change", (ev)=>{ const f = ev.target.files[0]; if(!f) return; const r = new FileReader(); r.onload = ()=>{ try{ const obj = JSON.parse(r.result); if(confirm('Importer va remplacer l’état actuel. Continuer ?')){ state = obj; saveStateToDB(); saveQuickState(); renderAll(); } }catch(e){ alert('Fichier invalide'); } }; r.readAsText(f); }); }

  const changePassBtn = document.getElementById("changePassBtn");
  if(changePassBtn){ changePassBtn.addEventListener("click", async ()=>{ const current = prompt('Mot de passe actuel :'); if(current===null) return; const admin = getAdminRecord(); if(!admin){ alert('Aucun mot de passe enregistré'); return; } const ok = await (async ()=>{ const h = await hashPassword(current, admin.salt); return h === admin.hash; })(); if(!ok){ alert('Mot de passe actuel incorrect'); return; } const np = prompt('Nouveau mot de passe :'); if(!np) return; const np2 = prompt('Confirmer nouveau mot de passe :'); if(np !== np2){ alert('Les mots de passe ne correspondent pas'); return; } const salt = genSalt(); const newHash = await hashPassword(np, salt); saveAdminRecord({ salt, hash: newHash }); alert('Mot de passe changé'); }); }
}

/* BLOC 5 — single DOMContentLoaded + init wiring
   =============================================== */

document.addEventListener("DOMContentLoaded", async () => {
  try {
    await initDB();
    await restoreDB();

    buildAdminUIIfMissing();

    const admin = getAdminRecord();
    if(!admin || !admin.hash || !admin.salt){
      setTimeout(()=> showPasswordSetup({ title: "Initialiser le mot de passe administrateur" }), 100);
    }

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
            document.getElementById("adminArea") && (document.getElementById("adminArea").style.display = 'block');
            if(passInput) passInput.value = '';
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
    
    if((state.activities||[]).length === 0 && (state.people||[]).length === 0){
      state.activities.push({ id: UID(), title:'Peinture', type:'color', data:'#ff7f50', icon:'🎨' });
      state.activities.push({ id: UID(), title:'Jeux Extérieurs', type:'color', data:'#4caf50', icon:'⚽' });
      state.activities.push({ id: UID(), title:'Atelier Cuisine', type:'color', data:'#2196f3', icon:'🍳' });
      ['Albert Einstein','Nicolas Tesla','Jeveuxpas Faireactivite','Alain Turing','Isaac N'].forEach(n=> state.people.push({ id: UID(), name: n, activityId: null, color: colorFrom(n) }));
      saveStateToDB(); saveQuickState();
    }

    // final render
    renderAll();

  } catch (err) {
    console.error("Erreur d'init:", err);
    alert("Erreur lors de l'initialisation : " + (err && err.message ? err.message : String(err)));
  }
});
