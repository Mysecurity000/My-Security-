const $ = (id) => document.getElementById(id);

const state = {
  files: [],
  results: [],
  scanning: false,
  toastTimer: null
};

const fileInput = $("fileInput");
const folderInput = $("folderInput");
const dropZone = $("dropZone");

function showToast(message) {
  const toast = $("toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => toast.classList.remove("show"), 3200);
}

function addFiles(fileList) {
  const incoming = Array.from(fileList || []);
  const byKey = new Map(state.files.map(file => [`${file.name}:${file.size}:${file.lastModified}`, file]));
  for (const file of incoming) {
    byKey.set(`${file.name}:${file.size}:${file.lastModified}`, file);
  }
  state.files = Array.from(byKey.values());
  $("selectionInfo").textContent = state.files.length
    ? `${state.files.length} Datei(en) ausgewählt`
    : "Noch keine Dateien ausgewählt";
  $("scanButton").disabled = state.files.length === 0 || state.scanning;
  if (incoming.length) showToast(`${incoming.length} Datei(en) hinzugefügt.`);
}

$("chooseFiles").addEventListener("click", () => fileInput.click());
$("chooseFolder").addEventListener("click", () => folderInput.click());
fileInput.addEventListener("change", event => addFiles(event.target.files));
folderInput.addEventListener("change", event => addFiles(event.target.files));

dropZone.addEventListener("click", event => {
  if (event.target.closest("button")) return;
  fileInput.click();
});
dropZone.addEventListener("keydown", event => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    fileInput.click();
  }
});
["dragenter", "dragover"].forEach(type => dropZone.addEventListener(type, event => {
  event.preventDefault();
  dropZone.classList.add("dragover");
}));
["dragleave", "drop"].forEach(type => dropZone.addEventListener(type, event => {
  event.preventDefault();
  dropZone.classList.remove("dragover");
}));
dropZone.addEventListener("drop", event => addFiles(event.dataTransfer.files));

async function sha256(file) {
  if (!crypto.subtle) {
    throw new Error("Web Crypto ist nicht verfügbar. Öffne die Website über localhost oder HTTPS.");
  }
  const buffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

function setProgress(done, total) {
  const percent = total ? Math.round((done / total) * 100) : 0;
  $("progressBar").style.width = `${percent}%`;
  $("progressPercent").textContent = `${percent}%`;
  $("progressText").textContent = `Analysiere Datei ${done} von ${total}`;
}

function renderStats() {
  const hits = state.results.filter(result => result.status === "hit").length;
  const errors = state.results.filter(result => result.status === "error").length;
  $("filesCount").textContent = state.results.length;
  $("threatCount").textContent = hits;
  $("errorCount").textContent = errors;
  $("summaryNumber").textContent = state.results.length;
  const ratio = state.results.length ? hits / state.results.length : 0;
  const degrees = Math.round(ratio * 360);
  $("summaryRing").style.background =
    `conic-gradient(${hits ? "#ef343b" : "#58d69b"} ${degrees}deg, #352124 ${degrees}deg)`;

  if (!state.results.length) {
    $("summaryTitle").textContent = "Bereit für den ersten Scan";
    $("summaryDescription").textContent = "Wähle Dateien aus, um eine lokale Analyse zu starten.";
  } else if (hits) {
    $("summaryTitle").textContent = `${hits} Testtreffer markiert`;
    $("summaryDescription").textContent = "Prüfe die markierten Dateien manuell. Es wurde nichts verändert.";
  } else {
    $("summaryTitle").textContent = "Keine Testtreffer";
    $("summaryDescription").textContent = "Es wurden keine Treffer in der lokalen Demo-Signaturprüfung gefunden.";
  }
}

function renderResults() {
  const body = $("resultsBody");
  body.replaceChildren();

  if (!state.results.length) {
    const row = document.createElement("tr");
    row.className = "empty-row";
    const cell = document.createElement("td");
    cell.colSpan = 3;
    cell.textContent = "Noch keine Analyse durchgeführt.";
    row.append(cell);
    body.append(row);
    $("exportButton").disabled = true;
    return;
  }

  for (const result of state.results) {
    const row = document.createElement("tr");
    const nameCell = document.createElement("td");
    nameCell.textContent = result.name;
    const hashCell = document.createElement("td");
    hashCell.className = "hash-cell";
    hashCell.textContent = result.hash || "—";
    const statusCell = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = `result-pill ${result.status === "hit" ? "result-hit" : result.status === "error" ? "result-error" : "result-clean"}`;
    pill.textContent = result.status === "hit"
      ? "DEMO-TESTTREFFER"
      : result.status === "error" ? "NICHT LESBAR" : "KEIN TESTTREFFER";
    statusCell.append(pill);
    row.append(nameCell, hashCell, statusCell);
    body.append(row);
  }
  $("exportButton").disabled = false;
}

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function startScan() {
  if (state.scanning || !state.files.length) return;
  state.scanning = true;
  state.results = [];
  $("scanButton").disabled = true;
  $("progressWrap").hidden = false;
  $("status-pill")?.classList.remove("offline");
  $("summaryTitle").textContent = "Analyse läuft …";
  renderResults();
  renderStats();

  const useDemo = $("demoMode").checked;
  const total = state.files.length;

  for (let index = 0; index < total; index++) {
    const file = state.files[index];
    let result;

    try {
      const hash = await sha256(file);
      // Absichtlich harmlose Demo-Regel, keine echte Malware-Signatur.
      const isDemoHit = useDemo && file.name.toLowerCase().includes("eicar-demo");
      result = {
        name: file.webkitRelativePath || file.name,
        hash,
        status: isDemoHit ? "hit" : "clean"
      };
    } catch (error) {
      result = { name: file.name, hash: "", status: "error" };
    }

    state.results.push(result);
    setProgress(index + 1, total);
    renderResults();
    renderStats();
    await wait(35);
  }

  state.scanning = false;
  $("scanButton").disabled = state.files.length === 0;
  $("lastScan").textContent = new Date().toLocaleTimeString("de-DE", {
    hour: "2-digit", minute: "2-digit"
  });
  $("summaryTitle").textContent = "Analyse abgeschlossen";
  $("progressText").textContent = "Analyse abgeschlossen";
  showToast("Lokale Analyse abgeschlossen.");
}

$("scanButton").addEventListener("click", startScan);

$("clearButton").addEventListener("click", () => {
  if (state.scanning) {
    showToast("Bitte warte, bis der Scan beendet ist.");
    return;
  }
  state.files = [];
  state.results = [];
  fileInput.value = "";
  folderInput.value = "";
  $("selectionInfo").textContent = "Noch keine Dateien ausgewählt";
  $("scanButton").disabled = true;
  $("progressWrap").hidden = true;
  $("progressBar").style.width = "0%";
  $("progressPercent").textContent = "0%";
  $("lastScan").textContent = "—";
  renderResults();
  renderStats();
  showToast("Sitzung wurde zurückgesetzt.");
});

$("exportButton").addEventListener("click", () => {
  if (!state.results.length) return;
  const lines = [
    "CART3R SECURITY — Lokaler Demo-Scan",
    `Datum: ${new Date().toLocaleString("de-DE")}`,
    "Hinweis: Kein vollständiger Virenscanner; kein Treffer bedeutet nicht sicher.",
    "",
    "Datei;SHA-256;Ergebnis",
    ...state.results.map(item =>
      [item.name, item.hash, item.status].map(value =>
        `"${String(value).replaceAll('"', '""')}"`
      ).join(";")
    )
  ];
  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "cart3r-scanbericht.csv";
  link.click();
  URL.revokeObjectURL(url);
});

renderStats();
renderResults();
