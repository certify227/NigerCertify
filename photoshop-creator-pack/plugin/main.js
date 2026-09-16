const { entrypoints } = require("uxp");
const { PLATFORM_PRESETS, defaultPresetIds } = require("./data/presets.js");
const { getNarrative, buildBeats } = require("./data/narratives.js");
const naming = require("./core/naming.js");
const copy = require("./core/copy.js");
const ps = require("./core/ps.js");
const canvas = require("./modules/canvas.js");
const type = require("./modules/type.js");
const story = require("./modules/story.js");
const exporter = require("./modules/export.js");

const state = {
  variantIndex: 0,
  safeVisible: true,
  ready: false
};

function $(id) {
  return document.getElementById(id);
}

function pickerValue(id, fallback) {
  const el = $(id);
  if (!el) return fallback;
  if (el.value) return el.value;
  const selected = el.querySelector("sp-menu-item[selected]");
  return (selected && selected.getAttribute("value")) || fallback;
}

function radioValue(id, fallback) {
  const group = $(id);
  if (!group) return fallback;
  return group.selected || group.getAttribute("selected") || fallback;
}

function isChecked(id) {
  const el = $(id);
  if (!el) return false;
  if (el.checked === true || el.checked === "true") return true;
  if (el.hasAttribute("checked")) {
    const v = el.getAttribute("checked");
    return v !== "false";
  }
  return false;
}

function setChecked(id, value) {
  const el = $(id);
  if (!el) return;
  el.checked = value;
  if (value) el.setAttribute("checked", "true");
  else el.removeAttribute("checked");
}

function setStatus(message, kind) {
  const el = $("status");
  if (!el) return;
  el.textContent = message;
  el.classList.remove("error", "ok");
  if (kind) el.classList.add(kind);
}

function busy(on) {
  document.querySelectorAll("sp-button").forEach((btn) => {
    if (on) btn.setAttribute("disabled", "true");
    else btn.removeAttribute("disabled");
  });
}

async function withBusy(label, fn) {
  busy(true);
  setStatus(label);
  try {
    return await fn();
  } catch (err) {
    if (err && err.cancelled) {
      setStatus("Annulé.");
      return null;
    }
    setStatus(ps.errorMessage(err), "error");
    throw err;
  } finally {
    busy(false);
  }
}

function renderPresets() {
  const root = $("preset-list");
  if (!root) return;
  root.innerHTML = "";
  const defaults = new Set(defaultPresetIds());
  PLATFORM_PRESETS.forEach((preset) => {
    const row = document.createElement("div");
    row.className = "preset-row";
    const box = document.createElement("sp-checkbox");
    box.setAttribute("id", `preset-${preset.id}`);
    box.textContent = `${preset.short}  ·  ${preset.label}`;
    if (defaults.has(preset.id)) box.setAttribute("checked", "true");
    const dim = document.createElement("span");
    dim.className = "preset-dim";
    dim.textContent = `${preset.width}×${preset.height}`;
    row.appendChild(box);
    row.appendChild(dim);
    root.appendChild(row);
  });
}

function selectedPresetIds() {
  return PLATFORM_PRESETS.filter((p) => isChecked(`preset-${p.id}`)).map((p) => p.id);
}

function setAllPresets(on) {
  PLATFORM_PRESETS.forEach((p) => setChecked(`preset-${p.id}`, on));
}

function renderBeats() {
  const id = pickerValue("story-template", "pas");
  const tpl = getNarrative(id);
  const raw = parseInt(fieldValue("frame-count"), 10);
  const n = Number.isFinite(raw) ? raw : tpl.defaultFrames;
  const beats = buildBeats(id, n);
  const root = $("beat-list");
  if (!root) return;
  root.innerHTML = "";
  beats.forEach((beat) => {
    const el = document.createElement("div");
    el.className = "beat";
    el.innerHTML = `<strong>FR ${String(beat.index).padStart(2, "0")} · ${beat.title}</strong><span>${beat.hint}</span>`;
    root.appendChild(el);
  });
}

function renderVariants(hook) {
  const root = $("hook-variants");
  if (!root) return;
  root.innerHTML = "";
  const variants = copy.hookVariants(hook);
  variants.forEach((text, i) => {
    if (!text) return;
    const chip = document.createElement("button");
    chip.className = "chip" + (i === state.variantIndex ? " active" : "");
    chip.type = "button";
    chip.textContent = text;
    chip.onclick = () => {
      state.variantIndex = i;
      $("txt-hook").value = text;
      renderVariants(hook);
    };
    root.appendChild(chip);
  });
}

function parseBrief() {
  const slots = copy.splitBrief($("brief").value);
  const templated = copy.applyTemplate(slots, pickerValue("type-template", "hook_proof_cta"));
  $("txt-hook").value = templated.hook;
  $("txt-proof").value = templated.proof;
  $("txt-cta").value = templated.cta;
  $("txt-hook").setAttribute("value", templated.hook);
  $("txt-proof").setAttribute("value", templated.proof);
  $("txt-cta").setAttribute("value", templated.cta);
  state.variantIndex = 0;
  renderVariants(templated.hook);
}

function fieldValue(id) {
  const el = $(id);
  return (el && (el.value || el.getAttribute("value"))) || "";
}

function syncDocLabel() {
  try {
    const { app } = ps.photoshop();
    const doc = app.activeDocument;
    $("doc-label").textContent = doc ? doc.title || doc.name : "Aucun document";
  } catch (_) {
    $("doc-label").textContent = "Photoshop non lié";
  }
}

function setupTabs() {
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.onclick = () => {
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("selected"));
      document.querySelectorAll(".page").forEach((p) => p.classList.remove("visible"));
      tab.classList.add("selected");
      document.getElementById(`page-${tab.dataset.tab}`).classList.add("visible");
    };
  });
}

async function onMaster() {
  await withBusy("Création de CP_MASTER…", async () => {
    await ps.ensureDocument();
    await ps.execute("Creator Pack — Master", async (_ctx, doc) => {
      await canvas.ensureMaster(doc);
    });
    setStatus("Artboard CP_MASTER prêt.", "ok");
    syncDocLabel();
  });
}

async function onSubject() {
  await withBusy("Select Subject…", async () => {
    await ps.execute("Creator Pack — Sujet", async (_ctx, doc) => {
      await canvas.detectSubject(doc);
    });
    setStatus("Calque CP_SUBJECT créé. Le recadrage s’ancrera dessus.", "ok");
  });
}

async function onCanvas() {
  await withBusy("Génération des artboards…", async () => {
    await ps.ensureDocument();
    const ids = selectedPresetIds();
    if (!ids.length) throw new Error("Coche au moins un format.");
    const result = await canvas.applyCanvas({
      presetIds: ids,
      cropMode: radioValue("crop-mode", "subject"),
      showSafezone: isChecked("chk-safezone"),
      replace: isChecked("chk-replace"),
      onProgress: (id, i, n) => setStatus(`Format ${i + 1}/${n} · ${id}`)
    });
    const parts = [];
    if (result.created.length) parts.push(`créés: ${result.created.join(", ")}`);
    if (result.replaced && result.replaced.length) parts.push(`remplacés: ${result.replaced.join(", ")}`);
    if (result.skipped.length) parts.push(`déjà là: ${result.skipped.join(", ")}`);
    setStatus(parts.join(" · ") || "Aucun artboard à créer.", "ok");
    syncDocLabel();
  });
}

async function onSafeToggle() {
  state.safeVisible = !state.safeVisible;
  await withBusy("Overlays…", async () => {
    const r = await canvas.toggleSafezones(state.safeVisible);
    $("btn-safe-toggle").textContent = state.safeVisible ? "Masquer overlays" : "Afficher overlays";
    setStatus(`${r.count} overlay(s) ${state.safeVisible ? "visibles" : "masqués"}.`);
  });
}

async function onType() {
  await withBusy("Type Rhythm…", async () => {
    if (!fieldValue("txt-hook") && fieldValue("brief")) parseBrief();
    if (!fieldValue("txt-hook")) throw new Error("Renseigne un hook ou un brief.");
    const result = await type.applyType({
      hook: fieldValue("txt-hook"),
      proof: fieldValue("txt-proof"),
      cta: fieldValue("txt-cta") || "En savoir plus",
      templateId: pickerValue("type-template", "hook_proof_cta"),
      density: pickerValue("type-density", "normal"),
      scrim: isChecked("chk-scrim"),
      scope: isChecked("chk-type-all") ? "all" : "active",
      skipFrames: true,
      fallbackPresetId: selectedPresetIds()[0] || pickerValue("story-preset", "ig_feed_45")
    });
    const overflows = (result.report || []).filter((r) => r.overflow);
    const host = $("type-report");
    host.innerHTML = (result.report || [])
      .map((r) => {
        const cls = r.overflow ? "warn" : "ok";
        const size = r.slots.hook ? `${r.slots.hook.size} pt` : "—";
        return `<div class="${cls}">${r.artboard} — hook ${size}${r.overflow ? " · overflow" : ""}</div>`;
      })
      .join("");
    setStatus(
      overflows.length
        ? `${overflows.length} format(s) encore trop longs. Raccourcis le hook.`
        : `Typo appliquée sur ${result.report.length} artboard(s).`,
      overflows.length ? undefined : "ok"
    );
  });
}

async function onStory() {
  await withBusy("Storyboard…", async () => {
    await ps.ensureDocument();
    const tpl = pickerValue("story-template", "pas");
    const presetId = pickerValue("story-preset", "ig_feed_45");
    const abName = naming.artboardName(presetId);
    const { app } = ps.photoshop();
    if (!ps.findLayerByName(app.activeDocument, abName)) {
      await canvas.applyCanvas({
        presetIds: [presetId],
        cropMode: radioValue("crop-mode", "subject"),
        showSafezone: false,
        replace: false
      });
    }
    if (isChecked("chk-cont-type") && (fieldValue("txt-hook") || fieldValue("brief"))) {
      if (!fieldValue("txt-hook")) parseBrief();
      await type.applyType({
        hook: fieldValue("txt-hook"),
        proof: fieldValue("txt-proof"),
        cta: fieldValue("txt-cta") || "En savoir plus",
        templateId: pickerValue("type-template", "hook_proof_cta"),
        density: pickerValue("type-density", "normal"),
        scrim: isChecked("chk-scrim"),
        scope: "all",
        skipFrames: true,
        fallbackPresetId: presetId
      });
    }
    const result = await story.applyStory({
      templateId: tpl,
      frameCount: parseInt(fieldValue("frame-count"), 10) || getNarrative(tpl).defaultFrames,
      showNotes: isChecked("chk-notes"),
      presetId,
      continuity: {
        background: isChecked("chk-cont-bg"),
        subject: isChecked("chk-cont-subject"),
        type: isChecked("chk-cont-type")
      }
    });
    setStatus(
      `Source ${result.source} → ${result.frames.join(", ")} (${result.created.length} nouvelles).`,
      "ok"
    );
  });
}

async function onExport() {
  await withBusy("Export du pack…", async () => {
    const result = await exporter.exportPack({
      presetIds: selectedPresetIds(),
      includeNotes: isChecked("chk-notes"),
      includeMaster: isChecked("chk-export-master"),
      type: {
        density: pickerValue("type-density", "normal"),
        template: pickerValue("type-template", "hook_proof_cta")
      },
      story: { template: pickerValue("story-template", "pas") }
    });
    if (!result) return;
    setStatus(`Exporté dans ${result.folder} (${result.files.length} fichiers).`, "ok");
  });
}

function reloadPlugin() {
  window.location.reload();
}

function bindUi() {
  $("btn-refresh").onclick = syncDocLabel;
  $("btn-master").onclick = () => onMaster().catch(() => {});
  $("btn-subject").onclick = () => onSubject().catch(() => {});
  $("btn-canvas").onclick = () => onCanvas().catch(() => {});
  $("btn-safe-toggle").onclick = () => onSafeToggle().catch(() => {});
  $("btn-parse").onclick = parseBrief;
  $("btn-type").onclick = () => onType().catch(() => {});
  $("btn-story").onclick = () => onStory().catch(() => {});
  $("btn-export").onclick = () => onExport().catch(() => {});
  $("btn-presets-all").onclick = () => setAllPresets(true);
  $("btn-presets-none").onclick = () => setAllPresets(false);
  $("story-template").addEventListener("change", () => {
    const tpl = getNarrative(pickerValue("story-template", "pas"));
    $("frame-count").value = String(tpl.defaultFrames);
    $("frame-count").setAttribute("value", String(tpl.defaultFrames));
    renderBeats();
  });
  $("frame-count").addEventListener("change", renderBeats);
  $("brief").addEventListener("change", () => {
    if (!fieldValue("txt-hook")) parseBrief();
  });
  $("type-template").addEventListener("change", () => {
    if (fieldValue("brief") || fieldValue("txt-hook")) parseBrief();
  });
}

function init() {
  if (state.ready) {
    syncDocLabel();
    return;
  }
  if (!$("preset-list")) return;
  renderPresets();
  renderBeats();
  setupTabs();
  bindUi();
  syncDocLabel();
  state.ready = true;

  try {
    const { action } = ps.photoshop();
    action.addNotificationListener(["select", "open", "make"], () => syncDocLabel());
  } catch (_) {
    /* hors Photoshop */
  }
}

entrypoints.setup({
  commands: {
    reloadPlugin
  },
  panels: {
    creatorPack: {
      show() {
        init();
      },
      menuItems: [
        { id: "reload", label: "Recharger le panneau", enabled: true, checked: false },
        { id: "about", label: "À propos", enabled: true, checked: false }
      ],
      invokeMenu(id) {
        if (id === "reload") reloadPlugin();
        if (id === "about") {
          ps.photoshop().app.showAlert(
            "Creator Pack 1.1 — Social Canvas, Type Rhythm, Storyboard Frames.\nPhotoshop 2025+ (26.0). Calques CP_*."
          );
        }
      }
    }
  }
});

if (document.readyState !== "loading") {
  try {
    init();
  } catch (_) {
    /* entrypoints.show will init */
  }
} else {
  document.addEventListener("DOMContentLoaded", () => {
    try {
      init();
    } catch (_) {
      /* ignore */
    }
  });
}
