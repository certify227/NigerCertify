const { entrypoints } = require("uxp");
const { PLATFORM_PRESETS, defaultPresetIds } = require("./data/presets.js");
const { getNarrative, buildBeats } = require("./data/narratives.js");
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
  return Boolean(el && el.checked);
}

function setStatus(message, kind) {
  const el = $("status");
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
    const result = await fn();
    return result;
  } catch (err) {
    const msg = ps.errorMessage(err);
    setStatus(msg, "error");
    try {
      await ps.photoshop().app.showAlert(msg);
    } catch (_) {
      /* panel-only */
    }
    throw err;
  } finally {
    busy(false);
  }
}

function renderPresets() {
  const root = $("preset-list");
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

function renderBeats() {
  const id = pickerValue("story-template", "pas");
  const tpl = getNarrative(id);
  const raw = parseInt($("frame-count").value, 10);
  const n = Number.isFinite(raw) ? raw : tpl.defaultFrames;
  const beats = buildBeats(id, n);
  const root = $("beat-list");
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
      renderVariants(text);
    };
    root.appendChild(chip);
  });
}

function parseBrief() {
  const slots = copy.splitBrief($("brief").value);
  const templated = copy.applyTemplate(slots, pickerValue("type-template", "hook_proof_cta"));
  $("txt-hook").setAttribute("value", templated.hook);
  $("txt-proof").setAttribute("value", templated.proof);
  $("txt-cta").setAttribute("value", templated.cta);
  $("txt-hook").value = templated.hook;
  $("txt-proof").value = templated.proof;
  $("txt-cta").value = templated.cta;
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
    const result = await canvas.applyCanvas({
      presetIds: selectedPresetIds(),
      cropMode: radioValue("crop-mode", "subject"),
      showSafezone: isChecked("chk-safezone")
    });
    const parts = [];
    if (result.created.length) parts.push(`créés: ${result.created.join(", ")}`);
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
    const result = await type.applyType({
      hook: fieldValue("txt-hook"),
      proof: fieldValue("txt-proof"),
      cta: fieldValue("txt-cta") || "En savoir plus",
      templateId: pickerValue("type-template", "hook_proof_cta"),
      density: pickerValue("type-density", "normal"),
      variantIndex: state.variantIndex,
      scrim: isChecked("chk-scrim"),
      scope: isChecked("chk-type-all") ? "all" : "active",
      fallbackPresetId: selectedPresetIds()[0] || "ig_feed_45"
    });
    const overflows = (result.report || []).filter((r) => r.overflow);
    const host = $("type-report");
    host.innerHTML = (result.report || [])
      .map((r) => {
        const cls = r.overflow ? "warn" : "ok";
        return `<div class="${cls}">${r.artboard} — hook ${r.slots.hook ? r.slots.hook.size + " pt" : "—"}${r.overflow ? " · overflow" : ""}</div>`;
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
    const result = await story.applyStory({
      templateId: tpl,
      frameCount: parseInt(fieldValue("frame-count"), 10) || getNarrative(tpl).defaultFrames,
      showNotes: isChecked("chk-notes"),
      continuity: {
        background: isChecked("chk-cont-bg"),
        subject: isChecked("chk-cont-subject"),
        type: isChecked("chk-cont-type")
      }
    });
    if (isChecked("chk-cont-type") && (fieldValue("txt-hook") || fieldValue("brief"))) {
      if (!fieldValue("txt-hook")) parseBrief();
      await type.applyType({
        hook: fieldValue("txt-hook"),
        proof: fieldValue("txt-proof"),
        cta: fieldValue("txt-cta") || "En savoir plus",
        templateId: pickerValue("type-template", "hook_proof_cta"),
        density: pickerValue("type-density", "normal"),
        variantIndex: state.variantIndex,
        scrim: isChecked("chk-scrim"),
        scope: "all",
        fallbackPresetId: pickerValue("story-preset", "ig_feed_45")
      });
    }
    setStatus(`Frames ${result.frames.join(", ")} (${result.created.length} nouvelles).`, "ok");
  });
}

async function onExport() {
  await withBusy("Export du pack…", async () => {
    const result = await exporter.exportPack({
      presetIds: selectedPresetIds(),
      includeNotes: isChecked("chk-notes"),
      type: {
        density: pickerValue("type-density", "normal"),
        template: pickerValue("type-template", "hook_proof_cta")
      },
      story: { template: pickerValue("story-template", "pas") }
    });
    setStatus(`Exporté dans ${result.folder} (${result.files.length} fichiers).`, "ok");
  });
}

function reloadPlugin() {
  window.location.reload();
}

function init() {
  if (state.ready) {
    syncDocLabel();
    return;
  }
  state.ready = true;
  renderPresets();
  renderBeats();
  setupTabs();
  syncDocLabel();

  $("btn-refresh").onclick = syncDocLabel;
  $("btn-master").onclick = () => onMaster().catch(() => {});
  $("btn-subject").onclick = () => onSubject().catch(() => {});
  $("btn-canvas").onclick = () => onCanvas().catch(() => {});
  $("btn-safe-toggle").onclick = () => onSafeToggle().catch(() => {});
  $("btn-parse").onclick = parseBrief;
  $("btn-type").onclick = () => onType().catch(() => {});
  $("btn-story").onclick = () => onStory().catch(() => {});
  $("btn-export").onclick = () => onExport().catch(() => {});
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
            "Creator Pack 1.0 — Social Canvas, Type Rhythm, Storyboard Frames.\nPhotoshop 2025+ (26.0). Calques CP_*."
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
