const { PLATFORM_PRESETS, getPreset } = require("./../data/presets.js");
const { getNarrative, buildBeats } = require("./../data/narratives.js");
const naming = require("./naming.js");
const crop = require("./crop.js");
const fit = require("./fit.js");
const copy = require("./copy.js");

function planCanvas(master, presetIds, cropMode, subject) {
  const src = {
    left: 0,
    top: 0,
    right: master.width,
    bottom: master.height,
    width: master.width,
    height: master.height
  };
  return presetIds.map((id) => {
    const preset = getPreset(id);
    if (!preset) throw new Error(`Preset inconnu: ${id}`);
    const transform = crop.computeCoverTransform(src, preset, subject, cropMode);
    return {
      name: naming.artboardName(id),
      preset,
      transform,
      safe: crop.safeRect(preset),
      typeBoxes: crop.typeBoxes(preset, "normal")
    };
  });
}

function planType(slots, presetIds, density, variantIndex, templateId) {
  const applied = copy.applyTemplate(slots, templateId || "hook_proof_cta");
  const variants = copy.hookVariants(applied.hook);
  const hook = variants[variantIndex || 0] || applied.hook;
  const result = [];
  for (const id of presetIds) {
    const preset = getPreset(id);
    if (!preset) continue;
    const boxes = crop.typeBoxes(preset, density);
    const dens = density || "normal";
    const hookFit = fit.fitFontSize({
      text: hook,
      maxWidth: boxes.hook.width,
      maxHeight: boxes.hook.height,
      maxPt: preset.type.hook.maxPt,
      minPt: preset.type.hook.minPt,
      maxLines: preset.type.hook.maxLines,
      density: dens
    });
    const proofFit = fit.fitFontSize({
      text: applied.proof,
      maxWidth: boxes.proof.width,
      maxHeight: boxes.proof.height,
      maxPt: preset.type.proof.maxPt,
      minPt: preset.type.proof.minPt,
      maxLines: preset.type.proof.maxLines,
      density: dens
    });
    const ctaFit = fit.fitFontSize({
      text: applied.cta,
      maxWidth: boxes.cta.width,
      maxHeight: boxes.cta.height,
      maxPt: preset.type.cta.maxPt,
      minPt: preset.type.cta.minPt,
      maxLines: preset.type.cta.maxLines,
      density: dens
    });
    result.push({
      presetId: id,
      artboard: naming.artboardName(id),
      boxes,
      hook: { text: hook, fit: hookFit },
      proof: { text: applied.proof, fit: proofFit },
      cta: { text: applied.cta, fit: ctaFit },
      overflow: Boolean(hookFit.overflow || proofFit.overflow || ctaFit.overflow)
    });
  }
  return { slots: { ...applied, hook }, variants, items: result };
}

function planStory(templateId, frameCount, presetId) {
  const preset = getPreset(presetId) || getPreset("ig_feed_45");
  const beats = buildBeats(templateId, frameCount);
  const tpl = getNarrative(templateId);
  return {
    template: tpl,
    preset,
    frames: beats.map((beat) => ({
      name: naming.frameName(beat.index),
      beat,
      export: true
    }))
  };
}

function buildManifest(meta) {
  return {
    version: "1.0",
    pack: "creator",
    createdAt: meta.createdAt || new Date().toISOString(),
    document: meta.document || "",
    locale: "fr-FR",
    canvas: meta.canvas || {},
    type: meta.type || {},
    story: meta.story || {},
    files: meta.files || []
  };
}

if (typeof module !== "undefined") {
  module.exports = {
    PLATFORM_PRESETS,
    planCanvas,
    planType,
    planStory,
    buildManifest
  };
}
