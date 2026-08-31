"use strict";

const assert = require("assert");
const path = require("path");
const fs = require("fs");

const crop = require("../plugin/core/crop.js");
const fit = require("../plugin/core/fit.js");
const copy = require("../plugin/core/copy.js");
const naming = require("../plugin/core/naming.js");
const plan = require("../plugin/core/plan.js");
const { PLATFORM_PRESETS, getPreset, defaultPresetIds } = require("../plugin/data/presets.js");
const { buildBeats, getNarrative, NARRATIVES } = require("../plugin/data/narratives.js");

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed += 1;
    console.log(`  ok  ${name}`);
  } catch (err) {
    failed += 1;
    console.error(`  FAIL  ${name}`);
    console.error(`        ${err.message}`);
  }
}

console.log("naming");
test("préfixe et artboards", () => {
  assert.strictEqual(naming.artboardName("ig_story"), "CP_AB_ig_story");
  assert.strictEqual(naming.frameName(3), "CP_FR_03");
  assert.strictEqual(naming.parseFrameIndex("CP_FR_03"), 3);
  assert.strictEqual(naming.isArtboardName("CP_MASTER"), true);
  assert.strictEqual(naming.isArtboardName("Logo"), false);
  assert.strictEqual(naming.exportSkip("CP_NOTE"), true);
  assert.strictEqual(naming.exportSkip("CP_TXT_HOOK"), false);
});

console.log("presets");
test("ids uniques et défauts", () => {
  const ids = PLATFORM_PRESETS.map((p) => p.id);
  assert.strictEqual(new Set(ids).size, ids.length);
  assert.ok(defaultPresetIds().includes("ig_feed_45"));
  assert.ok(getPreset("tiktok").height === 1920);
});

console.log("crop");
test("cover d’un 4:5 vers 9:16 remplit la hauteur", () => {
  const t = crop.computeCoverTransform(
    { width: 1080, height: 1350 },
    { width: 1080, height: 1920 },
    null,
    "subject"
  );
  assert.ok(Math.abs(t.scaledW - 1080 * (1920 / 1350)) < 1);
  assert.ok(t.scaledH >= 1920 - 0.5);
  assert.strictEqual(t.needsExpand, false);
});

test("letterbox ne croppe pas", () => {
  const t = crop.computeCoverTransform(
    { width: 1080, height: 1350 },
    { width: 1280, height: 720 },
    null,
    "letterbox"
  );
  assert.ok(t.scaledH <= 720 + 0.5);
  assert.ok(t.tx >= 0 || t.ty >= 0);
});

test("subject lock centre le sujet puis clamp", () => {
  const t = crop.computeCoverTransform(
    { width: 1080, height: 1350, left: 0, top: 0, right: 1080, bottom: 1350 },
    { width: 1080, height: 1080 },
    { left: 200, top: 100, right: 500, bottom: 700, width: 300, height: 600 },
    "subject"
  );
  assert.ok(t.crop.width === 1080);
  assert.ok(t.crop.left >= 0);
  assert.ok(t.crop.top >= 0);
});

test("face bias pousse le sujet vers le haut", () => {
  const sub = { left: 400, top: 400, right: 700, bottom: 800, width: 300, height: 400 };
  const src = { width: 1080, height: 1350 };
  const dst = { width: 1080, height: 1080 };
  const face = crop.computeCoverTransform(src, dst, sub, "face");
  const center = crop.computeCoverTransform(src, dst, sub, "subject");
  assert.ok(face.ty < center.ty);
});

test("safeRect Stories laisse 14% / 20%", () => {
  const story = getPreset("ig_story");
  const box = crop.safeRect(story);
  assert.strictEqual(box.top, Math.round(1920 * 0.14));
  assert.strictEqual(box.bottom, 1920 - Math.round(1920 * 0.2));
  assert.ok(box.height < 1920 * 0.7);
});

test("typeBoxes restent dans la safe zone", () => {
  const preset = getPreset("yt_thumb");
  const boxes = crop.typeBoxes(preset, "normal");
  const safe = crop.safeRect(preset);
  assert.ok(boxes.hook.top >= safe.top);
  assert.ok(boxes.cta.bottom <= safe.bottom + 1);
});

console.log("fit / contrast");
test("un hook court ne overflow pas", () => {
  const r = fit.fitFontSize({
    text: "Plus légère",
    maxWidth: 900,
    maxHeight: 400,
    maxPt: 72,
    minPt: 36,
    maxLines: 3,
    density: "normal"
  });
  assert.strictEqual(r.overflow, false);
  assert.ok(r.size >= 36);
});

test("un pavé overflow en miniature", () => {
  const r = fit.fitFontSize({
    text: "Voici une accroche beaucoup trop longue pour tenir confortablement dans une miniature YouTube sans casser la hiérarchie visuelle du Creator Pack",
    maxWidth: 400,
    maxHeight: 80,
    maxPt: 64,
    minPt: 28,
    maxLines: 2,
    density: "compact"
  });
  assert.strictEqual(r.overflow, true);
  assert.strictEqual(r.size, 28);
});

test("texte sur fond sombre → blanc", () => {
  const ink = fit.pickTextColor([20, 20, 20]);
  assert.deepStrictEqual(ink.rgb, [255, 255, 255]);
  assert.ok(ink.contrast >= 4.5);
});

test("texte sur fond clair → noir", () => {
  const ink = fit.pickTextColor([245, 245, 245]);
  assert.deepStrictEqual(ink.rgb, [12, 12, 12]);
});

console.log("copy");
test("splitBrief 3 phrases", () => {
  const s = copy.splitBrief("Nouvelles baskets. Amorti +20%. Shop now.");
  assert.strictEqual(s.hook, "Nouvelles baskets");
  assert.ok(/20%/.test(s.proof));
  assert.ok(/shop now/i.test(s.cta));
});

test("splitBrief 1 phrase ajoute un CTA", () => {
  const s = copy.splitBrief("Drop de septembre");
  assert.strictEqual(s.hook, "Drop de septembre");
  assert.strictEqual(s.cta, "En savoir plus");
});

test("variants conservent un chiffre", () => {
  const v = copy.hookVariants("Moins 30% aujourd’hui seulement");
  assert.ok(v.some((x) => x.includes("30%")));
});

console.log("story");
test("PAS = 5 beats, howto se recadre", () => {
  assert.strictEqual(buildBeats("pas", 5).length, 5);
  assert.strictEqual(buildBeats("howto", 5).length, 5);
  assert.strictEqual(buildBeats("howto", 8).length, 8);
  assert.strictEqual(getNarrative("missing").id, "pas");
  assert.strictEqual(NARRATIVES.length, 5);
});

console.log("plan");
test("planCanvas 4 formats", () => {
  const items = plan.planCanvas({ width: 1080, height: 1350 }, ["ig_feed_45", "ig_story", "tiktok", "yt_thumb"], "subject", {
    left: 300,
    top: 200,
    right: 780,
    bottom: 1100,
    width: 480,
    height: 900
  });
  assert.strictEqual(items.length, 4);
  assert.strictEqual(items[0].name, "CP_AB_ig_feed_45");
  assert.ok(items[1].transform.scalePercent > 100);
});

test("planType : Story plus grand que miniature, hook variant raccourci", () => {
  const short = plan.planType(
    { hook: "Plus légère", proof: "Amorti +20%", cta: "Shop now" },
    ["yt_thumb", "ig_story"],
    "normal",
    0,
    "hook_proof_cta"
  );
  const thumb = short.items.find((i) => i.presetId === "yt_thumb");
  const story = short.items.find((i) => i.presetId === "ig_story");
  assert.ok(story.hook.fit.size > thumb.hook.fit.size);

  const long = plan.planType(
    {
      hook: "Voici une accroche beaucoup trop longue qui ne rentrera jamais dans une miniature YouTube",
      proof: "Amorti",
      cta: "Shop now"
    },
    ["yt_thumb"],
    "compact",
    0,
    "hook_proof_cta"
  );
  assert.ok(long.slots.hook.length <= 42);
  assert.strictEqual(long.items[0].overflow, false);
});

test("planStory PAS nomme CP_FR_01..05", () => {
  const s = plan.planStory("pas", 5, "ig_feed_45");
  assert.deepStrictEqual(
    s.frames.map((f) => f.name),
    ["CP_FR_01", "CP_FR_02", "CP_FR_03", "CP_FR_04", "CP_FR_05"]
  );
});

test("manifest pack creator", () => {
  const m = plan.buildManifest({ document: "Drop.psd", files: ["a.png"] });
  assert.strictEqual(m.pack, "creator");
  assert.strictEqual(m.files.length, 1);
});

test("preset inconnu lève", () => {
  assert.throws(() => plan.planCanvas({ width: 100, height: 100 }, ["nope"], "subject"));
});

console.log("plugin bundle");
test("manifest UXP v5 Photoshop 26+", () => {
  const manifest = JSON.parse(
    fs.readFileSync(path.join(__dirname, "../plugin/manifest.json"), "utf8")
  );
  assert.strictEqual(manifest.manifestVersion, 5);
  assert.strictEqual(manifest.host.app, "PS");
  assert.ok(manifest.host.minVersion.startsWith("26"));
  assert.ok(manifest.entrypoints.some((e) => e.id === "creatorPack" && e.type === "panel"));
  assert.strictEqual(manifest.requiredPermissions.localFileSystem, "fullAccess");
  const html = fs.readFileSync(path.join(__dirname, "../plugin/index.html"), "utf8");
  assert.ok(html.includes("main.js"));
  assert.ok(fs.existsSync(path.join(__dirname, "../plugin/icons/plugin.png")));
  assert.ok(fs.existsSync(path.join(__dirname, "../plugin/main.js")));
});

console.log("");
console.log(`${passed} passed, ${failed} failed`);
if (failed) process.exit(1);
