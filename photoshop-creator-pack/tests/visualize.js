"use strict";

const fs = require("fs");
const path = require("path");
const { planCanvas, planType, planStory } = require("../plugin/core/plan.js");
const { getPreset } = require("../plugin/data/presets.js");

const master = { width: 1080, height: 1350 };
const subject = { left: 280, top: 220, right: 800, bottom: 1180, width: 520, height: 960 };
const presetIds = ["ig_feed_45", "ig_story", "tiktok", "yt_thumb"];
const canvas = planCanvas(master, presetIds, "subject", subject);
const type = planType(
  {
    hook: "Plus légère. Plus loin.",
    proof: "Amorti +20% sur chaque foulée",
    cta: "Shop now"
  },
  presetIds,
  "normal",
  0,
  "hook_proof_cta"
);
const story = planStory("pas", 5, "ig_feed_45");

const SCALE = 0.18;
const GAP = 36;
const PAD = 48;

function sx(n) {
  return n * SCALE;
}

let x = PAD;
const blocks = canvas.map((item) => {
  const p = item.preset;
  const w = sx(p.width);
  const h = sx(p.height);
  const block = { item, x, y: PAD + 40, w, h };
  x += w + GAP;
  return block;
});

const storyY = PAD + 40 + Math.max(...blocks.map((b) => b.h)) + 90;
const frameW = sx(1080);
const frameH = sx(1350);
const frames = story.frames.map((fr, i) => ({
  fr,
  x: PAD + i * (frameW + 24),
  y: storyY,
  w: frameW,
  h: frameH
}));

const width = Math.max(
  blocks[blocks.length - 1].x + blocks[blocks.length - 1].w,
  frames[frames.length - 1].x + frames[frames.length - 1].w
) + PAD;
const height = storyY + frameH + 80;

function board(b, fill) {
  const t = b.item.transform;
  const imgW = sx(t.scaledW);
  const imgH = sx(t.scaledH);
  const imgX = b.x + t.tx * SCALE;
  const imgY = b.y + t.ty * SCALE;
  const safe = b.item.safe;
  return `
  <g>
    <rect x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}" rx="6" fill="${fill}" stroke="#111" />
    <rect x="${imgX}" y="${imgY}" width="${imgW}" height="${imgH}" fill="#3d4a63" opacity="0.9" />
    <rect x="${b.x + sx(subject.left * t.scale)}" y="${b.y + t.ty * SCALE + sx(subject.top * t.scale)}" width="${sx(subject.width * t.scale)}" height="${sx(subject.height * t.scale)}" fill="#8ab4f8" opacity="0.55" />
    <rect x="${b.x + sx(safe.left)}" y="${b.y + sx(safe.top)}" width="${sx(safe.width)}" height="${sx(safe.height)}" fill="none" stroke="#ff5a6a" stroke-dasharray="4 3" />
    <text x="${b.x}" y="${b.y - 10}" fill="#f4f4f4" font-size="13" font-family="sans-serif">${b.item.preset.short} · ${b.item.name}</text>
  </g>`;
}

const typeNotes = type.items
  .map((i) => `${i.presetId}: hook ${i.hook.fit.size}pt${i.overflow ? " OVERFLOW" : " OK"}`)
  .join("   ·   ");

const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${Math.round(width)}" height="${Math.round(height)}" viewBox="0 0 ${width} ${height}">
  <rect width="100%" height="100%" fill="#1d1d1d"/>
  <text x="${PAD}" y="28" fill="#f4f4f4" font-size="18" font-family="sans-serif" font-weight="700">Creator Pack — golden path (1080×1350 master)</text>
  ${blocks.map((b, i) => board(b, i === 1 || i === 2 ? "#151515" : "#222")).join("\n")}
  <text x="${PAD}" y="${storyY - 18}" fill="#f4f4f4" font-size="16" font-family="sans-serif">Storyboard PAS</text>
  ${frames
    .map(
      (f) => `
    <g>
      <rect x="${f.x}" y="${f.y}" width="${f.w}" height="${f.h}" rx="6" fill="#2a2a2a" stroke="#2680eb"/>
      <text x="${f.x + 8}" y="${f.y + 22}" fill="#8ab4f8" font-size="12" font-family="sans-serif">${f.fr.name}</text>
      <text x="${f.x + 8}" y="${f.y + 40}" fill="#f4f4f4" font-size="11" font-family="sans-serif">${f.fr.beat.title}</text>
    </g>`
    )
    .join("")}
  <text x="${PAD}" y="${height - 24}" fill="#b3b3b3" font-size="12" font-family="sans-serif">${typeNotes}</text>
</svg>
`;

const out = path.join(__dirname, "../preview/golden-path.svg");
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, svg);
console.log("wrote", out);

const jsonOut = path.join(__dirname, "../preview/golden-path.json");
fs.writeFileSync(jsonOut, JSON.stringify({ master, subject, canvas, type, story }, null, 2));
console.log("wrote", jsonOut);
