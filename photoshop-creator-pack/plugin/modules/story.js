const naming = require("../core/naming.js");
const { buildBeats, getNarrative } = require("../data/narratives.js");
const ps = require("../core/ps.js");
const canvas = require("./canvas.js");

async function applyStory(options) {
  const templateId = options.templateId || "pas";
  const tpl = getNarrative(templateId);
  const count = Number(options.frameCount) || tpl.defaultFrames;
  const beats = buildBeats(templateId, count);
  const continuity = options.continuity || { background: true, subject: true, type: true };

  return ps.execute("Creator Pack — Storyboard Frames", async (_ctx, doc) => {
    const master = await canvas.ensureMaster(doc);
    const masterBox = await ps.getArtboardRect(master);
    let cursorX = masterBox.right + 80;
    const boards = ps.artboardsOf(doc);
    for (const b of boards) {
      const r = ps.boundsOf(b);
      if (r.right + 80 > cursorX) cursorX = r.right + 80;
    }

    const created = [];
    const reused = [];

    for (const beat of beats) {
      const name = naming.frameName(beat.index);
      let board = ps.findLayerByName(doc, name);
      if (board) {
        reused.push(name);
      } else {
        const copies = await doc.duplicateLayers([master]);
        board = copies[0];
        board.name = name;
        const after = await ps.getArtboardRect(board);
        const dx = cursorX - after.left;
        const dy = 0 - after.top;
        if (typeof board.translate === "function") {
          await board.translate(dx, dy);
        } else {
          await ps.selectOnly(board);
          await ps.translateSelected(dx, dy);
        }
        created.push(name);
        cursorX += (after.width || masterBox.width) + 80;
      }

      await writeNote(doc, board, beat, options.showNotes);
      await applyBeatVisibility(board, beat, continuity);
    }

    return {
      template: tpl.id,
      frames: beats.map((b) => naming.frameName(b.index)),
      beats,
      created,
      reused
    };
  });
}

async function writeNote(doc, board, beat, showNotes) {
  const noteName = naming.NOTE;
  const text = `${beat.title} — ${beat.hint}`;
  let note = null;
  if (board.layers) {
    note = ps.walkLayers(board.layers, []).find((l) => l.name === noteName);
  }
  const rect = await ps.getArtboardRect(board);
  if (!note) {
    const type = require("./type.js");
    note = await type.makeTextBox({
      name: noteName,
      text,
      box: {
        left: rect.left + 24,
        top: rect.top + 16,
        right: rect.right - 24,
        bottom: rect.top + 80
      },
      size: 14,
      rgb: [180, 220, 255],
      align: "left"
    });
    try {
      if (note && typeof note.move === "function") await note.move(board, "inside");
    } catch (_) {
      /* ignore */
    }
  } else {
    try {
      if (note.textItem) note.textItem.contents = text;
    } catch (_) {
      /* ignore */
    }
  }
  if (note) note.visible = Boolean(showNotes);
}

async function applyBeatVisibility(board, beat, continuity) {
  if (!board.layers) return;
  const layers = ps.walkLayers(board.layers, []);
  for (const layer of layers) {
    if (layer.name === naming.TXT.hook) layer.visible = beat.slot !== "cta" || beat.index === 1;
    if (layer.name === naming.TXT.proof) layer.visible = beat.slot === "proof" || beat.slot === "cta";
    if (layer.name === naming.TXT.cta) layer.visible = beat.slot === "cta";
    if (!continuity.background && layer.name === naming.BG) {
      /* keep visible — unlinking is a manual "New shot" */
    }
  }
  if (beat.slot === "hook") {
    const proof = layers.find((l) => l.name === naming.TXT.proof);
    const cta = layers.find((l) => l.name === naming.TXT.cta);
    if (proof) proof.visible = false;
    if (cta) cta.visible = false;
  }
  if (beat.slot === "cta") {
    const hook = layers.find((l) => l.name === naming.TXT.hook);
    const proof = layers.find((l) => l.name === naming.TXT.proof);
    if (hook) hook.visible = false;
    if (proof) proof.visible = true;
  }
}

async function reorderFrames(fromIndex, toIndex) {
  return ps.execute("Creator Pack — Réordonner", async (_ctx, doc) => {
    const frames = ps
      .artboardsOf(doc)
      .filter((l) => naming.parseFrameIndex(l.name) != null)
      .sort((a, b) => naming.parseFrameIndex(a.name) - naming.parseFrameIndex(b.name));
    if (!frames.length) return { frames: [] };
    const item = frames.splice(fromIndex, 1)[0];
    frames.splice(toIndex, 0, item);
    frames.forEach((layer, i) => {
      layer.name = naming.frameName(i + 1);
    });
    return { frames: frames.map((f) => f.name) };
  });
}

if (typeof module !== "undefined") {
  module.exports = { applyStory, reorderFrames };
}
