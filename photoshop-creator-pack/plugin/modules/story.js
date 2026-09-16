const naming = require("../core/naming.js");
const { buildBeats, getNarrative } = require("../data/narratives.js");
const ps = require("../core/ps.js");
const text = require("../core/text.js");
const canvas = require("./canvas.js");

function sourceBoard(doc, presetId) {
  if (presetId) {
    const named = ps.findLayerByName(doc, naming.artboardName(presetId));
    if (named) return named;
  }
  return ps.findLayerByName(doc, naming.MASTER);
}

async function applyStory(options) {
  const templateId = options.templateId || "pas";
  const tpl = getNarrative(templateId);
  const count = Number(options.frameCount) || tpl.defaultFrames;
  const beats = buildBeats(templateId, count);
  const continuity = options.continuity || { background: true, subject: true, type: true };
  const presetId = options.presetId || "ig_feed_45";

  return ps.execute("Creator Pack — Storyboard Frames", async (_ctx, doc) => {
    const master = await canvas.ensureMaster(doc);
    const source = sourceBoard(doc, presetId) || master;
    const sourceBox = await ps.getArtboardRect(source);
    const boards = ps.artboardsOf(doc);
    let cursorX = sourceBox.right + 80;
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
        const copies = await doc.duplicateLayers([source]);
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
        cursorX += (after.width || sourceBox.width) + 80;
      }

      await writeNote(doc, board, beat, options.showNotes);
      applyBeatVisibility(board, beat, continuity);
    }

    return {
      template: tpl.id,
      source: source.name,
      frames: beats.map((b) => naming.frameName(b.index)),
      beats,
      created,
      reused
    };
  });
}

async function writeNote(doc, board, beat, showNotes) {
  const noteName = naming.NOTE;
  const contents = `${beat.title} — ${beat.hint}`;
  let note = null;
  if (board.layers) {
    note = ps.walkLayers(board.layers, []).find((l) => l.name === noteName);
  }
  const rect = await ps.getArtboardRect(board);
  if (!note) {
    note = await text.makeTextBox({
      name: noteName,
      text: contents,
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
    await ps.moveInto(note, board);
  } else {
    try {
      await text.setTextContents(note, contents, 14, [180, 220, 255]);
    } catch (_) {
      /* ignore */
    }
  }
  if (note) note.visible = Boolean(showNotes);
}

function applyBeatVisibility(board, beat, continuity) {
  if (!board.layers) return;
  const layers = ps.walkLayers(board.layers, []);
  const hook = layers.find((l) => l.name === naming.TXT.hook);
  const proof = layers.find((l) => l.name === naming.TXT.proof);
  const cta = layers.find((l) => l.name === naming.TXT.cta);
  if (beat.slot === "hook") {
    if (hook) hook.visible = true;
    if (proof) proof.visible = false;
    if (cta) cta.visible = false;
  } else if (beat.slot === "proof") {
    if (hook) hook.visible = false;
    if (proof) proof.visible = true;
    if (cta) cta.visible = false;
  } else {
    if (hook) hook.visible = false;
    if (proof) proof.visible = Boolean(continuity.type);
    if (cta) cta.visible = true;
  }
}

if (typeof module !== "undefined") {
  module.exports = { applyStory, applyBeatVisibility };
}
