const naming = require("../core/naming.js");
const crop = require("../core/crop.js");
const fit = require("../core/fit.js");
const copy = require("../core/copy.js");
const ps = require("../core/ps.js");
const text = require("../core/text.js");
const { getPreset } = require("../data/presets.js");

function findInBoard(board, name) {
  if (!board || !board.layers) return null;
  return ps.walkLayers(board.layers, []).find((l) => l.name === name) || null;
}

function layerBelongsTo(layer, board) {
  let p = layer.parent;
  while (p) {
    if (p.id === board.id) return true;
    p = p.parent;
  }
  return false;
}

function resolvePresetForBoard(board, fallbackId) {
  const name = board && board.name;
  const fromAb = naming.parsePresetId(name);
  if (fromAb && getPreset(fromAb)) return getPreset(fromAb);
  return getPreset(fallbackId) || getPreset("ig_feed_45");
}

function absoluteBoxes(artboardRect, preset, density) {
  const local = crop.typeBoxes(preset, density);
  const ox = artboardRect.left;
  const oy = artboardRect.top;
  const shift = (r) => ({
    left: r.left + ox,
    top: r.top + oy,
    right: r.right + ox,
    bottom: r.bottom + oy,
    width: r.width,
    height: r.height
  });
  return {
    hook: shift(local.hook),
    proof: shift(local.proof),
    cta: shift(local.cta),
    safe: shift(local.safe)
  };
}

async function sampleBackground(doc, box) {
  try {
    const x = Math.round((box.left + box.right) / 2);
    const y = Math.round((box.top + box.bottom) / 2);
    const color = await doc.sampleColor({ x, y });
    if (color && color.rgb) {
      return [color.rgb.red, color.rgb.green, color.rgb.blue];
    }
  } catch (_) {
    /* default dark */
  }
  return [20, 20, 20];
}

async function applyType(options) {
  const slots = copy.applyTemplate(
    {
      hook: options.hook,
      proof: options.proof,
      cta: options.cta
    },
    options.templateId || "hook_proof_cta"
  );
  const density = options.density || "normal";
  const fallbackId = options.fallbackPresetId || "ig_feed_45";
  const skipFrames = Boolean(options.skipFrames);

  return ps.execute("Creator Pack — Type Rhythm", async (_ctx, doc) => {
    let boards = ps.artboardsOf(doc).filter((b) => naming.isArtboardName(b.name));
    if (skipFrames) {
      boards = boards.filter((b) => naming.parseFrameIndex(b.name) == null);
    }
    if (options.scope === "active") {
      const active = doc.activeLayers && doc.activeLayers[0];
      const pick = active && naming.isArtboardName(active.name) ? [active] : boards.slice(0, 1);
      boards = pick.length ? pick : boards;
    }
    if (!boards.length) {
      boards = [await require("./canvas.js").ensureMaster(doc)];
    }

    const report = [];
    for (const board of boards) {
      const preset = resolvePresetForBoard(board, fallbackId);
      const rect = await ps.getArtboardRect(board);
      const boxes = absoluteBoxes(rect, preset, density);
      const bg = await sampleBackground(doc, boxes.hook);
      const ink = fit.pickTextColor(bg);

      const specs = [
        { key: "hook", name: naming.TXT.hook, text: slots.hook, box: boxes.hook, scale: preset.type.hook },
        { key: "proof", name: naming.TXT.proof, text: slots.proof, box: boxes.proof, scale: preset.type.proof },
        { key: "cta", name: naming.TXT.cta, text: slots.cta, box: boxes.cta, scale: preset.type.cta }
      ];

      const item = { artboard: board.name, overflow: false, slots: {} };
      for (const spec of specs) {
        if (!spec.text) continue;
        const fitted = fit.fitFontSize({
          text: spec.text,
          maxWidth: spec.box.width,
          maxHeight: spec.box.height,
          maxPt: spec.scale.maxPt,
          minPt: spec.scale.minPt,
          maxLines: spec.scale.maxLines,
          density
        });
        let layer = findInBoard(board, spec.name);
        if (!layer) {
          const found = ps.findLayerByName(doc, spec.name);
          if (found && layerBelongsTo(found, board)) layer = found;
        }
        if (!layer) {
          layer = await text.makeTextBox({
            name: spec.name,
            text: spec.text,
            box: spec.box,
            size: fitted.size,
            rgb: ink.rgb
          });
          await ps.moveInto(layer, board);
        } else {
          await text.setTextContents(layer, spec.text, fitted.size, ink.rgb);
        }
        item.slots[spec.key] = { size: fitted.size, overflow: fitted.overflow };
        if (fitted.overflow) item.overflow = true;
      }

      if (options.scrim && ink.scrim) {
        await ensureScrim(doc, board, boxes.safe);
      }
      report.push(item);
    }
    return { slots, report };
  });
}

async function ensureScrim(doc, board, box) {
  if (findInBoard(board, naming.SCRIM)) return;
  await ps.batchPlay([
    {
      _obj: "make",
      _target: [{ _ref: "contentLayer" }],
      using: {
        _obj: "contentLayer",
        name: naming.SCRIM,
        type: {
          _obj: "solidColorLayer",
          color: { _obj: "RGBColor", red: 0, green: 0, blue: 0 }
        },
        shape: {
          _obj: "rectangle",
          unitValueQuadVersion: 1,
          top: { _unit: "pixelsUnit", _value: box.top },
          left: { _unit: "pixelsUnit", _value: box.left },
          bottom: { _unit: "pixelsUnit", _value: box.bottom },
          right: { _unit: "pixelsUnit", _value: box.right }
        }
      },
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
  const layer = doc.activeLayers && doc.activeLayers[0];
  if (layer) {
    layer.name = naming.SCRIM;
    layer.opacity = 40;
    await ps.moveInto(layer, board);
  }
}

if (typeof module !== "undefined") {
  module.exports = { applyType, findInBoard };
}
