const naming = require("../core/naming.js");
const crop = require("../core/crop.js");
const fit = require("../core/fit.js");
const copy = require("../core/copy.js");
const ps = require("../core/ps.js");
const { getPreset } = require("../data/presets.js");
const { artboardsOf, getArtboardRect, findLayerByName } = ps;

function slotNames() {
  return [naming.TXT.hook, naming.TXT.proof, naming.TXT.cta];
}

async function makeTextBox(opts) {
  const { name, text, box, size, rgb, align } = opts;
  const color = rgb || [255, 255, 255];
  const alignment = align || "center";
  await ps.batchPlay([
    {
      _obj: "make",
      _target: [{ _ref: "textLayer" }],
      using: {
        _obj: "textLayer",
        textKey: text,
        textShape: [
          {
            _obj: "textShape",
            char: { _enum: "char", _value: "box" },
            bounds: {
              _obj: "rectangle",
              top: box.top,
              left: box.left,
              bottom: box.bottom,
              right: box.right
            }
          }
        ],
        textStyleRange: [
          {
            _obj: "textStyleRange",
            from: 0,
            to: String(text).length,
            textStyle: {
              _obj: "textStyle",
              fontName: "Myriad Pro",
              fontStyleName: "Bold",
              fontPostScriptName: "MyriadPro-Bold",
              size: { _unit: "pointsUnit", _value: size },
              color: {
                _obj: "RGBColor",
                red: color[0],
                green: color[1],
                blue: color[2]
              }
            }
          }
        ],
        paragraphStyleRange: [
          {
            _obj: "paragraphStyleRange",
            from: 0,
            to: String(text).length,
            paragraphStyle: {
              _obj: "paragraphStyle",
              align: { _enum: "alignmentType", _value: alignment },
              hyphenate: true
            }
          }
        ]
      },
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
  const { app } = ps.photoshop();
  const layer = app.activeDocument.activeLayers[0];
  if (layer) layer.name = name;
  return layer;
}

async function setTextContents(layer, text, size, rgb) {
  const color = rgb || [255, 255, 255];
  try {
    if (layer.textItem) {
      layer.textItem.contents = text;
      if (layer.textItem.characterStyle) {
        layer.textItem.characterStyle.size = size;
      }
      return;
    }
  } catch (_) {
    /* batchPlay fallback */
  }
  await ps.selectOnly(layer);
  await ps.batchPlay([
    {
      _obj: "set",
      _target: [{ _ref: "textLayer", _id: layer.id }],
      to: {
        _obj: "textLayer",
        textKey: text,
        textStyleRange: [
          {
            _obj: "textStyleRange",
            from: 0,
            to: String(text).length,
            textStyle: {
              _obj: "textStyle",
              size: { _unit: "pointsUnit", _value: size },
              color: {
                _obj: "RGBColor",
                red: color[0],
                green: color[1],
                blue: color[2]
              }
            }
          }
        ]
      },
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
}

function resolvePresetForBoard(board, fallbackId) {
  const name = board && board.name;
  if (name && name.startsWith("CP_AB_")) {
    return getPreset(name.replace("CP_AB_", "")) || getPreset(fallbackId);
  }
  if (name && name.startsWith("CP_FR_")) {
    return getPreset(fallbackId) || getPreset("ig_feed_45");
  }
  if (name === naming.MASTER) {
    return getPreset(fallbackId) || getPreset("ig_feed_45");
  }
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
  const slotsIn = copy.applyTemplate(
    {
      hook: options.hook,
      proof: options.proof,
      cta: options.cta
    },
    options.templateId || "hook_proof_cta"
  );
  const variants = copy.hookVariants(slotsIn.hook);
  const hook = variants[options.variantIndex || 0] || slotsIn.hook;
  const slots = { ...slotsIn, hook };
  const density = options.density || "normal";
  const fallbackId = options.fallbackPresetId || "ig_feed_45";

  return ps.execute("Creator Pack — Type Rhythm", async (_ctx, doc) => {
    let boards = artboardsOf(doc).filter((b) => naming.isArtboardName(b.name));
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
      const rect = await getArtboardRect(board);
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
        let layer = findInBoard(board, spec.name) || findLayerByName(doc, spec.name);
        if (layer && options.scope !== "active" && !layerBelongsTo(layer, board)) {
          layer = findInBoard(board, spec.name);
        }
        if (!layer) {
          layer = await makeTextBox({
            name: spec.name,
            text: spec.text,
            box: spec.box,
            size: fitted.size,
            rgb: ink.rgb
          });
          try {
            if (layer && typeof layer.move === "function") {
              await layer.move(board, "inside");
            }
          } catch (_) {
            /* keep */
          }
        } else {
          await setTextContents(layer, spec.text, fitted.size, ink.rgb);
        }
        item.slots[spec.key] = { size: fitted.size, overflow: fitted.overflow };
        if (fitted.overflow) item.overflow = true;
      }

      if (options.scrim && ink.scrim) {
        await ensureScrim(doc, board, boxes.safe);
      }
      report.push(item);
    }
    return { slots, variants, report };
  });
}

function findInBoard(board, name) {
  if (!board.layers) return null;
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

async function ensureScrim(doc, board, box) {
  const name = "CP_SCRIM";
  if (findInBoard(board, name)) return;
  await ps.batchPlay([
    {
      _obj: "make",
      _target: [{ _ref: "contentLayer" }],
      using: {
        _obj: "contentLayer",
        name,
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
    layer.name = name;
    layer.opacity = 40;
    try {
      await layer.move(board, "inside");
    } catch (_) {
      /* ignore */
    }
  }
}

if (typeof module !== "undefined") {
  module.exports = { applyType, slotNames, makeTextBox };
}
