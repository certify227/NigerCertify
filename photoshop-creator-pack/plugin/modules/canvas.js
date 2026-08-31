const naming = require("../core/naming.js");
const crop = require("../core/crop.js");
const ps = require("../core/ps.js");

async function ensureMaster(doc) {
  let master = ps.findLayerByName(doc, naming.MASTER);
  if (master) return master;

  const existing = ps.artboardsOf(doc);
  if (existing.length) {
    const active = (doc.activeLayers && doc.activeLayers[0]) || existing[0];
    const pick = ps.isArtboard(active) ? active : existing[0];
    pick.name = naming.MASTER;
    return pick;
  }

  await ps.convertBackground(doc);
  const box = { left: 0, top: 0, right: doc.width, bottom: doc.height };
  try {
    await ps.batchPlay([
      {
        _obj: "selectAllLayers",
        _options: { dialogOptions: "dontDisplay" }
      }
    ]);
  } catch (_) {
    const tops = Array.from(doc.layers || []);
    if (tops[0]) await ps.selectOnly(tops[0]);
  }
  await ps.makeArtboardFromLayers(naming.MASTER, box);
  master = ps.findLayerByName(doc, naming.MASTER) || ps.artboardsOf(doc)[0];
  if (!master) {
    throw new Error("Impossible de créer l’artboard CP_MASTER. Passe le document en artboards (Fichier > Nouveau > Artboard) puis réessaie.");
  }
  master.name = naming.MASTER;
  return master;
}

async function detectSubject(doc) {
  await ps.batchPlay([
    {
      _obj: "selectSubject",
      sampleAllLayers: true,
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
  await ps.batchPlay([
    {
      _obj: "copyToLayer",
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
  const layer = doc.activeLayers && doc.activeLayers[0];
  if (layer) layer.name = naming.SUBJECT;
  return layer;
}

function nextOffsetX(doc, masterBox) {
  const boards = ps.artboardsOf(doc);
  let maxRight = masterBox.right;
  for (const b of boards) {
    const bb = ps.boundsOf(b);
    if (bb.right > maxRight) maxRight = bb.right;
  }
  return maxRight + 80;
}

async function applyCanvas(options) {
  const { presetIds, cropMode, showSafezone } = options;
  if (!presetIds.length) throw new Error("Coche au moins un format.");

  return ps.execute("Creator Pack — Social Canvas", async (_ctx, doc) => {
    const master = await ensureMaster(doc);
    const masterBox = await ps.getArtboardRect(master);
    const subjectLayer =
      ps.findLayerByName(doc, naming.SUBJECT) || ps.findLayerByName(doc, naming.FACE);
    const subject = subjectLayer ? ps.boundsOf(subjectLayer) : null;
    if (subject && masterBox) {
      subject.left -= masterBox.left;
      subject.top -= masterBox.top;
      subject.right -= masterBox.left;
      subject.bottom -= masterBox.top;
      subject.width = subject.right - subject.left;
      subject.height = subject.bottom - subject.top;
    }

    const src = {
      width: masterBox.width || doc.width,
      height: masterBox.height || doc.height,
      left: 0,
      top: 0,
      right: masterBox.width || doc.width,
      bottom: masterBox.height || doc.height
    };

    let cursorX = nextOffsetX(doc, masterBox);
    const created = [];
    const skipped = [];

    for (const id of presetIds) {
      const preset = require("../data/presets.js").getPreset(id);
      const name = naming.artboardName(id);
      const existing = ps.findLayerByName(doc, name);
      if (existing) {
        skipped.push(name);
        continue;
      }

      const transform = crop.computeCoverTransform(src, preset, subject, cropMode);
      const copies = await doc.duplicateLayers([master]);
      const board = copies[0];
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

      await ps.selectOnly(board);
      if (Math.abs(transform.scalePercent - 100) > 0.4) {
        await ps.scaleSelected(transform.scalePercent, "QCSAverage");
      }

      const placed = await ps.getArtboardRect(board);
      const target = {
        left: cursorX,
        top: 0,
        right: cursorX + preset.width,
        bottom: preset.height
      };
      await ps.setArtboardRect(board, target);

      const extraX = transform.tx - (placed.left - cursorX);
      const extraY = transform.ty - (placed.top - 0);
      if (Math.abs(extraX) > 1 || Math.abs(extraY) > 1) {
        await ps.selectOnly(board);
        await ps.translateSelected(extraX, extraY);
        await ps.setArtboardRect(board, target);
      }

      if (showSafezone) {
        await drawSafezone(doc, board, preset, target);
      }

      created.push(name);
      cursorX += preset.width + 80;
    }

    return { created, skipped, master: naming.MASTER };
  });
}

async function drawSafezone(doc, board, preset, target) {
  const box = crop.safeRect(preset);
  const name = naming.safezoneName(preset.id);
  if (ps.findLayerByName(doc, name)) return;
  const left = target.left;
  const top = target.top;
  const w = preset.width;
  const h = preset.height;
  const bands = [
    { l: left, t: top, r: left + w, b: top + box.top },
    { l: left, t: top + box.bottom, r: left + w, b: top + h },
    { l: left, t: top + box.top, r: left + box.left, b: top + box.bottom },
    { l: left + box.right, t: top + box.top, r: left + w, b: top + box.bottom }
  ];
  for (let i = 0; i < bands.length; i++) {
    const b = bands[i];
    if (b.b - b.t < 2 || b.r - b.l < 2) continue;
    await ps.batchPlay([
      {
        _obj: "make",
        _target: [{ _ref: "contentLayer" }],
        using: {
          _obj: "contentLayer",
          name: i === 0 ? name : `${name}_${i}`,
          type: {
            _obj: "solidColorLayer",
            color: { _obj: "RGBColor", red: 255, green: 60, blue: 80 }
          },
          shape: {
            _obj: "rectangle",
            unitValueQuadVersion: 1,
            top: { _unit: "pixelsUnit", _value: b.t },
            left: { _unit: "pixelsUnit", _value: b.l },
            bottom: { _unit: "pixelsUnit", _value: b.b },
            right: { _unit: "pixelsUnit", _value: b.r }
          }
        },
        _options: { dialogOptions: "dontDisplay" }
      }
    ]);
  }
  const created = ps.findLayerByName(doc, name);
  if (created) {
    created.opacity = 35;
    try {
      if (typeof created.move === "function") {
        await created.move(board, "inside");
      }
    } catch (_) {
      /* overlay stays top-level */
    }
  }
}

async function toggleSafezones(visible) {
  return ps.execute("Creator Pack — Safe zones", async (_ctx, doc) => {
    const layers = ps.allLayers(doc).filter((l) => (l.name || "").startsWith("CP_SAFEZONE_"));
    for (const layer of layers) layer.visible = visible;
    return { count: layers.length, visible };
  });
}

if (typeof module !== "undefined") {
  module.exports = { ensureMaster, detectSubject, applyCanvas, toggleSafezones };
}
