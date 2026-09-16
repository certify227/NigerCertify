const naming = require("../core/naming.js");
const crop = require("../core/crop.js");
const ps = require("../core/ps.js");
const { getPreset } = require("../data/presets.js");

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
  const tops = ps.listOf(doc.layers);
  if (!tops.length) {
    throw new Error("Le document n’a aucun calque à convertir en CP_MASTER.");
  }
  const box = { left: 0, top: 0, right: doc.width, bottom: doc.height };
  await ps.selectLayers(tops);
  try {
    await ps.makeArtboardFromLayers(naming.MASTER, box);
  } catch (_) {
    try {
      const group = await doc.groupLayers(tops);
      group.name = naming.MASTER;
    } catch (err) {
      throw new Error(
        "Impossible de créer CP_MASTER. Convertis le document en artboards (Fichier > Nouveau à partir de calque) puis réessaie."
      );
    }
  }
  master = ps.findLayerByName(doc, naming.MASTER) || ps.artboardsOf(doc)[0];
  if (!master) {
    throw new Error("CP_MASTER introuvable après conversion.");
  }
  master.name = naming.MASTER;
  return master;
}

async function detectSubject(doc) {
  const attempts = [
    { _obj: "selectSubject", sampleAllLayers: true, _options: { dialogOptions: "dontDisplay" } },
    { _obj: "selectSubject", version: 2, sampleAllLayers: true, _options: { dialogOptions: "dontDisplay" } },
    { _obj: "autoCutout", sampleAllLayers: true, _options: { dialogOptions: "dontDisplay" } }
  ];
  let selected = false;
  for (const cmd of attempts) {
    try {
      await ps.batchPlay([cmd]);
      selected = true;
      break;
    } catch (_) {
      /* next descriptor */
    }
  }
  if (!selected) {
    throw new Error("Select Subject a échoué. Sélectionne le sujet à la main, puis relance.");
  }
  await ps.batchPlay([
    {
      _obj: "copyToLayer",
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
  const layer = doc.activeLayers && doc.activeLayers[0];
  if (!layer) {
    throw new Error("Aucun calque sujet créé.");
  }
  layer.name = naming.SUBJECT;
  const master = ps.findLayerByName(doc, naming.MASTER);
  if (master) await ps.moveInto(layer, master);
  return layer;
}

function relativeSubject(doc, masterBox) {
  const subjectLayer =
    ps.findLayerByName(doc, naming.SUBJECT) || ps.findLayerByName(doc, naming.FACE);
  if (!subjectLayer || !masterBox) return null;
  const b = ps.boundsOf(subjectLayer);
  return {
    left: b.left - masterBox.left,
    top: b.top - masterBox.top,
    right: b.right - masterBox.left,
    bottom: b.bottom - masterBox.top,
    width: b.width,
    height: b.height
  };
}

function nextSlot(doc, masterBox) {
  const boards = ps.artboardsOf(doc);
  let maxRight = masterBox.right;
  for (const board of boards) {
    const bb = ps.boundsOf(board);
    if (bb.right > maxRight) maxRight = bb.right;
  }
  return { x: maxRight + 80, y: 0 };
}

async function wrapAsArtboard(doc, layers, name, box) {
  await ps.selectLayers(layers);
  try {
    await ps.makeArtboardFromLayers(name, box);
    const ab = ps.findLayerByName(doc, name);
    if (ab) return ab;
  } catch (_) {
    /* group fallback */
  }
  try {
    const group = await doc.groupLayers(layers);
    group.name = name;
    try {
      await ps.setArtboardRect(group, box);
    } catch (__) {
      /* group named is better than nothing */
    }
    return group;
  } catch (err) {
    if (layers[0]) layers[0].name = name;
    return layers[0] || null;
  }
}

async function buildVariant(origin, masterBox, preset, transform, originId) {
  let temp;
  try {
    temp = await origin.duplicate(`_CP_TMP_${preset.id}`);
    const sameCanvas =
      Math.abs(masterBox.left) < 1 &&
      Math.abs(masterBox.top) < 1 &&
      Math.abs(masterBox.width - temp.width) < 2 &&
      Math.abs(masterBox.height - temp.height) < 2;
    if (!sameCanvas) {
      await ps.cropDoc(temp, masterBox);
    }
    const sw = Math.round(transform.scaledW);
    const sh = Math.round(transform.scaledH);
    await ps.resizeImage(temp, sw, sh);
    if (transform.mode === "letterbox" || transform.needsExpand) {
      await ps.resizeCanvas(temp, preset.width, preset.height);
    } else {
      const c = transform.crop;
      const left = Math.max(0, Math.min(c.left, Math.max(0, temp.width - preset.width)));
      const top = Math.max(0, Math.min(c.top, Math.max(0, temp.height - preset.height)));
      await ps.cropDoc(temp, {
        left,
        top,
        right: left + preset.width,
        bottom: top + preset.height
      });
    }
    const payload = ps
      .listOf(temp.layers)
      .filter((l) => !naming.exportSkip(l.name) && !(l.name || "").startsWith("_CP_TMP_"));
    if (!payload.length) {
      throw new Error(`Aucune couche à transférer pour ${preset.id}.`);
    }
    await temp.duplicateLayers(payload, origin);
  } finally {
    await ps.closeTemp(temp, originId);
  }
}

async function applyCanvas(options) {
  const { presetIds, cropMode, showSafezone, replace, onProgress } = options;
  if (!presetIds || !presetIds.length) throw new Error("Coche au moins un format.");

  return ps.execute("Creator Pack — Social Canvas", async (ctx, doc) => {
    const master = await ensureMaster(doc);
    const masterBox = await ps.getArtboardRect(master);
    const subject = relativeSubject(doc, masterBox);
    const src = {
      width: masterBox.width || doc.width,
      height: masterBox.height || doc.height
    };
    const originId = doc.id;
    const created = [];
    const replaced = [];
    const skipped = [];
    let slot = nextSlot(doc, masterBox);

    for (let i = 0; i < presetIds.length; i++) {
      const id = presetIds[i];
      const preset = getPreset(id);
      if (!preset) throw new Error(`Preset inconnu: ${id}`);
      const name = naming.artboardName(id);
      ps.reportProgress(ctx, (i + 0.15) / presetIds.length, "Creator Pack — Social Canvas");
      if (typeof onProgress === "function") onProgress(id, i, presetIds.length);

      const existing = ps.findLayerByName(doc, name);
      let dest = { x: slot.x, y: slot.y };
      if (existing) {
        if (!replace) {
          skipped.push(name);
          continue;
        }
        const old = await ps.getArtboardRect(existing);
        dest = { x: old.left, y: old.top };
        await ps.deleteLayer(existing);
        replaced.push(name);
      }

      const transform = crop.computeCoverTransform(src, preset, subject, cropMode);
      transform.mode = cropMode || "subject";

      const before = ps.snapshotIds(doc);
      await buildVariant(doc, masterBox, preset, transform, originId);
      const added = ps.listOf(doc.layers).filter((l) => !before.has(l.id));
      if (!added.length) {
        throw new Error(`Échec du transfert ${name}.`);
      }

      await ps.translateLayers(added, dest.x, dest.y);
      const box = {
        left: dest.x,
        top: dest.y,
        right: dest.x + preset.width,
        bottom: dest.y + preset.height
      };
      let board;
      if (added.length === 1 && (ps.isArtboard(added[0]) || added[0].name === naming.MASTER)) {
        board = added[0];
        board.name = name;
        try {
          await ps.setArtboardRect(board, box);
        } catch (_) {
          /* keep translated copy */
        }
      } else {
        board = await wrapAsArtboard(doc, added, name, box);
      }
      if (showSafezone && board) {
        await drawSafezone(doc, board, preset, box);
      }
      created.push(name);
      if (!existing) slot.x += preset.width + 80;
    }

    return { created, replaced, skipped, master: naming.MASTER };
  });
}

async function drawSafezone(doc, board, preset, target) {
  const box = crop.safeRect(preset);
  const base = naming.safezoneName(preset.id);
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
          name: i === 0 ? base : `${base}_${i}`,
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
    const created = doc.activeLayers && doc.activeLayers[0];
    if (created) {
      created.opacity = 28;
      await ps.moveInto(created, board);
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
  module.exports = { ensureMaster, detectSubject, applyCanvas, toggleSafezones, relativeSubject };
}
