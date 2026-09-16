class UserCancel extends Error {
  constructor(message) {
    super(message || "Annulé");
    this.name = "UserCancel";
    this.cancelled = true;
  }
}

function photoshop() {
  return require("photoshop");
}

function uxp() {
  return require("uxp");
}

function unwrap(v) {
  if (v == null) return 0;
  if (typeof v === "number") return v;
  if (typeof v === "object" && typeof v._value === "number") return v._value;
  return Number(v) || 0;
}

function boundsOf(layer) {
  const b = (layer && (layer.boundsNoEffects || layer.bounds)) || {};
  return {
    left: unwrap(b.left),
    top: unwrap(b.top),
    right: unwrap(b.right),
    bottom: unwrap(b.bottom),
    width: unwrap(b.right) - unwrap(b.left),
    height: unwrap(b.bottom) - unwrap(b.top)
  };
}

function throwIfBatchError(result) {
  if (!result) return result;
  const list = Array.isArray(result) ? result : [result];
  const err = list.find((item) => item && (item._obj === "error" || item.result < 0));
  if (err) {
    const msg = err.message || err.localizedMessage || `Commande Photoshop refusée (${err.result})`;
    throw new Error(msg);
  }
  return result;
}

async function batchPlay(commands) {
  const { action } = photoshop();
  const result = await action.batchPlay(commands, {});
  return throwIfBatchError(result);
}

async function execute(commandName, fn) {
  const { core, app } = photoshop();
  return core.executeAsModal(
    async (executionContext) => {
      const doc = app.activeDocument;
      if (!doc) {
        throw new Error("Aucun document actif. Ouvre un PSD ou crée un visuel d’abord.");
      }
      let suspension;
      try {
        if (executionContext.hostControl && executionContext.hostControl.suspendHistory) {
          suspension = await executionContext.hostControl.suspendHistory({
            documentID: doc.id,
            name: commandName
          });
        }
        return await fn(executionContext, doc);
      } finally {
        if (suspension && executionContext.hostControl && executionContext.hostControl.resumeHistory) {
          try {
            await executionContext.hostControl.resumeHistory(suspension);
          } catch (_) {
            /* déjà repris */
          }
        }
      }
    },
    { commandName }
  );
}

function requireDoc() {
  const { app } = photoshop();
  if (!app.activeDocument) {
    throw new Error("Aucun document actif. Ouvre un PSD ou crée un visuel d’abord.");
  }
  return app.activeDocument;
}

function findDocument(id) {
  const { app } = photoshop();
  return Array.from(app.documents).find((d) => d.id === id) || null;
}

async function activate(doc) {
  const { app } = photoshop();
  if (doc && app.activeDocument !== doc) {
    app.activeDocument = doc;
  }
}

async function ensureDocument() {
  const { app, core, constants } = photoshop();
  if (app.activeDocument) return app.activeDocument;
  return core.executeAsModal(
    async () => {
      const opts = {
        width: 1080,
        height: 1350,
        resolution: 72,
        name: "Creator Pack"
      };
      try {
        opts.mode = constants.NewDocumentMode.RGB;
        opts.fill = constants.DocumentFill.WHITE;
      } catch (_) {
        opts.mode = "RGBColorMode";
        opts.fill = "white";
      }
      return app.documents.add(opts);
    },
    { commandName: "Creator Pack — Nouveau document" }
  );
}

function listOf(layers) {
  if (!layers) return [];
  try {
    return Array.from(layers);
  } catch (_) {
    return [];
  }
}

function walkLayers(layers, acc) {
  const out = acc || [];
  for (const layer of listOf(layers)) {
    out.push(layer);
    try {
      if (layer.layers && layer.layers.length) walkLayers(layer.layers, out);
    } catch (_) {
      /* pixel / text */
    }
  }
  return out;
}

function allLayers(doc) {
  return walkLayers(doc.layers, []);
}

function findLayerByName(doc, name) {
  return allLayers(doc).find((l) => l.name === name) || null;
}

function snapshotIds(doc) {
  return new Set(allLayers(doc).map((l) => l.id));
}

function addedLayers(doc, beforeIds) {
  return allLayers(doc).filter((l) => !beforeIds.has(l.id));
}

async function selectOnly(layer) {
  await batchPlay([
    {
      _obj: "select",
      _target: [{ _ref: "layer", _id: layer.id }],
      makeVisible: false,
      layerID: [layer.id],
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
}

async function addToSelection(layer) {
  await batchPlay([
    {
      _obj: "select",
      _target: [{ _ref: "layer", _id: layer.id }],
      selectionModifier: { _enum: "selectionModifierType", _value: "addToSelection" },
      makeVisible: false,
      layerID: [layer.id],
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
}

async function selectLayers(layers) {
  const list = listOf(layers).filter(Boolean);
  if (!list.length) return;
  await selectOnly(list[0]);
  for (let i = 1; i < list.length; i++) {
    await addToSelection(list[i]);
  }
}

function isArtboard(layer) {
  if (!layer) return false;
  if (layer.isArtboard) return true;
  const kind = String(layer.kind || layer.layerKind || "");
  return /artboard/i.test(kind);
}

function artboardsOf(doc) {
  try {
    if (doc.artboards && doc.artboards.length) {
      return listOf(doc.artboards);
    }
  } catch (_) {
    /* fallback */
  }
  return allLayers(doc).filter(isArtboard);
}

async function getArtboardRect(layer) {
  try {
    const result = await batchPlay([
      {
        _obj: "get",
        _target: [{ _ref: "layer", _id: layer.id }]
      }
    ]);
    const desc = result && result[0];
    const ab = desc && (desc.artboard || desc.artboardSection);
    const r = ab && (ab.artboardRect || ab);
    if (r && (r.left != null || r.right != null)) {
      return {
        left: unwrap(r.left),
        top: unwrap(r.top),
        right: unwrap(r.right),
        bottom: unwrap(r.bottom),
        width: unwrap(r.right) - unwrap(r.left),
        height: unwrap(r.bottom) - unwrap(r.top)
      };
    }
  } catch (_) {
    /* fallback bounds */
  }
  return boundsOf(layer);
}

async function setArtboardRect(layer, box) {
  await batchPlay([
    {
      _obj: "set",
      _target: [{ _ref: "layer", _id: layer.id }],
      to: {
        _obj: "artboard",
        artboardRect: {
          _obj: "classFloatRect",
          top: box.top,
          left: box.left,
          bottom: box.bottom,
          right: box.right
        }
      },
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
}

async function convertBackground(doc) {
  const bg = doc.backgroundLayer;
  if (!bg) return;
  await selectOnly(bg);
  await batchPlay([
    {
      _obj: "set",
      _target: [{ _ref: "layer", _property: "background" }],
      to: {
        _obj: "layer",
        opacity: { _unit: "percentUnit", _value: 100 }
      },
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
}

async function makeArtboardFromLayers(name, box) {
  await batchPlay([
    {
      _obj: "make",
      _target: [{ _ref: "artboardSection" }],
      using: {
        _obj: "artboardSection",
        name
      },
      name,
      artboard: {
        _obj: "artboard",
        artboardRect: {
          _obj: "classFloatRect",
          top: box.top,
          left: box.left,
          bottom: box.bottom,
          right: box.right
        }
      },
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
}

async function translateSelected(dx, dy) {
  if (Math.abs(dx) < 0.5 && Math.abs(dy) < 0.5) return;
  await batchPlay([
    {
      _obj: "move",
      _target: [{ _ref: "layer", _enum: "ordinal", _value: "targetEnum" }],
      to: {
        _obj: "offset",
        horizontal: { _unit: "pixelsUnit", _value: dx },
        vertical: { _unit: "pixelsUnit", _value: dy }
      },
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
}

async function translateLayers(layers, dx, dy) {
  const list = listOf(layers);
  if (!list.length) return;
  await selectLayers(list);
  await translateSelected(dx, dy);
}

async function cropDoc(doc, box) {
  const bounds = {
    left: Math.round(box.left),
    top: Math.round(box.top),
    right: Math.round(box.right),
    bottom: Math.round(box.bottom)
  };
  if (bounds.right <= bounds.left || bounds.bottom <= bounds.top) {
    throw new Error("Zone de recadrage invalide.");
  }
  try {
    await doc.crop(bounds);
  } catch (_) {
    await doc.crop([bounds.left, bounds.top, bounds.right, bounds.bottom]);
  }
}

function resampleMethod() {
  try {
    return photoshop().constants.ResampleMethod.BICUBICAUTOMATIC;
  } catch (_) {
    return "bicubicAutomatic";
  }
}

function anchorMiddle() {
  try {
    return photoshop().constants.AnchorPosition.MIDDLECENTER;
  } catch (_) {
    return "MIDDLECENTER";
  }
}

function placementInside() {
  try {
    return photoshop().constants.ElementPlacement.PLACEINSIDE;
  } catch (_) {
    return "placeInside";
  }
}

async function resizeImage(doc, width, height) {
  try {
    await doc.resizeImage(width, height, doc.resolution, resampleMethod());
  } catch (_) {
    await doc.resizeImage(width, height);
  }
}

async function resizeCanvas(doc, width, height) {
  try {
    await doc.resizeCanvas(width, height, anchorMiddle());
  } catch (_) {
    await doc.resizeCanvas(width, height);
  }
}

async function deleteLayer(layer) {
  if (!layer) return;
  try {
    if (typeof layer.delete === "function") {
      await layer.delete();
      return;
    }
  } catch (_) {
    /* batchPlay */
  }
  await selectOnly(layer);
  await batchPlay([
    {
      _obj: "delete",
      _target: [{ _ref: "layer", _enum: "ordinal", _value: "targetEnum" }],
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
}

async function moveInto(layer, parent) {
  if (!layer || !parent) return false;
  try {
    if (typeof layer.move === "function") {
      await layer.move(parent, placementInside());
      return true;
    }
  } catch (_) {
    /* ignore */
  }
  return false;
}

async function closeTemp(temp, originId) {
  if (!temp) return;
  try {
    temp.closeWithoutSaving();
  } catch (_) {
    try {
      await temp.closeWithoutSaving();
    } catch (__) {
      /* already closed */
    }
  }
  const origin = findDocument(originId);
  if (origin) await activate(origin);
}

function reportProgress(ctx, value, commandName) {
  try {
    if (ctx && typeof ctx.reportProgress === "function") {
      ctx.reportProgress({ value, commandName });
    }
  } catch (_) {
    /* optional */
  }
}

function errorMessage(err) {
  if (!err) return "Erreur inconnue";
  if (err.cancelled) return "Annulé.";
  if (typeof err === "string") return err;
  return err.message || String(err);
}

if (typeof module !== "undefined") {
  module.exports = {
    UserCancel,
    photoshop,
    uxp,
    unwrap,
    boundsOf,
    batchPlay,
    execute,
    requireDoc,
    findDocument,
    activate,
    ensureDocument,
    listOf,
    walkLayers,
    allLayers,
    findLayerByName,
    snapshotIds,
    addedLayers,
    selectOnly,
    addToSelection,
    selectLayers,
    isArtboard,
    artboardsOf,
    getArtboardRect,
    setArtboardRect,
    convertBackground,
    makeArtboardFromLayers,
    translateSelected,
    translateLayers,
    cropDoc,
    resizeImage,
    resizeCanvas,
    deleteLayer,
    moveInto,
    closeTemp,
    reportProgress,
    errorMessage
  };
}
