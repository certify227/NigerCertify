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
  const b = layer.bounds || layer.boundsNoEffects || {};
  return {
    left: unwrap(b.left),
    top: unwrap(b.top),
    right: unwrap(b.right),
    bottom: unwrap(b.bottom),
    width: unwrap(b.right) - unwrap(b.left),
    height: unwrap(b.bottom) - unwrap(b.top)
  };
}

async function batchPlay(commands) {
  const { action } = photoshop();
  return action.batchPlay(commands, {});
}

async function execute(commandName, fn) {
  const { core, app } = photoshop();
  return core.executeAsModal(
    async (executionContext) => {
      const doc = app.activeDocument;
      if (doc && typeof doc.suspendHistory === "function") {
        let result;
        await doc.suspendHistory(async () => {
          result = await fn(executionContext, doc);
        }, commandName);
        return result;
      }
      return fn(executionContext, doc);
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

function walkLayers(layers, acc) {
  const out = acc || [];
  if (!layers) return out;
  for (const layer of layers) {
    out.push(layer);
    if (layer.layers && layer.layers.length) walkLayers(layer.layers, out);
  }
  return out;
}

function allLayers(doc) {
  return walkLayers(doc.layers, []);
}

function findLayerByName(doc, name) {
  return allLayers(doc).find((l) => l.name === name) || null;
}

function findLayersByPrefix(doc, prefix) {
  return allLayers(doc).filter((l) => (l.name || "").startsWith(prefix));
}

async function selectLayer(layer, exclusive) {
  await batchPlay([
    {
      _obj: "select",
      _target: [{ _ref: "layer", _id: layer.id }],
      makeVisible: false,
      layerID: [layer.id],
      selectionModifier: exclusive
        ? { _enum: "selectionModifierType", _value: "addToSelectionContinuous" }
        : { _enum: "selectionModifierType", _value: "addToSelection" },
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
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

function isArtboard(layer) {
  if (!layer) return false;
  if (layer.isArtboard) return true;
  const kind = String(layer.kind || layer.layerKind || "");
  return /artboard/i.test(kind);
}

function artboardsOf(doc) {
  if (doc.artboards && doc.artboards.length) {
    return Array.from(doc.artboards);
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
  const cmds = [
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
  ];
  await batchPlay(cmds);
}

async function scaleSelected(percent, anchor) {
  const center = anchor || "QCSAverage";
  await batchPlay([
    {
      _obj: "transform",
      freeTransformCenterState: { _enum: "quadCenterState", _value: center },
      offset: {
        _obj: "offset",
        horizontal: { _unit: "pixelsUnit", _value: 0 },
        vertical: { _unit: "pixelsUnit", _value: 0 }
      },
      width: { _unit: "percentUnit", _value: percent },
      height: { _unit: "percentUnit", _value: percent },
      linked: true,
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
}

async function translateSelected(dx, dy) {
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

function errorMessage(err) {
  if (!err) return "Erreur inconnue";
  if (typeof err === "string") return err;
  return err.message || String(err);
}

if (typeof module !== "undefined") {
  module.exports = {
    photoshop,
    uxp,
    unwrap,
    boundsOf,
    batchPlay,
    execute,
    requireDoc,
    ensureDocument,
    walkLayers,
    allLayers,
    findLayerByName,
    findLayersByPrefix,
    selectLayer,
    selectOnly,
    isArtboard,
    artboardsOf,
    getArtboardRect,
    setArtboardRect,
    convertBackground,
    makeArtboardFromLayers,
    scaleSelected,
    translateSelected,
    errorMessage
  };
}
