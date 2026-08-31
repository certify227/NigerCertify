const naming = require("../core/naming.js");
const plan = require("../core/plan.js");
const ps = require("../core/ps.js");

async function pickFolder() {
  const fs = ps.uxp().storage.localFileSystem;
  const folder = await fs.getFolder();
  if (!folder) throw new Error("Aucun dossier choisi.");
  return folder;
}

async function exportPack(options) {
  const folder = await pickFolder();
  const includeNotes = Boolean(options.includeNotes);
  const meta = {
    document: "",
    canvas: { targets: options.presetIds || [] },
    type: options.type || {},
    story: options.story || {},
    files: []
  };

  await ps.execute("Creator Pack — Export", async (_ctx, doc) => {
    meta.document = doc.title || doc.name || "";
    const boards = ps.artboardsOf(doc).filter((b) => naming.isArtboardName(b.name));
    const targets = boards.length ? boards : [null];

    const hidden = [];
    if (!includeNotes) {
      for (const layer of ps.allLayers(doc)) {
        if (naming.exportSkip(layer.name) && layer.visible) {
          layer.visible = false;
          hidden.push(layer);
        }
      }
    }

    try {
      if (boards.length) {
        await exportViaQuickExport(folder, doc);
        for (const board of boards) {
          meta.files.push(`${board.name}.png`);
        }
      } else {
        const file = await folder.createFile("CP_MASTER.png", { overwrite: true });
        await doc.saveAs.png(file, { compression: 6 }, true);
        meta.files.push("CP_MASTER.png");
      }
    } catch (err) {
      await exportByDuplicate(folder, doc, targets, meta);
      if (!meta.files.length) throw err;
    }

    hidden.forEach((layer) => {
      layer.visible = true;
    });
  });

  const manifest = plan.buildManifest({
    ...meta,
    createdAt: new Date().toISOString()
  });
  const manifestFile = await folder.createFile("manifest.json", { overwrite: true });
  await manifestFile.write(JSON.stringify(manifest, null, 2));
  return { folder: folder.nativePath || folder.name, files: meta.files.concat(["manifest.json"]) };
}

async function exportViaQuickExport(folder, doc) {
  const dest = folder.nativePath;
  if (!dest) {
    throw new Error("Chemin dossier indisponible (nativePath).");
  }
  const boards = ps.artboardsOf(doc);
  if (boards.length) {
    for (const board of boards) {
      if (!naming.isArtboardName(board.name)) continue;
      await ps.selectOnly(board);
      await ps.batchPlay([
        {
          _obj: "exportSelectionAsFileTypePressed",
          _target: { _ref: "layer", _enum: "ordinal", _value: "targetEnum" },
          fileType: "png",
          quality: 32,
          metadata: 0,
          destFolder: dest,
          sRGB: true,
          openWindow: false,
          _options: { dialogOptions: "dontDisplay" }
        }
      ]);
    }
    return;
  }
  await ps.batchPlay([
    {
      _obj: "exportDocumentAsFileTypePressed",
      fileType: "png",
      quality: 32,
      metadata: 0,
      destFolder: dest,
      sRGB: true,
      openWindow: false,
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
}

async function exportByDuplicate(folder, doc, targets, meta) {
  const { app } = ps.photoshop();
  const originId = doc.id;
  for (const board of targets) {
    const copy = await doc.duplicate(board ? board.name : "CP_EXPORT");
    try {
      if (board) {
        const box = await ps.getArtboardRect(board);
        if (typeof copy.crop === "function") {
          await copy.crop({ left: box.left, top: box.top, right: box.right, bottom: box.bottom });
        }
      }
      const filename = `${(board && board.name) || "CP_MASTER"}.png`;
      const file = await folder.createFile(filename, { overwrite: true });
      await copy.saveAs.png(file, { compression: 6 }, true);
      meta.files.push(filename);
    } finally {
      copy.closeWithoutSaving();
      const origin = Array.from(app.documents).find((d) => d.id === originId);
      if (origin) app.activeDocument = origin;
    }
  }
}

if (typeof module !== "undefined") {
  module.exports = { exportPack };
}
