const naming = require("../core/naming.js");
const plan = require("../core/plan.js");
const ps = require("../core/ps.js");

async function pickFolder() {
  const fs = ps.uxp().storage.localFileSystem;
  let folder;
  try {
    folder = await fs.getFolder();
  } catch (err) {
    throw new ps.UserCancel("Export annulé.");
  }
  if (!folder) throw new ps.UserCancel("Export annulé.");
  return folder;
}

async function exportPack(options) {
  const folder = await pickFolder();
  const includeNotes = Boolean(options.includeNotes);
  const includeMaster = options.includeMaster !== false;
  const meta = {
    document: "",
    canvas: { targets: options.presetIds || [] },
    type: options.type || {},
    story: options.story || {},
    files: []
  };

  await ps.execute("Creator Pack — Export", async (_ctx, doc) => {
    meta.document = doc.title || doc.name || "";
    const boards = ps
      .artboardsOf(doc)
      .filter((b) => naming.shouldExportArtboard(b.name, includeMaster));

    try {
      if (boards.length) {
        await exportByDuplicate(folder, doc, boards, meta, includeNotes);
      } else {
        const file = await folder.createFile("CP_EXPORT.png", { overwrite: true });
        await doc.saveAs.png(file, { compression: 6 }, true);
        meta.files.push("CP_EXPORT.png");
      }
    } catch (err) {
      if (!boards.length) throw err;
      await exportViaQuickExport(folder, doc, boards);
      if (!meta.files.length) {
        boards.forEach((board) => meta.files.push(`${board.name}.png`));
      }
    }
  });

  const manifest = plan.buildManifest({
    ...meta,
    createdAt: new Date().toISOString()
  });
  const formats = ps.uxp().storage.formats;
  const manifestFile = await folder.createFile("manifest.json", { overwrite: true });
  if (formats && formats.utf8) {
    await manifestFile.write(JSON.stringify(manifest, null, 2), { format: formats.utf8 });
  } else {
    await manifestFile.write(JSON.stringify(manifest, null, 2));
  }
  return {
    folder: folder.nativePath || folder.name,
    files: meta.files.concat(["manifest.json"])
  };
}

async function exportByDuplicate(folder, origin, boards, meta, includeNotes) {
  const originId = origin.id;
  for (const board of boards) {
    const filename = `${board.name}.png`;
    const box = await ps.getArtboardRect(board);
    let copy;
    try {
      copy = await origin.duplicate(board.name);
      if (!includeNotes) {
        for (const layer of ps.allLayers(copy)) {
          if (naming.exportSkip(layer.name)) layer.visible = false;
        }
      }
      await ps.cropDoc(copy, box);
      const file = await folder.createFile(filename, { overwrite: true });
      await copy.saveAs.png(file, { compression: 6 }, true);
      meta.files.push(filename);
    } finally {
      await ps.closeTemp(copy, originId);
    }
  }
}

async function exportViaQuickExport(folder, doc, boards) {
  const dest = folder.nativePath;
  if (!dest) throw new Error("Chemin dossier indisponible (nativePath).");
  for (const board of boards) {
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
}

if (typeof module !== "undefined") {
  module.exports = { exportPack };
}
