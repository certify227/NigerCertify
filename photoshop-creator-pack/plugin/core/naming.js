const PREFIX = "CP_";
const MASTER = "CP_MASTER";
const SUBJECT = "CP_SUBJECT";
const FACE = "CP_FACE";
const BG = "CP_BG";
const ACCENT = "CP_ACCENT";
const META = "CP_META";
const NOTE = "CP_NOTE";
const SHAPE_CTA = "CP_SHAPE_CTA";
const ADJ_PALETTE = "CP_ADJ_PALETTE";

const TXT = {
  hook: "CP_TXT_HOOK",
  proof: "CP_TXT_PROOF",
  cta: "CP_TXT_CTA"
};

function artboardName(presetId) {
  return `CP_AB_${presetId}`;
}

function frameName(index) {
  const n = String(index).padStart(2, "0");
  return `CP_FR_${n}`;
}

function safezoneName(presetId) {
  return `CP_SAFEZONE_${presetId}`;
}

function parseFrameIndex(name) {
  const m = /^CP_FR_(\d+)$/.exec(name || "");
  return m ? parseInt(m[1], 10) : null;
}

function isManaged(name) {
  return typeof name === "string" && name.startsWith(PREFIX);
}

function isArtboardName(name) {
  return /^(CP_MASTER|CP_AB_|CP_FR_)/.test(name || "");
}

function exportSkip(name) {
  return /^(CP_META|CP_SAFEZONE_|CP_UI_MOCK|CP_NOTE)/.test(name || "");
}

if (typeof module !== "undefined") {
  module.exports = {
    PREFIX,
    MASTER,
    SUBJECT,
    FACE,
    BG,
    ACCENT,
    META,
    NOTE,
    SHAPE_CTA,
    ADJ_PALETTE,
    TXT,
    artboardName,
    frameName,
    safezoneName,
    parseFrameIndex,
    isManaged,
    isArtboardName,
    exportSkip
  };
}
