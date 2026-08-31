function wrapWords(text, charsPerLine) {
  const words = String(text || "")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  if (!words.length) return [];
  const lines = [];
  let current = "";
  for (const word of words) {
    const next = current ? `${current} ${word}` : word;
    if (next.length <= charsPerLine || !current) {
      current = next;
      if (word.length > charsPerLine && current === word) {
        lines.push(current);
        current = "";
      }
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current) lines.push(current);
  return lines;
}

const DENSITY = {
  compact: { lineHeight: 1.02, tracking: -20 },
  normal: { lineHeight: 1.15, tracking: 0 },
  airy: { lineHeight: 1.32, tracking: 20 }
};

/**
 * Estime une taille de police qui tient dans la boîte.
 * Photoshop affine ensuite avec les vrais bounds du calque.
 */
function fitFontSize(options) {
  const text = String(options.text || "").trim();
  const maxWidth = Math.max(1, options.maxWidth || 1);
  const maxHeight = Math.max(1, options.maxHeight || 1);
  const maxPt = options.maxPt || 48;
  const minPt = options.minPt || 12;
  const maxLines = options.maxLines || 3;
  const dens = DENSITY[options.density] || DENSITY.normal;
  const charFactor = options.charFactor || 0.56;

  if (!text) {
    return { size: maxPt, lines: [], overflow: false, lineHeight: dens.lineHeight };
  }

  let size = maxPt;
  let best = null;
  while (size >= minPt) {
    const avgChar = Math.max(1, size * charFactor);
    const charsPerLine = Math.max(1, Math.floor(maxWidth / avgChar));
    const lines = wrapWords(text, charsPerLine);
    const lineH = size * dens.lineHeight;
    const fitsLines = lines.length <= maxLines;
    const fitsHeight = lines.length * lineH <= maxHeight;
    const longest = lines.reduce((m, l) => Math.max(m, l.length), 0);
    const fitsWidth = longest * avgChar <= maxWidth * 1.02;
    if (fitsLines && fitsHeight && fitsWidth) {
      best = { size, lines, overflow: false, lineHeight: dens.lineHeight, tracking: dens.tracking };
      break;
    }
    size -= 1;
  }

  if (best) return best;

  const avgChar = Math.max(1, minPt * charFactor);
  const lines = wrapWords(text, Math.max(1, Math.floor(maxWidth / avgChar)));
  return {
    size: minPt,
    lines,
    overflow: true,
    lineHeight: dens.lineHeight,
    tracking: dens.tracking
  };
}

function luminance(rgb) {
  const [r, g, b] = rgb.map((c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrastRatio(a, b) {
  const l1 = luminance(a);
  const l2 = luminance(b);
  const light = Math.max(l1, l2);
  const dark = Math.min(l1, l2);
  return (light + 0.05) / (dark + 0.05);
}

function pickTextColor(bgRgb) {
  const white = contrastRatio(bgRgb, [255, 255, 255]);
  const black = contrastRatio(bgRgb, [12, 12, 12]);
  if (white >= 4.5 || white >= black) {
    return { rgb: [255, 255, 255], contrast: white, scrim: white < 4.5 };
  }
  return { rgb: [12, 12, 12], contrast: black, scrim: black < 4.5 };
}

if (typeof module !== "undefined") {
  module.exports = { wrapWords, fitFontSize, DENSITY, luminance, contrastRatio, pickTextColor };
}
