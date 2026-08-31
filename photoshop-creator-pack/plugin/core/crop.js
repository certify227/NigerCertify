function unwrap(v) {
  if (v == null) return 0;
  if (typeof v === "number") return Number.isFinite(v) ? v : 0;
  if (typeof v === "object") {
    if (typeof v._value === "number") return v._value;
    if (typeof v.value === "number") return v.value;
  }
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function rect(left, top, right, bottom) {
  const l = unwrap(left);
  const t = unwrap(top);
  const r = unwrap(right);
  const b = unwrap(bottom);
  return {
    left: l,
    top: t,
    right: r,
    bottom: b,
    width: r - l,
    height: b - t
  };
}

function fromSize(width, height, left, top) {
  const l = unwrap(left);
  const t = unwrap(top);
  return rect(l, t, l + unwrap(width), t + unwrap(height));
}

function clamp(v, min, max) {
  return Math.max(min, Math.min(max, v));
}

/**
 * Calcule un transform cover/letterbox du master vers un preset.
 * src / dst / subject : {left,top,right,bottom,width,height} ou {width,height}.
 */
function computeCoverTransform(src, dst, subject, cropMode) {
  const srcW = src.width != null ? unwrap(src.width) : unwrap(src.right) - unwrap(src.left);
  const srcH = src.height != null ? unwrap(src.height) : unwrap(src.bottom) - unwrap(src.top);
  const dstW = dst.width != null ? unwrap(dst.width) : unwrap(dst.right) - unwrap(dst.left);
  const dstH = dst.height != null ? unwrap(dst.height) : unwrap(dst.bottom) - unwrap(dst.top);

  if (srcW <= 0 || srcH <= 0) {
    throw new Error("Master invalide (largeur/hauteur).");
  }
  if (dstW <= 0 || dstH <= 0) {
    throw new Error("Preset invalide (largeur/hauteur).");
  }

  const cover = Math.max(dstW / srcW, dstH / srcH);
  const contain = Math.min(dstW / srcW, dstH / srcH);
  const mode = cropMode || "subject";
  const scale = mode === "letterbox" ? contain : cover;
  const scaledW = srcW * scale;
  const scaledH = srcH * scale;

  let tx = (dstW - scaledW) / 2;
  let ty = (dstH - scaledH) / 2;

  const hasSubject =
    subject &&
    (subject.width > 0 || unwrap(subject.right) - unwrap(subject.left) > 0);

  if (hasSubject && (mode === "subject" || mode === "face")) {
    const sl = unwrap(subject.left);
    const st = unwrap(subject.top);
    const sr = subject.right != null ? unwrap(subject.right) : sl + unwrap(subject.width);
    const sb = subject.bottom != null ? unwrap(subject.bottom) : st + unwrap(subject.height);
    const cx = ((sl + sr) / 2) * scale;
    const cy = ((st + sb) / 2) * scale;
    const targetY = mode === "face" ? dstH * 0.38 : dstH / 2;
    tx = dstW / 2 - cx;
    ty = targetY - cy;
  }

  if (mode !== "letterbox") {
    tx = clamp(tx, Math.min(0, dstW - scaledW), 0);
    ty = clamp(ty, Math.min(0, dstH - scaledH), 0);
  }

  const needsExpand = mode !== "letterbox" && (scaledW + 0.5 < dstW || scaledH + 0.5 < dstH);

  return {
    scale,
    scalePercent: scale * 100,
    tx,
    ty,
    scaledW,
    scaledH,
    dstW,
    dstH,
    needsExpand,
    crop: {
      left: mode === "letterbox" ? 0 : Math.round(-tx),
      top: mode === "letterbox" ? 0 : Math.round(-ty),
      width: dstW,
      height: dstH
    }
  };
}

function safeRect(preset) {
  const w = unwrap(preset.width);
  const h = unwrap(preset.height);
  const top = Math.round(h * (preset.safeTop || 0));
  const bottomPad = Math.round(h * (preset.safeBottom || 0));
  const side = Math.round(w * (preset.safeSide || 0.04));
  return rect(side, top, w - side, h - bottomPad);
}

function typeBoxes(preset, density) {
  const box = safeRect(preset);
  const dens = density || "normal";
  const gap = dens === "airy" ? 28 : dens === "compact" ? 12 : 18;
  const hookRatio = 0.42;
  const proofRatio = 0.32;
  const ctaRatio = 0.18;
  const usable = box.height - gap * 2;
  const hookH = Math.round(usable * hookRatio);
  const proofH = Math.round(usable * proofRatio);
  const ctaH = Math.round(usable * ctaRatio);
  let y = box.top;
  const hook = rect(box.left, y, box.right, y + hookH);
  y += hookH + gap;
  const proof = rect(box.left, y, box.right, y + proofH);
  y += proofH + gap;
  const cta = rect(box.left, y, box.right, Math.min(box.bottom, y + ctaH));
  return { safe: box, hook, proof, cta };
}

if (typeof module !== "undefined") {
  module.exports = {
    unwrap,
    rect,
    fromSize,
    clamp,
    computeCoverTransform,
    safeRect,
    typeBoxes
  };
}
