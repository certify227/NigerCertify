function splitBrief(raw) {
  const text = String(raw || "").replace(/\r/g, "").trim();
  if (!text) {
    return { hook: "", proof: "", cta: "" };
  }
  const parts = text
    .split(/\n+|[\.\!\?]+/)
    .map((s) => s.trim())
    .filter(Boolean);

  const hook = parts[0] || "";
  const ctaCandidate = parts.length > 2 ? parts[parts.length - 1] : "";
  const looksCta = /^(shop|buy|get|try|join|download|swipe|link|achète|achetez|découvre|découvrez|essaie|en savoir|commande|shop now|lien)/i.test(
    ctaCandidate
  );
  let proof;
  let cta;
  if (parts.length === 1) {
    proof = "";
    cta = "En savoir plus";
  } else if (parts.length === 2) {
    proof = parts[1];
    cta = "En savoir plus";
  } else if (looksCta) {
    proof = parts.slice(1, -1).join(". ");
    cta = ctaCandidate;
  } else {
    proof = parts.slice(1, -1).join(". ");
    cta = ctaCandidate;
  }
  return { hook, proof, cta };
}

function shorten(text, max) {
  const t = String(text || "").trim();
  if (t.length <= max) return t;
  const cut = t.slice(0, max - 1);
  const sp = cut.lastIndexOf(" ");
  return `${(sp > 12 ? cut.slice(0, sp) : cut).trim()}…`;
}

function extractNumber(text) {
  const m = String(text || "").match(/-?\d+(?:[.,]\d+)?%?/);
  return m ? m[0] : null;
}

function hookVariants(hook) {
  const base = String(hook || "").trim();
  if (!base) return ["", "", ""];
  const num = extractNumber(base);
  const short = shorten(base, 42);
  const emotion = base.length > 28 ? shorten(base, 28) : base;
  const upper = short.toUpperCase();
  const numbered = num ? `${num}. ${shorten(base.replace(num, "").trim(), 36)}` : `Stop. ${emotion}`;
  return [short, upper, numbered];
}

function applyTemplate(slots, templateId) {
  const hook = slots.hook || "";
  const proof = slots.proof || "";
  const cta = slots.cta || "En savoir plus";
  switch (templateId) {
    case "number_context_cta": {
      const n = extractNumber(hook) || extractNumber(proof) || "3";
      return {
        hook: `${n} choses à savoir`,
        proof: proof || hook,
        cta
      };
    }
    case "question_answer_cta":
      return {
        hook: hook.endsWith("?") ? hook : `${shorten(hook, 40)} ?`,
        proof,
        cta
      };
    case "quote_source":
      return {
        hook: `« ${shorten(hook, 48)} »`,
        proof,
        cta: cta
      };
    case "silent_caption":
      return {
        hook: shorten(hook, 28),
        proof: "",
        cta: shorten(cta, 18)
      };
    default:
      return { hook, proof, cta };
  }
}

if (typeof module !== "undefined") {
  module.exports = { splitBrief, shorten, extractNumber, hookVariants, applyTemplate };
}
