const NARRATIVES = [
  {
    id: "pas",
    label: "PAS (problème → agitate → solution)",
    minFrames: 5,
    maxFrames: 5,
    defaultFrames: 5,
    beats: [
      { slot: "hook", title: "Problème", hint: "Nomme la douleur en 5 mots." },
      { slot: "proof", title: "Agitation", hint: "Montre le coût de ne rien changer." },
      { slot: "proof", title: "Solution", hint: "Introduis le produit / l’idée." },
      { slot: "proof", title: "Preuve", hint: "Chiffre, avant/après, témoignage." },
      { slot: "cta", title: "CTA", hint: "Verbe + offre claire." }
    ]
  },
  {
    id: "before_after",
    label: "Avant / Après",
    minFrames: 3,
    maxFrames: 3,
    defaultFrames: 3,
    beats: [
      { slot: "hook", title: "Avant", hint: "Situation actuelle, friction visible." },
      { slot: "proof", title: "Après", hint: "Résultat désiré, même cadrage." },
      { slot: "cta", title: "Offre", hint: "Comment ils y arrivent + CTA." }
    ]
  },
  {
    id: "howto",
    label: "How-to",
    minFrames: 5,
    maxFrames: 8,
    defaultFrames: 6,
    beats: [
      { slot: "hook", title: "Hook", hint: "Promesse du tuto." },
      { slot: "proof", title: "Étape 1", hint: "Action concrète." },
      { slot: "proof", title: "Étape 2", hint: "Action concrète." },
      { slot: "proof", title: "Étape 3", hint: "Action concrète." },
      { slot: "proof", title: "Résultat", hint: "Montre le livrable." },
      { slot: "cta", title: "CTA", hint: "Suivre / enregistrer / lien bio." }
    ]
  },
  {
    id: "myth",
    label: "Mythe vs vérité",
    minFrames: 4,
    maxFrames: 4,
    defaultFrames: 4,
    beats: [
      { slot: "hook", title: "Mythe", hint: "Croyance répandue." },
      { slot: "proof", title: "Vérité", hint: "Correction nette." },
      { slot: "proof", title: "Preuve", hint: "Pourquoi c’est vrai." },
      { slot: "cta", title: "CTA", hint: "Application concrète." }
    ]
  },
  {
    id: "reels_beats",
    label: "Reels / Shorts (6 beats)",
    minFrames: 6,
    maxFrames: 6,
    defaultFrames: 6,
    beats: [
      { slot: "hook", title: "0–1s Hook visuel", hint: "Pattern interrupt, visage ou texte énorme." },
      { slot: "hook", title: "1–3s Texte", hint: "Hook écrit, 5 mots max." },
      { slot: "proof", title: "3–5s Contexte", hint: "Pourquoi ça compte." },
      { slot: "proof", title: "Démo", hint: "Montre, ne raconte pas." },
      { slot: "proof", title: "Preuve", hint: "Résultat / social proof." },
      { slot: "cta", title: "Close CTA", hint: "Un verbe. Un lien." }
    ]
  }
];

function getNarrative(id) {
  return NARRATIVES.find((n) => n.id === id) || NARRATIVES[0];
}

function buildBeats(templateId, frameCount) {
  const tpl = getNarrative(templateId);
  const n = clamp(frameCount, tpl.minFrames, tpl.maxFrames);
  const beats = tpl.beats.slice();
  if (n === beats.length) return beats.map((b, i) => ({ ...b, index: i + 1 }));
  if (n < beats.length) {
    const head = beats.slice(0, n - 1);
    const last = beats[beats.length - 1];
    return [...head, last].map((b, i) => ({ ...b, index: i + 1 }));
  }
  const extra = n - beats.length;
  const insertAt = Math.max(1, beats.length - 2);
  const out = beats.slice();
  for (let i = 0; i < extra; i++) {
    out.splice(insertAt + i, 0, {
      slot: "proof",
      title: `Détail ${i + 1}`,
      hint: "Point de continuité (même fond, nouvel accent)."
    });
  }
  return out.map((b, i) => ({ ...b, index: i + 1 }));
}

function clamp(v, min, max) {
  return Math.max(min, Math.min(max, v));
}

if (typeof module !== "undefined") {
  module.exports = { NARRATIVES, getNarrative, buildBeats };
}
