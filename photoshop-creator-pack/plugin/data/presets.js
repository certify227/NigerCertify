/**
 * Presets plateformes Photoshop 2025 / 2026.
 * Dimensions en pixels, safe zones en ratios 0–1.
 */
const PLATFORM_PRESETS = [
  {
    id: "ig_feed_45",
    label: "Instagram Feed 4:5",
    short: "IG 4:5",
    platform: "instagram",
    width: 1080,
    height: 1350,
    safeTop: 0.04,
    safeBottom: 0.06,
    safeSide: 0.05,
    type: {
      hook: { minPt: 36, maxPt: 72, maxLines: 3 },
      proof: { minPt: 22, maxPt: 36, maxLines: 3 },
      cta: { minPt: 20, maxPt: 28, maxLines: 1 }
    },
    default: true
  },
  {
    id: "ig_feed_11",
    label: "Instagram 1:1",
    short: "IG 1:1",
    platform: "instagram",
    width: 1080,
    height: 1080,
    safeTop: 0.05,
    safeBottom: 0.06,
    safeSide: 0.05,
    type: {
      hook: { minPt: 34, maxPt: 64, maxLines: 3 },
      proof: { minPt: 20, maxPt: 32, maxLines: 3 },
      cta: { minPt: 18, maxPt: 26, maxLines: 1 }
    },
    default: false
  },
  {
    id: "ig_story",
    label: "Instagram Story / Reels",
    short: "Story 9:16",
    platform: "instagram",
    width: 1080,
    height: 1920,
    safeTop: 0.14,
    safeBottom: 0.20,
    safeSide: 0.08,
    type: {
      hook: { minPt: 42, maxPt: 78, maxLines: 4 },
      proof: { minPt: 24, maxPt: 40, maxLines: 3 },
      cta: { minPt: 22, maxPt: 32, maxLines: 1 }
    },
    default: true
  },
  {
    id: "tiktok",
    label: "TikTok",
    short: "TikTok",
    platform: "tiktok",
    width: 1080,
    height: 1920,
    safeTop: 0.12,
    safeBottom: 0.22,
    safeSide: 0.10,
    type: {
      hook: { minPt: 42, maxPt: 78, maxLines: 4 },
      proof: { minPt: 24, maxPt: 38, maxLines: 3 },
      cta: { minPt: 22, maxPt: 32, maxLines: 1 }
    },
    default: true
  },
  {
    id: "yt_thumb",
    label: "YouTube Miniature",
    short: "YT 16:9",
    platform: "youtube",
    width: 1280,
    height: 720,
    safeTop: 0.08,
    safeBottom: 0.12,
    safeSide: 0.06,
    type: {
      hook: { minPt: 28, maxPt: 64, maxLines: 2 },
      proof: { minPt: 18, maxPt: 28, maxLines: 2 },
      cta: { minPt: 16, maxPt: 24, maxLines: 1 }
    },
    default: true
  },
  {
    id: "yt_short",
    label: "YouTube Shorts",
    short: "Shorts",
    platform: "youtube",
    width: 1080,
    height: 1920,
    safeTop: 0.12,
    safeBottom: 0.18,
    safeSide: 0.08,
    type: {
      hook: { minPt: 42, maxPt: 78, maxLines: 4 },
      proof: { minPt: 24, maxPt: 40, maxLines: 3 },
      cta: { minPt: 22, maxPt: 32, maxLines: 1 }
    },
    default: false
  },
  {
    id: "li_post",
    label: "LinkedIn Post",
    short: "LinkedIn",
    platform: "linkedin",
    width: 1200,
    height: 627,
    safeTop: 0.08,
    safeBottom: 0.10,
    safeSide: 0.06,
    type: {
      hook: { minPt: 26, maxPt: 52, maxLines: 2 },
      proof: { minPt: 16, maxPt: 26, maxLines: 2 },
      cta: { minPt: 16, maxPt: 22, maxLines: 1 }
    },
    default: false
  },
  {
    id: "x_post",
    label: "X / Twitter",
    short: "X 16:9",
    platform: "x",
    width: 1600,
    height: 900,
    safeTop: 0.06,
    safeBottom: 0.08,
    safeSide: 0.05,
    type: {
      hook: { minPt: 28, maxPt: 56, maxLines: 2 },
      proof: { minPt: 18, maxPt: 28, maxLines: 2 },
      cta: { minPt: 16, maxPt: 22, maxLines: 1 }
    },
    default: false
  }
];

function getPreset(id) {
  return PLATFORM_PRESETS.find((p) => p.id === id) || null;
}

function defaultPresetIds() {
  return PLATFORM_PRESETS.filter((p) => p.default).map((p) => p.id);
}

if (typeof module !== "undefined") {
  module.exports = { PLATFORM_PRESETS, getPreset, defaultPresetIds };
}
