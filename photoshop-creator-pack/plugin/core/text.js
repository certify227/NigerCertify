const ps = require("./ps.js");

async function makeTextBox(opts) {
  const { name, text, box, size, rgb, align } = opts;
  const color = rgb || [255, 255, 255];
  const alignment = align === "left" ? "left" : align === "right" ? "right" : "center";
  const contents = String(text || "");
  const px = (n) => ({ _unit: "pixelsUnit", _value: n });

  const using = {
    _obj: "textLayer",
    textKey: contents,
    textShape: [
      {
        _obj: "textShape",
        char: { _enum: "char", _value: "box" },
        bounds: {
          _obj: "rectangle",
          top: px(box.top),
          left: px(box.left),
          bottom: px(box.bottom),
          right: px(box.right)
        }
      }
    ],
    textStyleRange: [
      {
        _obj: "textStyleRange",
        from: 0,
        to: contents.length,
        textStyle: {
          _obj: "textStyle",
          size: { _unit: "pointsUnit", _value: size },
          color: {
            _obj: "RGBColor",
            red: color[0],
            green: color[1],
            blue: color[2]
          }
        }
      }
    ],
    paragraphStyleRange: [
      {
        _obj: "paragraphStyleRange",
        from: 0,
        to: contents.length,
        paragraphStyle: {
          _obj: "paragraphStyle",
          align: { _enum: "alignmentType", _value: alignment },
          hyphenate: true
        }
      }
    ]
  };

  try {
    await ps.batchPlay([
      {
        _obj: "make",
        _target: [{ _ref: "textLayer" }],
        using,
        _options: { dialogOptions: "dontDisplay" }
      }
    ]);
  } catch (_) {
    const doc = ps.requireDoc();
    const layer = await doc.createTextLayer({
      name,
      contents,
      fontSize: size,
      position: { x: box.left, y: box.top + size }
    });
    if (layer) layer.name = name;
    return layer;
  }

  const { app } = ps.photoshop();
  const layer = app.activeDocument.activeLayers[0];
  if (layer) layer.name = name;
  return layer;
}

async function setTextContents(layer, text, size, rgb) {
  const contents = String(text || "");
  const color = rgb || [255, 255, 255];
  try {
    if (layer.textItem) {
      layer.textItem.contents = contents;
      if (layer.textItem.characterStyle) {
        try {
          layer.textItem.characterStyle.size = size;
        } catch (_) {
          layer.textItem.characterStyle.size = { _unit: "pointsUnit", _value: size };
        }
      }
      return;
    }
  } catch (_) {
    /* batchPlay fallback */
  }
  await ps.selectOnly(layer);
  await ps.batchPlay([
    {
      _obj: "set",
      _target: [{ _ref: "textLayer", _id: layer.id }],
      to: {
        _obj: "textLayer",
        textKey: contents,
        textStyleRange: [
          {
            _obj: "textStyleRange",
            from: 0,
            to: contents.length,
            textStyle: {
              _obj: "textStyle",
              size: { _unit: "pointsUnit", _value: size },
              color: {
                _obj: "RGBColor",
                red: color[0],
                green: color[1],
                blue: color[2]
              }
            }
          }
        ]
      },
      _options: { dialogOptions: "dontDisplay" }
    }
  ]);
}

if (typeof module !== "undefined") {
  module.exports = { makeTextBox, setTextContents };
}
