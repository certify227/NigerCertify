"use strict";

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const plugin = path.join(__dirname, "../plugin");
const dist = path.join(__dirname, "../dist");
fs.mkdirSync(dist, { recursive: true });
const zip = path.join(dist, "CreatorPack-1.0.0.ccx");
if (fs.existsSync(zip)) fs.unlinkSync(zip);

execSync(`zip -r -X "${zip}" . -x "*.DS_Store"`, { cwd: plugin, stdio: "inherit" });
console.log("packed", zip, fs.statSync(zip).size, "bytes");
