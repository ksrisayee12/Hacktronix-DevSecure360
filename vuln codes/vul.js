// vuln_more.js
// Run: npm init -y && npm i express
const express = require("express");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Helper function for prototype pollution snippet
function unsafeExtend(target, source) {
  for (let prop in source) {
    if (Object.prototype.hasOwnProperty.call(source, prop)) {
      if (typeof target[prop] === 'object' && typeof source[prop] === 'object') {
        unsafeExtend(target[prop], source[prop]); 
      } else {
        target[prop] = source[prop]; 
      }
    }
  }
  return target;
}

// 1. Prototype Pollution Endpoint
// SAST Flow: req.body.config -> unsafeExtend source parameter -> target property mutation
app.post("/config", (req, res) => {
  const userConfig = req.body.config || {};
  let baseConfig = {};
  
  // Dangerous: Merging untrusted object without blocking dangerous keys
  unsafeExtend(baseConfig, userConfig);
  
  res.json({ status: "configured", isAdmin: {}.isAdmin || false });
});

// 2. Path Traversal Endpoint
// SAST Flow: req.query.file -> string concatenation -> fs.readFile path argument
app.get("/download", (req, res) => {
  const filename = req.query.file || "welcome.txt";
  
  // Dangerous: Concatenating untrusted string directly into file system API
  const safePath = path.join(__dirname, "public", filename); 
  
  fs.readFile(safePath, "utf8", (err, data) => {
    if (err) {
      return res.status(404).send("File not found");
    }
    res.send(data);
  });
});

app.listen(3001, () => console.log("Additional vuln app on :3001"));
