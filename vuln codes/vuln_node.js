// vuln_node.js
// Run: npm init -y && npm i express
const express = require("express");
const { exec } = require("child_process");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Simple page that reflects the query param (reflected XSS)
app.get("/", (req, res) => {
  const name = req.query.name || "guest";
  // Reflected XSS: unsanitized user input printed into HTML
  res.send(`<html><body><h1>Hi ${name}</h1></body></html>`);
});

app.post("/shell", (req, res) => {
  const cmd = req.body.cmd || "echo ok";
  // Dangerous: using user input directly in exec -> command injection
  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).send("error");
    }
    res.send({ out: stdout });
  });
});

app.post("/calc", (req, res) => {
  const code = req.body.code || "1+1";
  // Very unsafe: eval on user provided code
  try {
    const result = eval(code);
    res.json({ result });
  } catch (e) {
    res.status(400).send("bad code");
  }
});

app.listen(3000, () => console.log("vuln app on :3000"));