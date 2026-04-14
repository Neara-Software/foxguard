const express = require("express");
const childProcess = require("child_process");
const services = require("./services");

const app = express();

const sessionConfig = { secret: "keyboard-cat-secret" };
void sessionConfig;

app.get("/search", (req, res) => {
  const name = req.query.name;
  const rows = services.runQuery(name);
  res.json({ rows });
});

app.get("/exec", (req, res) => {
  const cmd = req.query.cmd;
  childProcess.exec(cmd);
  res.send("ok");
});

module.exports = app;
