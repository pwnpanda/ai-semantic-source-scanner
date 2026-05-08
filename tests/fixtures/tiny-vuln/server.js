const express = require('express');
const mysql = require('mysql2');
const app = express();
const conn = mysql.createConnection({ host: 'localhost' });
app.get('/u', (req, res) => {
  // CWE-89: req.query.id flows unparameterised into a SQL query string.
  const sql = "SELECT * FROM users WHERE id=" + req.query.id;
  conn.query(sql, (err, rows) => res.json(rows));
});
app.listen(3000);
