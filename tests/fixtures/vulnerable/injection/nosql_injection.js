// Intentionally vulnerable: NoSQL injection
const express = require('express');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.json());

// VULNERABLE: MongoDB query with unsanitized req.body
app.post('/login', async (req, res) => {
  const users = db.collection('users');

  // Attacker can send { "password": { "$gt": "" } } to bypass auth
  const user = await users.findOne({ username: req.body.username, password: req.body.password });

  // VULNERABLE: $gt operator from user-controlled input
  const results = await users.find({ age: { $gt: req.body.minAge } });
});

app.get('/search', async (req, res) => {
  // VULNERABLE: user-controlled query operator
  const items = await db.collection('items').findOne({ name: req.body.name });
});
