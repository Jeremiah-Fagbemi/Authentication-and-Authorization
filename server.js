const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const app = express();
const port = 3000;

app.use(bodyParser.json());

const secretKey = 'yourSecretKey'; // Replace with a secure secret key

// Load user and inventory data from JSON files
let users = loadJsonFile('users.json') || [];
let inventory = loadJsonFile('inventory.json') || [];
let nextItemId = inventory.length > 0 ? Math.max(...inventory.map(item => item.id)) + 1 : 1;

// Middleware for API key authentication
const authenticate = (req, res, next) => {
  const apiKey = req.headers['api-key'];
  if (!apiKey) {
    return res.status(401).json({ error: 'API key is missing' });
  }

  try {
    jwt.verify(apiKey, secretKey);
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid API key' });
  }
};

// Middleware for authorization
const authorize = (req, res, next) => {
  const username = req.user.username;
  const isAdmin = users.find(user => user.username === username && user.role === 'admin');
  if (isAdmin) {
    next();
  } else {
    res.status(403).json({ error: 'Unauthorized. Only admin users are allowed' });
  }
};

// Helper function to load data from a JSON file
function loadJsonFile(filename) {
  try {
    const data = fs.readFileSync(filename);
    return JSON.parse(data);
  } catch (error) {
    return null;
  }
}

// Helper function to save data to a JSON file
function saveJsonFile(filename, data) {
  try {
    fs.writeFileSync(filename, JSON.stringify(data, null, 2));
  } catch (error) {
    console.error(`Error saving ${filename}:`, error.message);
  }
}

// Endpoint to create a new user
app.post('/api/users', (req, res) => {
  const { username, password, role } = req.body;

  // Check for duplicate username
  if (users.some(user => user.username === username)) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  const newUser = { username, password, role: role || 'normal' };
  users.push(newUser);
  saveJsonFile('users.json', users);

  res.status(201).json({ message: 'User created successfully' });
});

// Endpoint for user login to obtain an API key
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);

  if (user) {
    const apiKey = jwt.sign({ username: user.username, role: user.role }, secretKey);
    res.json({ apiKey });
  } else {
    res.status(401).json({ error: 'Invalid username or password' });
  }
});

// Middleware to authenticate requests using API key
app.use(authenticate);

// Endpoint to get all items (only accessible to normal users)
app.get('/api/items', (req, res) => {
  if (req.user.role === 'normal') {
    res.json(inventory);
  } else {
    res.status(403).json({ error: 'Unauthorized. Only normal users are allowed' });
  }
});

// Middleware to authorize requests for admin-only operations
app.use(authorize);

// CRUD operations for inventory (only accessible to admin users)
app.post('/api/items', (req, res) => {
  const newItem = {
    id: nextItemId++,
    name: req.body.name,
    price: req.body.price,
    size: req.body.size,
  };
  inventory.push(newItem);
  saveJsonFile('inventory.json', inventory);

  res.status(201).json(newItem);
});

app.put('/api/items/:id', (req, res) => {
  const itemId = parseInt(req.params.id);
  const updatedItem = req.body;
  const index = inventory.findIndex(item => item.id === itemId);

  if (index !== -1) {
    inventory[index] = { ...inventory[index], ...updatedItem };
    saveJsonFile('inventory.json', inventory);

    res.json(inventory[index]);
  } else {
    res.status(404).json({ error: 'Item not found' });
  }
});

app.delete('/api/items/:id', (req, res) => {
  const itemId = parseInt(req.params.id);
  const index = inventory.findIndex(item => item.id === itemId);

  if (index !== -1) {
    const deletedItem = inventory.splice(index, 1)[0];
    saveJsonFile('inventory.json', inventory);

    res.json(deletedItem);
  } else {
    res.status(404).json({ error: 'Item not found' });
  }
});

app.listen(port, () => {
  console.log(`API server listening at http://localhost:${port}`);
});
