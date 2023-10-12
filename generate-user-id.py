// Task 2: Develop a SCIM API server using Express to manage user identities

const express = require('express');
const app = express();
const bodyParser = require('body-parser');

// Middleware for parsing JSON request bodies
app.use(bodyParser.json());

// In-memory storage for user resources
let users = [];

// Endpoint for creating user resources
app.post('/Users', (req, res) => {
  const user = req.body;
  // Generate a unique ID for the user
  const userId = generateUserId();
  user.id = userId;
  users.push(user);
  res.status(201).json(user);
});

// Endpoint for reading user resources
app.get('/Users/:userId', (req, res) => {
  const userId = req.params.userId;
  const user = users.find((user) => user.id === userId);
  if (user) {
    res.json(user);
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

// Endpoint for updating user resources
app.put('/Users/:userId', (req, res) => {
  const userId = req.params.userId;
  const updatedUser = req.body;
  const userIndex = users.findIndex((user) => user.id === userId);
  if (userIndex !== -1) {
    users[userIndex] = { ...users[userIndex], ...updatedUser };
    res.json(users[userIndex]);
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

// Endpoint for deleting user resources
app.delete('/Users/:userId', (req, res) => {
  const userId = req.params.userId;
  const userIndex = users.findIndex((user) => user.id === userId);
  if (userIndex !== -1) {
    const deletedUser = users.splice(userIndex, 1)[0];
    res.json(deletedUser);
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

// Start the server
app.listen(3000, () => {
  console.log('SCIM API server started on port 3000');
});

// Helper function to generate a unique user ID
function generateUserId() {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}
