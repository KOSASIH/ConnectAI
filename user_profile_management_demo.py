const express = require('express');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.json());

// In-memory user data
let users = [
  { id: 1, username: 'john.doe', email: 'john.doe@example.com', firstName: 'John', lastName: 'Doe' },
  { id: 2, username: 'jane.smith', email: 'jane.smith@example.com', firstName: 'Jane', lastName: 'Smith' }
];

// Get user profile
app.get('/users/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  const user = users.find(user => user.id === userId);

  if (!user) {
    res.status(404).json({ error: 'User not found' });
  } else {
    res.json(user);
  }
});

// Update user profile
app.put('/users/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  const userIndex = users.findIndex(user => user.id === userId);

  if (userIndex === -1) {
    res.status(404).json({ error: 'User not found' });
  } else {
    const updatedUser = { ...users[userIndex], ...req.body };
    users[userIndex] = updatedUser;
    res.json(updatedUser);
  }
});

// Delete user profile
app.delete('/users/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  const userIndex = users.findIndex(user => user.id === userId);

  if (userIndex === -1) {
    res.status(404).json({ error: 'User not found' });
  } else {
    const deletedUser = users[userIndex];
    users = users.filter(user => user.id !== userId);
    res.json(deletedUser);
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
