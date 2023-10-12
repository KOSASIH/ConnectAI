const express = require('express');
const app = express();

// Define a roles array to store the roles
let roles = [];

// Endpoint for creating a new role
app.post('/roles', (req, res) => {
  const { roleName } = req.body;
  
  // Check if the role already exists
  const roleExists = roles.find(role => role.name === roleName);
  if (roleExists) {
    return res.status(400).json({ error: 'Role already exists' });
  }

  // Create a new role and add it to the roles array
  const newRole = { name: roleName };
  roles.push(newRole);

  return res.status(201).json(newRole);
});

// Endpoint for reading all roles
app.get('/roles', (req, res) => {
  return res.json(roles);
});

// Endpoint for updating a role
app.put('/roles/:roleId', (req, res) => {
  const { roleId } = req.params;
  const { roleName } = req.body;

  // Find the role to update
  const roleToUpdate = roles.find(role => role.name === roleName);
  if (!roleToUpdate) {
    return res.status(404).json({ error: 'Role not found' });
  }

  // Update the role name
  roleToUpdate.name = roleName;

  return res.json(roleToUpdate);
});

// Endpoint for deleting a role
app.delete('/roles/:roleId', (req, res) => {
  const { roleId } = req.params;

  // Find the role to delete
  const roleIndex = roles.findIndex(role => role.id === roleId);
  if (roleIndex === -1) {
    return res.status(404).json({ error: 'Role not found' });
  }

  // Remove the role from the roles array
  roles.splice(roleIndex, 1);

  return res.sendStatus(204);
});

// Middleware function to check if the user has the required role
function checkRole(roleName) {
  return (req, res, next) => {
    // Check if the user has the required role
    const hasRole = req.user.roles.includes(roleName);
    if (!hasRole) {
      return res.status(403).json({ error: 'Access denied' });
    }

    return next();
  };
}

// Example route that requires the 'admin' role
app.get('/admin-only', checkRole('admin'), (req, res) => {
  return res.json({ message: 'Admin only route' });
});

// Start the server
app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
