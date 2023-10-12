// Define roles and their corresponding permissions
const roles = {
  admin: ['create', 'read', 'update', 'delete'],
  user: ['read', 'update']
};

// Middleware function to check if the user has the required role
function checkRole(role) {
  return (req, res, next) => {
    // Get the user's role from the authentication process
    const userRole = req.user.role;

    // Check if the user has the required role
    if (roles[userRole] && roles[userRole].includes(role)) {
      next(); // User has the required role, proceed to the next middleware
    } else {
      res.status(403).json({ error: 'Access denied' }); // User doesn't have the required role
    }
  };
}

// Example route for creating a user (restricted to admins only)
app.post('/users', checkRole('create'), (req, res) => {
  // Create the user
  // ...
  res.status(201).json({ message: 'User created successfully' });
});

// Example route for updating a user (restricted to admins and users)
app.put('/users/:id', checkRole('update'), (req, res) => {
  // Update the user
  // ...
  res.json({ message: 'User updated successfully' });
});

// Example route for deleting a user (restricted to admins only)
app.delete('/users/:id', checkRole('delete'), (req, res) => {
  // Delete the user
  // ...
  res.json({ message: 'User deleted successfully' });
});
