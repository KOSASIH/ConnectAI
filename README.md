# ConnectAI
Revolutionizing Identity with OIDC &amp; SCIM

# Tutorial 

## Implement OIDC Authentication

```javascript
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const OIDCStrategy = require('passport-openidconnect').Strategy;

const app = express();

// Configure session middleware
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}));

// Configure passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Configure OIDC strategy
passport.use(new OIDCStrategy({
  issuer: 'https://your-oidc-provider.com',
  authorizationURL: 'https://your-oidc-provider.com/authorize',
  tokenURL: 'https://your-oidc-provider.com/token',
  userInfoURL: 'https://your-oidc-provider.com/userinfo',
  clientID: 'your-client-id',
  clientSecret: 'your-client-secret',
  callbackURL: 'http://localhost:3000/callback',
  scope: 'openid profile email'
}, (accessToken, refreshToken, profile, done) => {
  // Save the access token and ID token to the session
  req.session.accessToken = accessToken;
  req.session.idToken = profile.id;

  // Handle user authentication logic here

  return done(null, profile);
}));

// Configure passport serialization
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Define routes
app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.get('/login', passport.authenticate('openidconnect'));

app.get('/callback', passport.authenticate('openidconnect', {
  successRedirect: '/profile',
  failureRedirect: '/login'
}));

app.get('/profile', (req, res) => {
  // Access the access token and ID token from the session
  const accessToken = req.session.accessToken;
  const idToken = req.session.idToken;

  // Use the tokens to access user information or perform other actions

  res.send('User profile');
});

// Start the server
app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

This code demonstrates how to implement an OIDC authentication flow using the `passport-openidconnect` library. It configures the necessary client credentials, authorization endpoint, token endpoint, and callback URL. It also includes the code for handling the callback and obtaining the user's access token and ID token.

## Develop SCIM API Derver

```javascript
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
```

This code sets up an Express server that provides endpoints for creating, reading, updating, and deleting user resources. The server uses an in-memory storage (`users` array) to store the user data.

To run this code, you would need to have Node.js and the required dependencies (`express` and `body-parser`) installed. You can start the server by running the script with Node.js (`node server.js`). The server will listen on port 3000.

## Example Web Application

```javascript
// Sample web application integrating OIDC authentication and SCIM user management

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const OIDCStrategy = require('passport-openidconnect').Strategy;
const axios = require('axios');

// Configure OIDC authentication
passport.use(
  new OIDCStrategy(
    {
      issuer: 'https://your-oidc-provider.com',
      authorizationURL: 'https://your-oidc-provider.com/auth',
      tokenURL: 'https://your-oidc-provider.com/token',
      userInfoURL: 'https://your-oidc-provider.com/userinfo',
      clientID: 'your-client-id',
      clientSecret: 'your-client-secret',
      callbackURL: 'http://localhost:3000/auth/callback',
      scope: 'openid profile',
    },
    (accessToken, refreshToken, profile, done) => {
      // Save the access token and user profile to session
      req.session.accessToken = accessToken;
      req.session.profile = profile;
      return done(null, profile);
    }
  )
);

// Configure SCIM API server endpoint
const scimAPIEndpoint = 'https://your-scim-api-server.com/api/users';

// Create Express app
const app = express();

// Enable session management
app.use(
  session({
    secret: 'your-session-secret',
    resave: false,
    saveUninitialized: true,
  })
);

// Initialize Passport and session
app.use(passport.initialize());
app.use(passport.session());

// Define routes

// OIDC authentication routes
app.get('/auth', passport.authenticate('openidconnect'));

app.get(
  '/auth/callback',
  passport.authenticate('openidconnect', {
    successRedirect: '/profile',
    failureRedirect: '/login',
  })
);

// Profile route
app.get('/profile', (req, res) => {
  // Check if user is authenticated
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }

  // Retrieve user information from SCIM API server using OIDC access token
  axios
    .get(scimAPIEndpoint, {
      headers: {
        Authorization: `Bearer ${req.session.accessToken}`,
      },
    })
    .then((response) => {
      const users = response.data;
      // Render user profile page with retrieved user information
      res.render('profile', { user: req.session.profile, users: users });
    })
    .catch((error) => {
      console.error(error);
      res.sendStatus(500);
    });
});

// Create user route
app.post('/users', (req, res) => {
  // Check if user is authenticated
  if (!req.isAuthenticated()) {
    return res.sendStatus(401);
  }

  // Create new user in SCIM API server using OIDC access token
  axios
    .post(scimAPIEndpoint, req.body, {
      headers: {
        Authorization: `Bearer ${req.session.accessToken}`,
      },
    })
    .then((response) => {
      res.sendStatus(201);
    })
    .catch((error) => {
      console.error(error);
      res.sendStatus(500);
    });
});

// Update user route
app.put('/users/:id', (req, res) => {
  // Check if user is authenticated
  if (!req.isAuthenticated()) {
    return res.sendStatus(401);
  }

  // Update user in SCIM API server using OIDC access token
  axios
    .put(`${scimAPIEndpoint}/${req.params.id}`, req.body, {
      headers: {
        Authorization: `Bearer ${req.session.accessToken}`,
      },
    })
    .then((response) => {
      res.sendStatus(200);
    })
    .catch((error) => {
      console.error(error);
      res.sendStatus(500);
    });
});

// Delete user route
app.delete('/users/:id', (req, res) => {
  // Check if user is authenticated
  if (!req.isAuthenticated()) {
    return res.sendStatus(401);
  }

  // Delete user from SCIM API server using OIDC access token
  axios
    .delete(`${scimAPIEndpoint}/${req.params.id}`, {
      headers: {
        Authorization: `Bearer ${req.session.accessToken}`,
      },
    })
    .then((response) => {
      res.sendStatus(204);
    })
    .catch((error) => {
      console.error(error);
      res.sendStatus(500);
    });
});

// Start the server
app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
```

Please note that this code assumes you have installed the required dependencies (`express`, `express-session`, `passport`, `passport-openidconnect`, and `axios`). It also assumes you have set up the necessary routes and endpoints on your SCIM API server.

## Midleware 

To implement role-based access control (RBAC) in the SCIM API server, you can use middleware functions to enforce authorization based on the user's role. Here's an example code snippet using the Express framework:

```javascript
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
```

In this example, the `checkRole` middleware function checks if the authenticated user has the required role to access a particular route. If the user has the required role, the middleware calls the `next` function to proceed to the next middleware or route handler. If the user doesn't have the required role, a 403 Forbidden response is sent.

You can assign roles to users during user creation or update, and store the role information in the user's profile or database. When a user makes a request to a protected route, the `checkRole` middleware can retrieve the user's role and compare it with the required role for that route.

Note that this code assumes that you have already implemented authentication using OIDC and obtained the user's profile, including their role, during the authentication process.

## App Demo ( Midleware Function ) 

To enhance the OIDC authentication flow by implementing support for refresh tokens, you can modify the existing code in your web application. Here's an example of how you can handle token expiration and automatically refresh the access token using the refresh token:

```javascript
// Import necessary libraries and modules
const express = require('express');
const axios = require('axios');
const { Issuer, Strategy } = require('openid-client');

// Initialize the Express app
const app = express();

// OIDC configuration
const oidcConfig = {
  issuer: 'https://your-oidc-provider.com',
  client_id: 'your-client-id',
  client_secret: 'your-client-secret',
  redirect_uri: 'http://localhost:3000/callback',
  scope: 'openid profile',
};

// Initialize the OpenID Connect client
let oidcClient;

async function initializeOIDCClient() {
  const issuer = await Issuer.discover(oidcConfig.issuer);
  oidcClient = new issuer.Client({
    client_id: oidcConfig.client_id,
    client_secret: oidcConfig.client_secret,
    redirect_uris: [oidcConfig.redirect_uri],
    response_types: ['code'],
  });
}

// Middleware to check if the access token is expired and refresh it
async function checkTokenExpiration(req, res, next) {
  if (!req.session.tokenSet) {
    // Redirect to the login page if no token is found
    res.redirect('/login');
    return;
  }

  const { expired, claims } = req.session.tokenSet;

  if (expired()) {
    try {
      // Use the refresh token to obtain a new access token
      const refreshedTokenSet = await oidcClient.refresh(req.session.tokenSet);

      // Update the session with the new token set
      req.session.tokenSet = refreshedTokenSet;

      // Continue with the next middleware or route handler
      next();
    } catch (error) {
      // Handle the error, e.g., redirect to the login page
      res.redirect('/login');
    }
  } else {
    // Continue with the next middleware or route handler
    next();
  }
}

// Login route
app.get('/login', (req, res) => {
  const authUrl = oidcClient.authorizationUrl({
    scope: oidcConfig.scope,
    response_mode: 'form_post',
  });

  res.redirect(authUrl);
});

// Callback route
app.post('/callback', async (req, res) => {
  const params = oidcClient.callbackParams(req);
  const tokenSet = await oidcClient.callback(oidcConfig.redirect_uri, params, {
    response_type: 'code',
  });

  // Store the token set in the session
  req.session.tokenSet = tokenSet;

  // Redirect to the home page or any other protected route
  res.redirect('/');
});

// Protected route that requires authentication
app.get('/', checkTokenExpiration, async (req, res) => {
  // Access token can be used to authenticate requests to the SCIM API server
  const accessToken = req.session.tokenSet.access_token;

  // Make authenticated requests to the SCIM API server using the access token
  // Example: Retrieve user information from the SCIM server
  const userResponse = await axios.get('https://your-scim-server.com/users', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  // Example: Create a new user using the SCIM API server
  const newUser = {
    username: 'john.doe',
    email: 'john.doe@example.com',
    // Additional user attributes...
  };

  const createUserResponse = await axios.post('https://your-scim-server.com/users', newUser, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  // Example: Update user attributes using the SCIM API server
  const updatedUser = {
    email: 'john.doe@example.org',
    // Updated user attributes...
  };

  const updateUserResponse = await axios.patch('https://your-scim-server.com/users/{userId}', updatedUser, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  // Example: Delete a user using the SCIM API server
  const deleteUserResponse = await axios.delete('https://your-scim-server.com/users/{userId}', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  // Handle the responses and send the appropriate response to the client
  res.send('Authenticated and authorized!');
});

// Start the server
app.listen(3000, () => {
  console.log('Server started on http://localhost:3000');
});

// Initialize the OIDC client
initializeOIDCClient();
```

Please note that this code assumes you have already set up the necessary dependencies and middleware (e.g., express-session) for session management. Also, make sure to replace the placeholder values (`https://your-oidc-provider.com`, `your-client-id`, `your-client-secret`, `http://localhost:3000/callback`, `https://your-scim-server.com`, `{userId}`, etc.) with the actual values from your OIDC provider and SCIM server.

This code demonstrates how to handle token expiration and automatically refresh the access token using the refresh token in the OIDC authentication flow.

## SCIM API Server Demo 

```javascript
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());

// Sample user data
let users = [
  {
    id: '1',
    username: 'john.doe',
    password: '$2b$10$Q7T6K8fXeD9cZQy4Lk8F7e2E9OJZC6uOqY9nO3I4K6nvV0ZzFJr1m', // hashed password: 'password'
    email: 'john.doe@example.com',
    roles: ['admin'],
  },
  {
    id: '2',
    username: 'jane.doe',
    password: '$2b$10$Q7T6K8fXeD9cZQy4Lk8F7e2E9OJZC6uOqY9nO3I4K6nvV0ZzFJr1m', // hashed password: 'password'
    email: 'jane.doe@example.com',
    roles: ['user'],
  },
];

// Middleware to authenticate requests using OIDC access token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Endpoint to reset user password
app.post('/users/:userId/reset-password', authenticateToken, (req, res) => {
  const { userId } = req.params;
  const { currentPassword, newPassword } = req.body;

  const user = users.find((user) => user.id === userId);
  if (!user) return res.sendStatus(404);

  // Check if the current password matches the stored hashed password
  bcrypt.compare(currentPassword, user.password, (err, result) => {
    if (err) return res.sendStatus(500);
    if (!result) return res.sendStatus(401);

    // Generate a new hashed password
    bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
      if (err) return res.sendStatus(500);

      // Update the user's password
      user.password = hashedPassword;
      res.sendStatus(204);
    });
  });
});

// Endpoint to change user password
app.put('/users/:userId/change-password', authenticateToken, (req, res) => {
  const { userId } = req.params;
  const { newPassword } = req.body;

  const user = users.find((user) => user.id === userId);
  if (!user) return res.sendStatus(404);

  // Generate a new hashed password
  bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
    if (err) return res.sendStatus(500);

    // Update the user's password
    user.password = hashedPassword;
    res.sendStatus(204);
  });
});

// Endpoint to enforce password complexity rules
app.post('/users/enforce-password-complexity', (req, res) => {
  const { password } = req.body;

  // Check password complexity rules (e.g., minimum length, special characters, etc.)
  // Implement your own password complexity rules here

  // Return appropriate response based on password complexity
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
  }

  // Additional complexity rules can be added here

  res.sendStatus(204);
});

// Start the server
app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In the code above, we have implemented user password management in the SCIM API server. It includes three endpoints:

1. **Reset User Password** (`POST /users/:userId/reset-password`): This endpoint allows a user to reset their password by providing their current password and a new password. The current password is compared with the stored hashed password to verify the user's identity. If the current password matches, the new password is hashed and stored as the user's new password.

2. **Change User Password** (`PUT /users/:userId/change-password`): This endpoint allows a user to change their password by providing a new password. The new password is hashed and stored as the user's new password.

3. **Enforce Password Complexity** (`POST /users/enforce-password-complexity`): This endpoint enforces password complexity rules. It validates the provided password against the defined complexity rules (e.g., minimum length, special characters, etc.). If the password meets the complexity requirements, a success response is returned. Otherwise, an error response is returned.

Please note that the code provided is a sample implementation and should be adapted to fit your specific requirements and the framework you are using.

## Management Role Demo

Here's an example of how you can implement user role management in the SCIM API server using a framework like Express:

```javascript
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
```

In this code, we have endpoints for creating, reading, updating, and deleting roles. The roles are stored in an array called `roles`. We also have a middleware function `checkRole` that checks if the user has the required role before allowing access to certain routes.

To assign roles to users, you would need to modify your user management endpoints to include a `roles` property in the user object. You can then update the user creation and update routes to handle assigning roles to users.

To enforce role-based access control on the SCIM routes, you can use the `checkRole` middleware function on the routes that require specific roles. If a user doesn't have the required role, they will receive a 403 Forbidden response.

Please note that this code is just a basic example and may need further customization based on your specific requirements.


## Implementasi MFA Demo

To enhance the OIDC authentication flow with support for multi-factor authentication (MFA), you can use the following code as an example:

```javascript
// Import necessary libraries
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy;

// Initialize the Express app
const app = express();

// Configure session middleware
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false
}));

// Configure passport
app.use(passport.initialize());
app.use(passport.session());

// Configure OIDC strategy
passport.use(new OIDCStrategy({
    identityMetadata: 'https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration',
    clientID: 'your-client-id',
    clientSecret: 'your-client-secret',
    responseType: 'code',
    responseMode: 'form_post',
    redirectUrl: 'http://localhost:3000/auth/openid/return',
    allowHttpForRedirectUrl: true,
    scope: ['openid', 'profile']
  },
  (iss, sub, profile, accessToken, refreshToken, done) => {
    // Perform additional authentication factor verification here
    // For example, prompt user for SMS verification code or biometric authentication
    // Verify the additional factor and call the 'done' function accordingly
    // If the additional factor is verified, call 'done(null, profile)' to authenticate the user
    // If the additional factor is not verified, call 'done(null, false)' to reject the authentication
    // You can also pass additional user information in the 'profile' object
    done(null, profile);
  }
));

// Serialize user object to session
passport.serializeUser((user, done) => {
  done(null, user);
});

// Deserialize user object from session
passport.deserializeUser((user, done) => {
  done(null, user);
});

// Define the authentication route
app.get('/auth/openid',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/');
  }
);

// Define the authentication callback route
app.post('/auth/openid/return',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/');
  }
);

// Define a protected route that requires MFA
app.get('/protected',
  ensureAuthenticated,
  (req, res) => {
    res.send('Protected route');
  }
);

// Middleware to ensure user is authenticated
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

// Start the server
app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

In this example, we use the `passport-azure-ad` library to implement the OIDC authentication flow. We configure the OIDC strategy with the necessary parameters, including the identity metadata, client ID, client secret, and redirect URL. 

To implement multi-factor authentication (MFA), you need to add additional logic in the OIDC strategy's callback function. This is where you can prompt the user for additional authentication factors, such as SMS verification codes or biometric authentication. You can then verify the additional factor and call the `done` function accordingly to authenticate or reject the user.

The code also includes a protected route (`/protected`) that requires the user to be authenticated. The `ensureAuthenticated` middleware is used to check if the user is authenticated before allowing access to the protected route.

Please note that this code is a basic example, and you may need to modify it to fit your specific authentication requirements and integrate it with your existing OIDC and MFA providers.
