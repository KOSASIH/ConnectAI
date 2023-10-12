const express = require('express');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');

const app = express();

// Generate a unique activation token for each new user
function generateActivationToken() {
  return uuidv4();
}

// Send the activation email to the user
function sendActivationEmail(email, activationToken) {
  // Configure the email transport
  const transporter = nodemailer.createTransport({
    // Specify your email service provider details here
    // For example, if using Gmail, you would provide SMTP details
    // host: 'smtp.gmail.com',
    // port: 587,
    // secure: false,
    // auth: {
    //   user: 'your-email@gmail.com',
    //   pass: 'your-email-password',
    // },
  });

  // Define the email options
  const mailOptions = {
    from: 'your-email@gmail.com',
    to: email,
    subject: 'Account Activation',
    text: `Click the following link to activate your account: http://your-website.com/activate/${activationToken}`,
    html: `<p>Click the following link to activate your account: <a href="http://your-website.com/activate/${activationToken}">Activate Account</a></p>`,
  };

  // Send the email
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log('Error sending activation email:', error);
    } else {
      console.log('Activation email sent:', info.response);
    }
  });
}

// Handle the activation callback route
app.get('/activate/:token', (req, res) => {
  const { token } = req.params;

  // TODO: Verify the activation token against your database or storage

  // TODO: Activate the user account in your database or storage

  res.send('Account activated successfully');
});

// Handle user registration route
app.post('/register', (req, res) => {
  const { email } = req.body;

  // TODO: Save the user details in your database or storage

  // Generate an activation token
  const activationToken = generateActivationToken();

  // Send the activation email to the user
  sendActivationEmail(email, activationToken);

  res.send('Registration successful. Please check your email for activation instructions.');
});

// Start the server
app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});
