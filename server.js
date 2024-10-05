const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');

// Initialize app
const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MongoDB connection
const dbURI = "mongodb://localhost:27017/"; // Database name: tiktik_time
mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected...'))
    .catch(err => console.error('Database connection error:', err));

// JWT Secret Key
const JWT_SECRET = '348bd58d5cfdc514985a7549935c7c33ac0109d028680721156deaf5055c9e2bcdb0a0a6dfa7307bd7df012b7e4cf39c5178263a23c9a55c8c372a58ace5efef'; // Replace with a more secure key in production

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// Payment Schema
const paymentSchema = new mongoose.Schema({
    name: String,
    email: String,
    contact: String,
    address: String,
    pincode: String
});
const Payment = mongoose.model('Payment', paymentSchema);

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).send('No token provided.');

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send('Invalid token.');
        req.user = user;
        next();
    });
};

// Register Route
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;

    // Check if user already exists
    const userExists = await User.findOne({ username });
    if (userExists) {
        return res.status(400).send({ message: 'Username already exists.' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({ username, password: hashedPassword });
    newUser.save()
        .then(() => res.status(201).send({ message: 'Registration successful!' }))
        .catch(err => res.status(500).send({ message: 'Error registering user.', error: err }));
});

// Login Route
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ username });
    if (!user) {
        return res.status(400).send({ message: 'Invalid username or password.' });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).send({ message: 'Invalid username or password.' });
    }

    // Generate JWT
    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    res.status(200).send({ message: 'Login successful!', token });
});

// Payment Route (Protected)
app.post('/api/payment', authenticateToken, (req, res) => {
    const { name, email, contact, address, pincode } = req.body;

    // Validate input
    if (!name || !email || !contact || !address || !pincode) {
        return res.status(400).send({ message: 'All fields are required.' });
    }

    const newPayment = new Payment({ name, email, contact, address, pincode });

    // Save payment to database
    newPayment.save()
        .then(() => res.status(200).send({ message: 'Payment information saved successfully!' }))
        .catch(err => res.status(500).send({ message: 'Error saving payment information.', error: err }));
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
