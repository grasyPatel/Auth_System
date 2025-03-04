const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const User = require('../models/User');
const authMiddleware = require('../middleware/auth');
const router = express.Router();
const sendEmail = require('../utils/sendEmail');
const crypto = require('crypto');

// Role-Based Access Middleware
const roleMiddleware = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ msg: 'Access denied: Insufficient permissions' });
    }
    next();
  };
};

// ✅ Signup Route
router.post('/signup', [
  check('name', 'Name is required').not().isEmpty(),
  check('email', 'Enter a valid email').isEmail(),
  check('password', 'Password must be at least 6 characters').isLength({ min: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { name, email, password, role } = req.body; // Role added

  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: 'User already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({ 
      name, 
      email, 
      password: hashedPassword, 
      role: role || 'user' // ✅ Default role is "user"
    });

    await user.save();

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(201).json({ msg: 'User registered successfully', token });

  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// ✅ Login Route
router.post('/login', [
  check('email', 'Enter a valid email').isEmail(),
  check('password', 'Password is required').exists()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ msg: 'Login successful', token, role: user.role });

  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});
// Forgot Password Route
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ msg: 'User not found' });
  
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetUrl = `http://localhost:3000/reset-password/${resetToken}`;
  
    await sendEmail(email, 'Password Reset', `Click here to reset password: ${resetUrl}`);
  
    res.json({ msg: 'Password reset email sent' });
  });

// ✅ Protected Route (Only logged-in users)
router.get('/protected', authMiddleware, (req, res) => {
  res.json({ msg: 'This is a protected route', user: req.user });
});

// ✅ Admin-Only Route
router.get('/admin', authMiddleware, roleMiddleware(['admin']), (req, res) => {
  res.json({ msg: 'Admin access granted' });
});

// ✅ Route for both User & Admin
router.get('/dashboard', authMiddleware, roleMiddleware(['user', 'admin']), (req, res) => {
  res.json({ msg: `Welcome, ${req.user.role}` });
});

module.exports = router;
