const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer'); // Import nodemailer
const User = require('../models/User');
const router = express.Router();
const Recommendation = require('../models/Recommendation');
require('dotenv').config();



// @route   POST api/auth/signup
// @desc    Sign up user
router.post('/signup', async (req, res) => {
  try {
    const { email, username, password } = req.body;

    // Validate inputs
    if (!email || !username || !password) {
      return res.status(400).json({ msg: "All fields are required." });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ msg: "User already exists." });
    }

    console.log("Password before hashing:", password);
const hashedPassword = await bcrypt.hash(password, 10);
console.log("Password after hashing:", hashedPassword);
    const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Generate a 6-digit verification OTP
    const verifyOtp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP
    const otpExpiration = Date.now() + 15 * 60 * 1000; // OTP valid for 15 minutes

    const newUser = new User({
      email,
      username,
      password: hashedPassword,
      verifyOtp, // Save OTP
      otpExpiration, // Save OTP expiration time
      isVerified: false, // User is not verified yet
      verificationToken, // Save verification token
      verificationExpires: Date.now() + 60 * 60 * 1000, // Token valid for 1 hour
    });

    await newUser.save();
    console.log("User created successfully:", newUser);

    // Send OTP email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Email Verification OTP',
      text: `Your OTP for email verification is: ${verifyOtp}. It is valid for 15 minutes.`,
    };

    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error sending OTP email:", error);
        return res.status(500).json({ msg: "Error sending OTP email." });
      }

      // Create a JWT token containing only the email
      const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '15m' });

      // Send the token to the frontend
      res.status(201).json({
        msg: "User created successfully. OTP sent for email verification.",
        token, // Include token in the response
      });
    });
  } catch (error) {
    console.error('Error during signup:', error);
    res.status(500).json({ msg: "Internal server error.", error: error.message });
  }
});

// @route   POST api/auth/login
// @desc    Login user
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user || !user.isVerified) {
            return res.status(401).json({ msg: "Invalid credentials or email not verified." });
        }

    // Compare the provided password with the hashed password
    console.log("Password provided during login:", password);
    console.log("Hashed password from database:", user.password);
    const isMatch = await bcrypt.compare(password, user.password);
    console.log("Password match result:", isMatch);
        if (!isMatch) {
            return res.status(401).json({ msg: "Invalid password credentials." });
        }

        // Generate JWT token
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' }); // Expire in 1 day

        // Set token as an HTTP-only cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', // Send cookies securely in production
            maxAge: 24 * 60 * 60 * 1000, // 1 day
            sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
        });

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Login Notification',
            text: `Hello ${user.username || ''},\n\nYou have successfully logged in.`,
        };

        transporter.sendMail(mailOptions, (error) => {
            if (error) console.error("Error sending email:", error);
        });

        res.json({ msg: "Login successful." });
    }
     catch (error) {
        console.error(error);
        res.status(500).json({ msg: "Server error." });
    }
});

const verifyToken = (req, res, next) => {
  console.log('Cookies received:', req.cookies);
  console.log('Headers:', req.headers);
  
  const token = req.cookies?.token;

  if (!token) {
    return res.status(401).json({ msg: "No token provided, authorization denied" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("Token verification failed:", error);
    if (error.name === 'TokenExpiredError') {
        return res.status(401).json({ msg: "Token expired. Please log in again." });
    }
    return res.status(401).json({ msg: "Invalid token" });
  }
};

// Protected route example
router.get('/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password'); // Exclude password from the result
        if (!user) {
            return res.status(404).json({ msg: "User not found" }); // Proper JSON error response
        }
        res.json(user); // Send the user profile data as JSON
    } catch (error) {
        console.error("Error in /profile:", error);
        res.status(500).json({ msg: "Server error" }); // Proper JSON error response
    }
});

router.post('/verify-email-otp', async (req, res) => {
  try {
    const { otp } = req.body;
    const token = req.headers.authorization?.split(' ')[1]; // Extract token from header

    if (!token) {
      return res.status(401).json({ msg: "No token provided." });
    }

    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const email = decoded.email;

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ msg: "User not found." });
    }

    // Check if the OTP matches and is not expired
    if (user.verifyOtp !== otp || user.otpExpiration < Date.now()) {
      return res.status(400).json({ msg: "Invalid or expired OTP." });
    }

    // Mark the user as verified
    user.isVerified = true;
    user.verifyOtp = null; // Clear the OTP
    user.otpExpiration = null; // Clear the OTP expiration
    await user.save();

    res.status(200).json({ msg: "Email verified successfully." });
  } catch (error) {
    console.error("Error during OTP verification:", error);
    res.status(500).json({ msg: "Internal server error." });
  }
});

// @route   POST api/auth/forgot-password
// @desc    Request password reset
// @route   POST api/auth/forgot-password
// @desc    Request password reset
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ msg: "User not found." });
    }

    // Generate a password reset token with the user's email
    const resetToken = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Save the reset token and its expiration time in the user document
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    // Send the reset token to the user's email
    const resetUrl = `http://localhost:3000/reset-password/${resetToken}`; // Replace with your frontend URL

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Request',
      text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
        Please click on the following link, or paste this into your browser to complete the process:\n\n
        ${resetUrl}\n\n
        If you did not request this, please ignore this email and your password will remain unchanged.\n`,
    };

    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error sending reset email:", error);
        return res.status(500).json({ msg: "Error sending reset email." });
      }

      res.status(200).json({ msg: "Password reset email sent." });
    });
  } catch (error) {
    console.error("Error during forgot password:", error);
    res.status(500).json({ msg: "Internal server error." });
  }
});

// @route   POST api/auth/reset-password/:token
// @desc    Reset password
// @route   POST api/auth/reset-password/:token
// @desc    Reset password
router.post('/reset-password/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const { newPassword } = req.body;

    console.log("Token received:", token); // Debugging

    // Verify the token and decode the email
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Decoded token:", decoded); // Debugging

    // Find the user by email and check if the token matches and is not expired
    const user = await User.findOne({
      email: decoded.email
    });

    if (!user) {
      console.log("User not found or token expired"); // Debugging
      return res.status(400).json({ msg: "Invalid or expired token." });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password and clear the reset token
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ msg: "Password reset successfully." });
  } catch (error) {
    console.error("Error during password reset:", error); // Debugging
    res.status(500).json({ msg: "Internal server error." });
  }
});

// @route   POST api/auth/save-measurements
// @desc    Save user measurements and calculate body type
router.post('/save-measurements', verifyToken, async (req, res) => {
  try {
    const { height, weight, bust, waist, hip, shoulderWidth } = req.body;

    // Validate inputs
    if (!height || !weight || !bust || !waist || !hip || !shoulderWidth) {
      return res.status(400).json({ msg: "All fields are required." });
    }

    // Calculate body type
    const bodyType = calculateBodyType(bust, waist, hip, shoulderWidth);

    // Find the user by ID and update their measurements
    const user = await User.findByIdAndUpdate(
      req.user.id, // User ID from the token
      {
        measurements: {
          height,
          weight,
          bust,
          waist,
          hip,
          shoulderWidth,
        },
        bodyType,
      },
      { new: true } // Return the updated user document
    );

    if (!user) {
      return res.status(404).json({ msg: "User not found." });
    }

    res.status(200).json({ msg: "Measurements saved successfully.", bodyType });
  } catch (error) {
    console.error("Error saving measurements:", error);
    res.status(500).json({ msg: "Internal server error." });
  }
});

// Helper function to calculate body type
function calculateBodyType(bust, waist, hip, shoulderWidth) {
  const waistToHipRatio = waist / hip;
  const bustToHipRatio = bust / hip;
  const shoulderToHipRatio = shoulderWidth / hip;

  if (waistToHipRatio < 0.75 && bustToHipRatio >= 0.9 && shoulderToHipRatio < 0.9) {
    return "Pear";
  } else if (waistToHipRatio >= 0.85 && bustToHipRatio >= 0.9 && shoulderToHipRatio >= 0.9) {
    return "Apple";
  } else if (waistToHipRatio < 0.75 && bustToHipRatio >= 0.9 && shoulderToHipRatio >= 0.9) {
    return "Hourglass";
  } else {
    return "Rectangle";
  }
}

// @route   POST api/auth/select-event
// @desc    Save user's selected event
// @route   POST api/auth/select-event
// @desc    Save user's selected event
router.post('/select-event', verifyToken, async (req, res) => {
  try {
    const { eventType } = req.body;

    // Validate input
    if (!eventType) {
      return res.status(400).json({ msg: "Event type is required." });
    }

    // Find the user by ID and update their selected event
    const user = await User.findByIdAndUpdate(
      req.user.id, // User ID from the token
      { selectedEvent: eventType },
      { new: true } // Return the updated user document
    );

    if (!user) {
      return res.status(404).json({ msg: "User not found." });
    }

    console.log("Selected event saved:", user.selectedEvent); // Debugging
    res.status(200).json({ msg: "Event selected successfully.", eventType });
  } catch (error) {
    console.error("Error selecting event:", error);
    res.status(500).json({ msg: "Internal server error." });
  }
});

// @route   GET api/auth/recommendations
// @desc    Get personalized outfit recommendations
// @route   GET api/auth/recommendations
// @desc    Get personalized outfit recommendations
router.get('/recommendations', verifyToken, async (req, res) => {
  try {
    // Find the user by ID
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ msg: "User not found." });
    }

    console.log("User body type:", user.bodyType); // Debugging
    console.log("Selected event:", user.selectedEvent); // Debugging

    // Get recommendations based on body type and selected event
    const recommendations = await Recommendation.find({
      bodyType: user.bodyType,
      eventType: user.selectedEvent,
    });

    console.log("Recommendations found:", recommendations); // Debugging

    if (recommendations.length === 0) {
      return res.status(404).json({ msg: "No recommendations available." });
    }

    res.status(200).json({ recommendations });
  } catch (error) {
    console.error("Error fetching recommendations:", error);
    res.status(500).json({ msg: "Internal server error." });
  }
});
module.exports = router;