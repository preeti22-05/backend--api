const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  username: { type: String, required: true },
  verifyOtp: { type: String }, // Field to store the OTP
  otpExpiration: { type: Date }, // Field to store the OTP expiration time
  isVerified: { type: Boolean, default: false }, // Field to track if the user is verified
  verificationToken: { type: String }, // Field to store the verification token
  verificationExpires: { type: Date }, // Field to store the verification token expiration time
  measurements: {
    height: { type: Number },
    weight: { type: Number },
    bust: { type: Number },
    waist: { type: Number },
    hip: { type: Number },
    shoulderWidth: { type: Number },
  },
  bodyType: { type: String },
  selectedEvent: { type: String }, // Add this field
});

module.exports = mongoose.model('User', userSchema);