const mongoose = require('mongoose');
require('dotenv').config();

const connectDB = async () => {
  try {
    // Use await to ensure the connection is established
    await mongoose.connect(process.env.MONGO_URI);
    console.log('MongoDB Connected');
  } catch (error) {
    console.error('MongoDB Connection Error:', error);
    process.exit(1); // Exit the process with a failure code
  }
};

module.exports = connectDB;