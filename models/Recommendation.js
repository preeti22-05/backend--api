// models/Recommendation.js
const mongoose = require('mongoose');

const recommendationSchema = new mongoose.Schema({
  bodyType: { type: String, required: true }, // e.g., Pear, Apple, Hourglass, Rectangle
  eventType: { type: String, required: true }, // e.g., casual, formal, business
  image: { type: String, required: true }, // Path to the image file
  tip: { type: String, required: true }, // Styling tip
});

module.exports = mongoose.model('Recommendation', recommendationSchema);