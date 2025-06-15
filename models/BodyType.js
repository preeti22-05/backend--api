const mongoose = require('mongoose');

const bodyTypeSchema = new mongoose.Schema({
  name: { type: String, required: true }, // e.g., "Pear", "Hourglass"
  description: { type: String },
});

module.exports = mongoose.model('BodyType', bodyTypeSchema);