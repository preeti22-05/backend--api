const express = require('express');
const router = express.Router();
const BodyType = require('../models/BodyType'); // Ensure this path is correct

// Example route
router.get('/', async (req, res) => {
  try {
    const bodyTypes = await BodyType.find();
    res.json(bodyTypes);
  } catch (error) {
    console.error('Error fetching body types:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;