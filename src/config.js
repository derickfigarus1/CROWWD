const mongoose = require('mongoose');

// Check database connected or not


// Create Schema
const Loginschema = new mongoose.Schema({
    name: {
        type:String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type:String,
        required: true
    },
    user_type: {
        type:String,
        required: true
    },
});

// collection part
const collection = new mongoose.model("users", Loginschema);

module.exports = collection;
