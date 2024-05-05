const mongoose = require('mongoose');

// Create Schema
const Loginschema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    user_type: {
        type: String,
        required: true
    },
    ac_number: { // New field
        type: String,
        required: false // Adjust based on whether this field is mandatory
    },
    ifsc_code: { // New field
        type: String,
        required: false // Adjust based on whether this field is mandatory
    },
    aadhar_no: { // New field
        type: String,
        required: false // Adjust based on whether this field is mandatory
    }
});

// collection part
const collection = mongoose.model("users", Loginschema);

module.exports = collection;
