const mongoose = require('mongoose');

const imageSchema = new mongoose.Schema({
  email: String,
  textbox1: String,
  textbox2: String,
  textbox3: String,
  textbox4: String,
  textbox5: String,
  textbox6: String,
  textbox7: String,
  textbox8: String,
  textbox9: String,
  datePicker: Date,
  dropdown1: String,
  dropdown2: String,
  imagePath: String,
  totalTickets: {
    type: Number,
    required: true
  }
});

const Image = mongoose.model('Image', imageSchema);

module.exports = Image;
