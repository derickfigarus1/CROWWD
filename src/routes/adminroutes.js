const express = require("express");
const multer = require('multer');
const mongoose = require('mongoose');

const Image = require('../models/image'); // Adjust the path as necessary
const router = express.Router();

const app = express()

const cloudinary = require('cloudinary').v2;
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key:process.env.API_KEY,
  api_secret: process.env.API_SECRET
});
//multer library used for image storing middleware
const upload = multer({ 
    storage: multer.diskStorage({
        destination: function (req, file, cb) {
            cb(null, path.join(__dirname, '../public/uploads/')); // Destination folder
        },
        filename: function (req, file, cb) {
            cb(null, file.originalname); 
        }
    })
});

const imageSchema = new mongoose.Schema({
      email:String,
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
app.post('/submit', upload.single('imageUploader'), async (req, res) => {
      try {
        // Upload the image to Cloudinary
        const result = await cloudinary.uploader.upload(req.file.path);
        // Use the URL from Cloudinary for the imagePath
        const imagePath = result.secure_url;
         const userEmail = req.session.email;
         const date = new Date(req.body.datePicker);
         const day = date.getDate().toString().padStart(2, '0');
         const month = (date.getMonth() + 1).toString().padStart(2, '0');
         const year = date.getFullYear();
         const formattedDate = `${year}-${month}-${day}`;
         let totalTickets = parseInt(req.body.totalTickets, 10);
        if (isNaN(totalTickets)) {
          totalTickets = 0; 
        }
         const image = new Image({
           email: userEmail,
           textbox1: req.body.textbox1,
           textbox2: req.body.textbox2,
           textbox3: req.body.textbox3,
           textbox4: req.body.textbox4,
           textbox5: req.body.textbox5,
           textbox6: req.body.textbox6,
           textbox7: req.body.textbox7,
           textbox8: req.body.textbox8,
           textbox9: req.body.textbox9,
           datePicker: formattedDate,
           dropdown1: req.body.dropdown1,
           dropdown2: req.body.dropdown2,
           imagePath: imagePath,
           totalTickets: totalTickets 
         });
     
         await image.save();
          const newTicket = new Ticket({
           eventId: image._id,
           totalTickets: req.body.totalTickets
         });
         await newTicket.save();
         req.flash('message', 'Event registered successfully.');
         res.redirect('/admin'); // Redirect to the admin page
      } catch (error) {
         console.error(error);
         res.status(500).send('Server error');
      }
     });
    
     const ticketSchema = new mongoose.Schema({
      eventId: {
         type: mongoose.Schema.Types.ObjectId,
         ref: 'Image',
         required: true
      },
      totalTickets: {
         type: Number,
         required: true
      }
     });
     const Ticket = mongoose.model('Ticket', ticketSchema);
// Define a route for the admin dashboard
router.get('/', (req, res) => {
    const name = req.session.name || 'Guest';
    res.locals.messages = req.flash();
    res.render('admin', { name: name });
});

// Export the router to be used in other files
module.exports = router;
