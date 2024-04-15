const express = require("express");
const session = require('express-session');
const path = require("path");
const collection = require("./config");
const bcrypt = require('bcrypt');
const multer = require('multer');
const mongoose = require('mongoose');
const crypto = require('crypto');
const app = express();
const dotenv = require("dotenv");
const cookieParser = require('cookie-parser');
const flash = require('connect-flash');
//point to connection string
require('dotenv').config({ path: './src/.env' });
//cloudinary used for storing image in cloud
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
//connection string
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
 .then(() => console.log("mongoDB is connected"))
  .then(() => console.log("Database Connected Successfully"))
  .catch(err => console.error("Database Connection Error: ", err));
//session used for collecting email of loggedin user
app.use(cookieParser('secret'));
app.use(session({
  cookie: { maxAge: 60000 },
  secret: process.env.SESSION_SECRET || 'crowwd123',
  resave: false,
  saveUninitialized: false
}));
app.use(flash());
// convert data into json format
app.use(express.json());
app.use(express.static("public"));
app.use(express.urlencoded({ extended: false }));
app.set("view engine", "ejs");
app.get("/", (req, res) => {
  res.render("login");
});
app.get("/register", (req, res) => {
  // Pass an empty string as the default message
  res.render("register", { message: "" });
 });
 
//register page
app.post("/register", async (req, res) => {
  try {
     const data = {
       name: req.body.name,
       email: req.body.email,
       password: req.body.password,
       c_password: req.body.c_password,
       user_type: req.body.user_type
     };
     // Check if the username already exists in the database
     if (data.password !== data.c_password) {
       res.render("register", { message: 'Passwords do not match.' });
     }
     const existingUser = await collection.findOne({ email: data.email });
     if (existingUser) {
       res.render("register", { message: 'User already exists.' });
     }
     // Hash the password using bcrypt
     const saltRounds = 10;
     const hashedPassword = await bcrypt.hash(data.password, saltRounds);
     const newUser = new collection({
       name: data.name,
       email: data.email,
       password: hashedPassword,
       user_type: data.user_type
     });
     // Save the user to the database
     await newUser.save();
     console.log("User registered successfully.");
     res.render("register", { message: 'User registered successfully.' });
  } catch (error) {
     console.error(error);
     res.render("register", { message: 'An error occurred while registering user.' });
    }
 });
// Login user 
app.post("/login", async (req, res) => {
 try {
    const check = await collection.findOne({ email: req.body.email });
    if (!check) {
      return res.render('login', { errorMessage: "User name cannot found!" });
    }
    // Compare the hashed password from the database with the plaintext password
    const isPasswordMatch = await bcrypt.compare(req.body.password, check.password);
    if (!isPasswordMatch) {
      return res.render('login', { errorMessage: "Wrong Password!" });
    }
    // Fetch ranked events before rendering the home view
    const rankedEvents = await getRankedEvents();
    req.session.email = check.email;
    req.session.name = check.name; // Set the user's name in the session
    if (check.user_type === 'admin') {
      // Redirect to admin.html
      res.render('admin', { name: check.name });
    } else {
      res.render('home', { name: check.name, rankedEvents: rankedEvents });
    }
 } catch (error) {
    console.error(error);
    res.render('login', { errorMessage: "An error occurred during login." });
 }
});

async function getRankedEvents() {
 try {
    const topEvents = await Image.aggregate([
      {
        $lookup: {
          from: 'tickets', // Assuming 'tickets' is the collection name for Ticket model
          localField: '_id',
          foreignField: 'eventId',
          as: 'ticketInfo'
        }
      },
      {
        $unwind: '$ticketInfo'
      },
      {
        $project: {
          textbox4: 1,
          dropdown2: 1,
          datePicker:1,
          totalTickets: 1,
          ticketInfo: 1,
          percentage: {
            $multiply: [
              { $divide: ['$totalTickets', '$ticketInfo.totalTickets'] },
              100
            ]
          }
        }
      },
      {
        $sort: {
          percentage: -1
        }
      },
      {
        $limit: 6
      }
    ]);

    return topEvents;
 } catch (error) {
    console.error(error);
    throw error; // Rethrow the error to handle it in the calling function
 }
}

//Admin page
// Define a schema for the images collection
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
// Create a model from the schema
const Image = mongoose.model('Image', imageSchema); 
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
      totalTickets = 0; // Defau
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
       totalTickets: totalTickets // Assuming you have a new input field for total tickets
     });
 
     await image.save();
 
     // Create a new ticket document for the event
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
 

 
app.get('/admin', (req, res) => {
    const name = req.session.name || 'Guest';
    res.locals.messages = req.flash();
    res.render('admin', { name: name });
  });
  //searching for events that match date and location selected
app.post('/search-events-by-date-and-location', async (req, res) => {
    const { fromDate, toDate, location } = req.body;
    const from = new Date(fromDate);
    const to = new Date(toDate);
    const events = await Image.find({
        datePicker: { $gte: from, $lte: to },
        dropdown2: location
    });
    res.render('events', { events: events });
});
//searching the database for words
app.post('/search-events', async (req, res) => {
    const searchQuery = req.body.searchQuery;
    const events = await Image.find({
        $or: [
            { textbox1: { $regex: searchQuery, $options: 'i' } },
            { textbox4: { $regex: searchQuery, $options: 'i' } },
            { textbox5: { $regex: searchQuery, $options: 'i' } },
            { textbox6: { $regex: searchQuery, $options: 'i' } },
            { textbox7: { $regex: searchQuery, $options: 'i' } },
            { textbox8: { $regex: searchQuery, $options: 'i' } },
        ]
    });
    res.render('events', { events: events });
});

app.get('/event/:id', async (req, res) => {
  try {
     // Extract the event ID from the request parameters
     const eventId = req.params.id;
 
     // Find the event in the database using the provided ID
     const event = await Image.findById(eventId);
 
     // If the event is not found, send a 404 response
     if (!event) {
       return res.status(404).send('Event not found');
     }
 
     // Render the event details view, passing the event data
     res.render('event-details', { event: event });
  } catch (error) { 
     console.error(error);
     res.status(500).send('Server error');
  }
 });
 app.post('/book-event/:id', async (req, res) => {
  try {
      const eventId = req.params.id;
      const quantity = parseInt(req.body.quantity, 10); // Ensure to parse the quantity as an integer
 
      // Check if quantity is a valid number
      if (isNaN(quantity) || quantity <= 0) {
        return res.status(400).send('Invalid quantity.');
      }
 
      // Find the event by its ID
      const event = await Image.findById(eventId);
      if (!event) {
        return res.status(404).send('Event not found');
      }
 
      // Subtract the quantity from the totalTickets
      const updatedTotalTickets = event.totalTickets - quantity;
 
      // Update the event with the new totalTickets value
      await Image.updateOne({ _id: eventId }, { totalTickets: updatedTotalTickets });
 
      // Redirect or send a response indicating success
      res.redirect('/success'); // Assuming you have a success page
  } catch (error) {
      console.error(error);
      res.status(500).send('An error occurred while booking the event.');
  }
 });

// Assuming you have already defined your Image and Ticket models

// Assuming you have already defined your Image and Ticket models

 
 




 
// Define Port for Application
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});