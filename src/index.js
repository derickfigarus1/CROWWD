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
require('dotenv').config({ path: './src/.env' });
app.use(flash());
app.use(express.json());
app.use(express.static("public"));
app.use(express.urlencoded({ extended: false }));
app.set("view engine", "ejs");
app.use(cookieParser('secret'));



mongoose.connect(process.env.MONGO_URI, )
  .then(() => console.log("mongoDB is connected"))
  .then(() => console.log("Database Connected Successfully"))
  .catch(err => console.error("Database Connection Error: ", err));


//cloudinary used for storing image in cloud
const cloudinary = require('cloudinary').v2;
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
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

//session used for collecting email of loggedin user
app.use(session({
  cookie: { maxAge: 60000 },
  secret: process.env.SESSION_SECRET || 'crowwd123',
  resave: false,
  saveUninitialized: false
}));

app.get("/", (req, res) => {
  res.render("login");
});
app.get("/register", (req, res) => {
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
    if (data.password !== data.c_password) {
      res.render("register", { message: 'Passwords do not match.' });
    }
        // Check if the username already exists in the database
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
    // Compare the hashed password from the database with the plain text password
    const isPasswordMatch = await bcrypt.compare(req.body.password, check.password);
    if (!isPasswordMatch) {
      return res.render('login', { errorMessage: "Wrong Password!" });
    }
    // Fetch ranked events before rendering the home view
    const userEmail = req.session.email; // Get the current session's email
    const events = await Image.find({ email: userEmail }); // Fetch events by email
    const images = await Image.find({}, { imagePath: 1, _id: 0 });
    const rankedEvents = await getRankedEvents();
    
    req.session.email = check.email;
    req.session.name = check.name; // Set the user's name in the session
    if (check.user_type === 'admin') {
      res.render('admin', { name: check.name, events: events });
    } else {
      res.render('home', { name: check.name, rankedEvents: rankedEvents, images: images });
      console.log( req.session.email)
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
          from: 'tickets', 
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
          imagePath: 1,
          dropdown2: 1,
          datePicker: 1,
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
    throw error; 
  }
}

//Admin page
// Define a schema for the images collection
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
  },
  clicks: {
    type: Number,
    default: 0 
  }
});
// Create a model from the schema
const Image = mongoose.model('Image', imageSchema);
app.post('/submit', upload.single('imageUploader'), async (req, res) => {
  try {
    // Upload the image to Cloudinary
    const result = await cloudinary.uploader.upload(req.file.path);
    const imagePath = result.secure_url;
    const userEmail = req.session.email;
    const events = await Image.find({ email: userEmail });
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
    res.redirect('/admin');
  } catch (error) {
    console.error(error);
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

app.get('/admin', async (req, res) => {
  const name = req.session.name || 'Guest';
  const userEmail = req.session.email; // Get the current session's email
  const events = await Image.find({ email: userEmail }); // Fetch events by email
  res.locals.messages = req.flash();
  res.render('admin', { name: name, events: events }); 
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
//searching the database for texts
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
    const eventId = req.params.id;
    const event = await Image.findById(eventId);
    const email = req.session.email; // Get the email from the session

    if (!event) {
      return res.status(404).send('Event not found');
    }
    // Fetch similar events
    const similarEvents = await Image.find({
      dropdown1: event.dropdown1,
      _id: { $ne: eventId } // Exclude the current event
    });
    res.render('event-details', { event: event, similarEvents: similarEvents });
  } catch (error) {
    console.error(error);
  }
});

app.post('/book-event/:id', async (req, res) => {
  try {
     const eventId = req.params.id;
     const quantity = parseInt(req.body.quantity, 10);
 
     if (isNaN(quantity) || quantity <= 0) {
       return res.status(400).send('Invalid quantity.');
     }
 
     const event = await Image.findById(eventId);
     if (!event) {
       return res.status(404).send('Event not found');
     }
     console.log(req.session.email)
     const userEmail = req.session.email; 
     console.log('Email from session:', userEmail);
     const user = await User.findOne({ email: userEmail });
     console.log('User found:', user);

     if (!user) {
       return res.status(404).send('User not found');
     }
 
     const newBooking = new Booking({
       user: user._id, 
       event: eventId,
       quantity: quantity,
       bookingId: `${eventId}-${user._id}`,
       email: userEmail 
     });
 
     await newBooking.save();
  } catch (error) {
     console.error(error);
     res.status(500).send('Server error');
  }
 });
 

app.get('/filter-events', async (req, res) => {
  const dropdown1Value = req.query.dropdown1;
  const events = await Image.find({ dropdown1: dropdown1Value });
  res.render('events', { events: events });
});


const qrCodeSchema = new mongoose.Schema({
  uniqueId: {
    type: String,
    required: true,
    unique: true
  },
});

const QRCode = mongoose.model('QRCode', qrCodeSchema);
const userSchema = new mongoose.Schema({
  email: String,
  name: String,
  // other fields as necessary
 });
 
 const User = mongoose.model('User', userSchema);
const bookingSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User', 
    required: true
  },
  event: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Image', 
    required: true
  },
  quantity: {
    type: Number,
    required: true
  },
  bookingId: {
    type: String,
    required: true,
    unique: true
  },
  email: { 
     type: String,
     required: true
  }
});

const Booking = mongoose.model('Booking', bookingSchema); 

app.post('/event-click', async (req, res) => {
  try {
    const { eventId } = req.body; 
    const query = { _id: eventId };
    await Image.findOneAndUpdate(query, { $inc: { clicks: 1 } });
  } catch (error) {
    console.error(error);
  }
});


app.get('/profile', async (req, res) => {
  try {
    const userEmail = req.session.email;
    const bookedEvents = await Booking.find({ email: userEmail }).populate('event');
    res.render('profile', { bookedEvents: bookedEvents });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});