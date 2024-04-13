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
//point to connection steing
require('dotenv').config({ path: './src/.env' });
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
  res.render("register");
});
app.post("/register", async (req, res) => {
  console.log(req.body);
  const data = {
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    c_password: req.body.c_password,
    user_type:req.body.user_type
  }
  // Check if the username already exists in the database
  if (data.password !== data.c_password) {
    return res.send('Password and confirm password do not match.');
  }
  const existingUser = await collection.findOne({ email: data.email });
  if (existingUser) {
    res.send('User already exists. Please choose a different email.');
  } 
  try {
    // Hash the password using bcrypt
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(data.password, saltRounds);
    const newUser = new collection({
      name: data.name,
      email: data.email,
      password: hashedPassword,
      user_type:data.user_type
    });
    // Save the user to the database
    await newUser.save();
    console.log("User registered successfully.");
res.render("register", { message: 'User registered successfully.' });
  } catch (error) {
    console.error(error);
    res.status(500).send('An error occurred while registering user.');
  }
});
// Login user 
app.post("/login", async (req, res) => {
  try {
    const check = await collection.findOne({ email: req.body.email });
    if (!check) {
      res.send("User name cannot found")
    }
    // Compare the hashed password from the database with the plaintext password
    const isPasswordMatch = await bcrypt.compare(req.body.password, check.password);
    if (!isPasswordMatch) {
      res.send("wrong Password");
    }
   else {
    req.session.email = check.email;
    req.session.name = check.name; // Set the user's name in the session
    if (check.user_type === 'admin') {
      // Redirect to admin.html
      res.render('admin', { name: check.name });
    } else {
      res.render('home', { name: check.name });
    }
  }
} catch {
  res.send("wrong Details");
}
});
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
  imagePath: String
});
// Create a model from the schema
const Image = mongoose.model('Image', imageSchema); 
app.post('/submit', upload.single('imageUploader'), async (req, res) => {
  try {
    const userEmail = req.session.email;
    const date = new Date(req.body.datePicker);
    const day = date.getDate().toString().padStart(2, '0');
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const year = date.getFullYear();
    const formattedDate = `${year}-${month}-${day}`;
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
      imagePath: `/uploads/${req.file.filename}`
    });
    await image.save();
    req.flash('message', 'Event registered successfully.');
    res.redirect('/admin'); // Redirect to the admin page
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});
app.get('/admin', (req, res) => {
    const name = req.session.name || 'Guest';
    res.locals.messages = req.flash();
    res.render('admin', { name: name });
  });
app.post('/search-events-by-date-and-location', async (req, res) => {
    const { fromDate, toDate, location } = req.body;
    // Convert the dates to Date objects for comparison
    const from = new Date(fromDate);
    const to = new Date(toDate);
    // Perform a search in the database
    const events = await Image.find({
        datePicker: { $gte: from, $lte: to },
        dropdown2: location
    });
    // Render the events page with the search results
    res.render('events', { events: events });
});

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
app.get('/event-details', function(req, res) { res.render('event-details'); });


// Define Port for Application
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});