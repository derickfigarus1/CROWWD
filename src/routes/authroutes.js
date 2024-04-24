const express = require("express");
const collection = require("../config");
const bcrypt = require('bcrypt');
const Image = require("../models/image");
const session = require('express-session');
const cookieParser = require('cookie-parser');
const flash = require('connect-flash');

const app = express();

app.use(cookieParser('secret'));
const database=require("../database")
const router = express.Router();





app.use(session({
  cookie: { maxAge: 60000 },
  secret: process.env.SESSION_SECRET || 'crowwd123',
  resave: false,
  saveUninitialized: false
}));
app.use(flash());
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
     const images = await Image.find({}, { imagePath: 1, _id: 0 });
     const rankedEvents = await getRankedEvents();
     req.session.email = check.email;
     req.session.name = check.name; // Set the user's name in the session
     if (check.user_type === 'admin') {
       // Redirect to admin.html
       res.render('admin', { name: check.name });
     } else {
       res.render('home', { name: check.name, rankedEvents: rankedEvents ,images: images}); 
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
          imagePath:1,
          dropdown2: 1,
          datePicker:1,
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











   //reg
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
  
   
   module.exports = router;
