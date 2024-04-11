const express = require("express");
const session = require('express-session');
const path = require("path");
const collection = require("./config");
const bcrypt = require('bcrypt');
const multer = require('multer');
//const { MongoClient } = require('mongodb');
const mongoose = require('mongoose');
const crypto = require('crypto');
const app = express();
const dotenv = require("dotenv");


require('dotenv').config({ path: './src/.env' });


const upload = multer({ 
    dest: 'uploads/', // Specify the destination folder for uploaded images
    storage: multer.diskStorage({ // Define multer storage
        destination: function (req, file, cb) {
            cb(null, 'uploads/'); // Destination folder
        },
        filename: function (req, file, cb) {
            cb(null, file.originalname); // Use the original file name
        }
    })
});

//connection to mongodb mongoose.connect("mongodb+srv://arunmanoj005:ioc8Yl567WUcMv02@cluster1.zm5fy5d.mongodb.net/", { useNewUrlParser: true, useUnifiedTopology: true })
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
 .then(() => console.log("mongoDB is connected"))
  .then(() => console.log("Database Connected Successfully"))
  .catch(err => console.error("Database Connection Error: ", err));

//session used for collecting email of loggedin user
app.use(session({
    secret: 'mykey123',
    resave: false,
    saveUninitialized: true
  }));

// convert data into json format
app.use(express.json());
//1 line today
//app.use(cors());

app.use(express.static("public"));
app.use(express.urlencoded({ extended: false }));
app.set("view engine", "ejs");
app.get("/", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

// Register User
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
    res.send('User registered successfully.');
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
      if (check.user_type === 'admin') {
        // Redirect to admin.html
        res.render('admin',{name:check.name});
        req.session.email = check.email;
        //res.sendFile(path.join(__dirname, '../views/admin.ejs'));
      } else {
        req.session.email = check.email;
        res.render('home',{name:check.name});
        req.session.email = check.email;    }
  }
}
  catch {
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
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.post('/submit', upload.single('imageUploader'), async (req, res) => {
  try {
    const userEmail = req.session.email;
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
      datePicker: new Date(req.body.datePicker),
      dropdown1: req.body.dropdown1,
      dropdown2: req.body.dropdown2,
      imagePath: `/uploads/${req.file.filename}`
    });
    await image.save();
    res.send('Image uploaded successfully');
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});
app.get('/', (req, res) => {
  res.render('admin');
});


// Define Port for Application
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});