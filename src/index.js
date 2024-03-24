const express = require("express");
const path = require("path");
const collection = require("./config");
const bcrypt = require('bcrypt');

const app = express();
// convert data into json format
app.use(express.json());
// Static file
app.use(express.static("public"));

app.use(express.urlencoded({ extended: false }));
//use EJS as the view engine
app.set("view engine", "ejs");

app.get("/", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

// Register User
app.post("/register", async (req, res) => {

    const data = {
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        c_password: req.body.c_password
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

        // Create a new user object with hashed password
        const newUser = new collection({
            name: data.name,
            email: data.email,
            password: hashedPassword
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
            res.render("home");
        }
    }
    catch {
        res.send("wrong Details");
    }
});


// Define Port for Application
const port = 5000;
app.listen(port, () => {
    console.log(`Server listening on port ${port}`)
});