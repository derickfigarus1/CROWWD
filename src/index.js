// Required modules

const express = require("express");
const session = require('express-session');
const path = require("path");
const bcrypt = require('bcrypt');
const fs = require('fs');
const mongoose = require('mongoose');
const crypto = require('crypto');
const axios = require('axios');
const dotenv = require("dotenv");
const cookieParser = require('cookie-parser');
const QRCode = require('qrcode');
const multer = require('multer');
const flash = require('connect-flash');
const Recaptcha = require('express-recaptcha').RecaptchaV2;
const QrCode = require('html5-qrcode');
const cors = require("cors");
const Razorpay = require("razorpay");
const MongoStore = require('connect-mongo');
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
var nodemailer = require('nodemailer');

// Initialize Express app
const app = express();

// Middleware setup
app.use(flash());
app.use(express.json());
app.use(express.static("public"));
app.use(express.urlencoded({ extended: false }));
app.set("view engine", "ejs");
app.use(cookieParser('secret'));
app.use(cors());

// Load environment variables
require('dotenv').config({ path: './src/.env' });

// Database connection
mongoose.connect(process.env.MONGO_URI,)
  .then(() => console.log("Database Connected Successfully"))
  .catch(err => console.error("Database Connection Error: ", err))

// Cloudinary configuration
const cloudinary = require('cloudinary').v2;
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET
});

// Middleware for ensuring authentication
function ensureAuthenticated(req, res, next) {
  if (req.session && req.session.email) {
    return next();
  }
  res.redirect('/');
}

// Multer configuration for file uploads
const upload = multer({
  storage: multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, path.join(__dirname, '../public/uploads/'));
    },
    filename: function (req, file, cb) {
      cb(null, file.originalname);
    }
  })
})

// Session middleware setup
app.use(session({
  cookie: { maxAge: 600000 },
  secret: process.env.SESSION_SECRET || 'crowwd123',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }), // Use MongoDB as session store

}));




app.get("/", (req, res) => {
  res.render("login");
});
app.get("/register", (req, res) => {
  res.render("register", { message: "" });
});
const Loginschema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true
  },
  contact: {
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
  ac_number: {
    type: Number,
    required: false
  },
  ifsc_code: {
    type: String,
    required: false
  },
  aadhar_no: {
    type: String,
    required: false
  }
});

const User = mongoose.model('User', Loginschema);

app.post("/register", async (req, res) => {
  try {
    const data = {
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
      c_password: req.body.c_password,
      user_type: req.body.user_type,
      ac_number: req.body['ac-number'],
      ifsc_code: req.body['ifsc-number'],
      aadhar_no: req.body['aadhar-number'],
      contact: req.body.contact
    };
    if (data.password !== data.c_password) {
      res.render("register", { message: 'Passwords do not match.' });
      return;
    }
    if (!passwordRegex.test(data.password)) {
      res.render("register", { message: 'Password must contain at least 8 characters, including at least one uppercase letter, one lowercase letter, one number, and one special character.' });
      return;
    }
    const recaptchaResponse = req.body['g-recaptcha-response'];
    const secretKey = process.env.CAPTCHA_SECRET;
    const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptchaResponse}`;
    const result = await axios.post(verificationUrl);
    const captchaData = result.data;

    if (!captchaData.success) {
      res.render('register', { message: 'reCAPTCHA validation failed. Please try again.' });
      return;
    }
    const existingUser = await User.findOne({ email: data.email });
    if (existingUser) {
      res.render("register", { message: 'User already exists.' });
    }
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(data.password, saltRounds);
    const newUser = new User({
      name: data.name,
      email: data.email,
      password: hashedPassword,
      user_type: data.user_type,
      ac_number: data.ac_number,
      ifsc_code: data.ifsc_code,
      aadhar_no: data.aadhar_no,
      contact: data.contact
    });
    await newUser.save();
    res.render("register", { message: 'User registered successfully.' });
  } catch (error) {
    console.error(error);
    res.render("register", { message: 'An error occurred while registering user.' });
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

app.post("/login", async (req, res) => {
  try {
    const check = await User.findOne({ email: req.body.email });
    if (!check) {
      return res.render('login', { errorMessage: "User name cannot found!" });
    }
    const isPasswordMatch = await bcrypt.compare(req.body.password, check.password);
    if (!isPasswordMatch) {
      return res.render('login', { errorMessage: "Wrong Password!" });
    }
    const recaptchaResponse = req.body['g-recaptcha-response'];
    const secretKey = process.env.CAPTCHA_SECRET;
    const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${recaptchaResponse}`;
    const result = await axios.post(verificationUrl);
    const data = result.data;

    req.session.email = check.email;
    const userEmail = req.session.email;
    req.session.todays_date = new Date().toISOString().split('T')[0];

    const events = await Image.find({ email: userEmail });
    let grandTotal = 0;

    for (let event of events) {
      const bookings = await Booking.find({ eventId: event._id });
      const totalAmount = bookings.reduce((sum, booking) => sum + booking.amount, 0);
       console.log(totalAmount)
    event.totalAmount = totalAmount;
    grandTotal += totalAmount;
    console.log(grandTotal)

    }
    const todayAmount = await calculateTotalAmountForToday(userEmail);
    const images = await Image.find({}, { imagePath: 1, _id: 0 });
    const rankedEvents = await getRankedEvents();
    const name = req.session.name || 'Guest';
    const formattedGrandTotal = new Intl.NumberFormat().format(grandTotal);
    const formattedtodayAmount = new Intl.NumberFormat().format(todayAmount);



    if (!data.success) {
      return res.render('login', { errorMessage: 'validation failed. Please try again.' });
    }
    if (check.user_type === 'admin') {
      res.render('admin', { name: name, events: events, grandTotal: formattedGrandTotal, todayAmount: formattedtodayAmount });
    } else {
      res.render('home', { name: check.name, rankedEvents: rankedEvents, images: images });
    }
  } catch (error) {
    console.error(error);
    res.render('login', { errorMessage: "An error occurred during login." });
  }
});

app.get('/home', ensureAuthenticated, async (req, res) => {
  try {
    const userEmail = req.session.email;
    const rankedEvents = await getRankedEvents();
    const images = await Image.find({}, { imagePath: 1, _id: 0 });
    res.render('home', { name: req.session.name, rankedEvents: rankedEvents, images: images });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error')
  }
});
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
  },
  ticketPrice: {
    type: Number,
    required: true
  }
});
const Image = mongoose.model('Image', imageSchema);
app.post('/submit', upload.single('imageUploader'), async (req, res) => {
  try {
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
    let ticketPrice = parseInt(req.body.ticketPrice, 10);
    if (isNaN(ticketPrice)) {
      ticketPrice = 0;
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
      totalTickets: totalTickets,
      ticketPrice: ticketPrice
    });
    await image.save();
    const newTicket = new Ticket({
      eventId: image._id,
      totalTickets: req.body.totalTickets
    });
    await newTicket.save();
    req.flash('message', 'Event registered successfully.')
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
const Ticket = mongoose.model('Ticket', ticketSchema)


async function calculateTotalAmountForToday(email) {
 

}

app.get('/admin', ensureAuthenticated, async (req, res) => {
  const name = req.session.name || 'Guest';
  const userEmail = req.session.email;
  const events = await Image.find({ email: userEmail });
  let grandTotal = 0;
  const now = new Date();
  const today = new Date(now.getUTCFullYear() , now.getUTCMonth(), now.getUTCDate());
  console.log(`Today: ${today.toISOString()}`);
  const bookings = await Booking.find({
    createdAt: {
      $gte: today,
      $lt: new Date(today.getTime() + 24*60*60*1000) // Add one day to today to include bookings up to the end of today
    },
    userEmail: email
  });
  let totalAmount = 0;
  bookings.forEach(booking => {
    totalAmount += booking.amount;
  });
  
  for (let event of events) {
    const bookings = await Booking.find({ eventId: event._id });
    const totalAmount = bookings.reduce((sum, booking) => sum + booking.amount, 0);
    console.log(totalAmount)
    event.totalAmount = totalAmount;
    grandTotal += totalAmount;
    console.log(grandTotal)

  }
  const formattedGrandTotal = new Intl.NumberFormat().format(grandTotal);
  const formattedtodayAmount = new Intl.NumberFormat().format(todayAmount);
  res.render('admin', { name: name, events: events, grandTotal: formattedGrandTotal, todayAmount: formattedtodayAmount });
});

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


app.get('/event/:id', ensureAuthenticated, async (req, res) => {
  try {
    const eventId = req.params.id;
    const event = await Image.findById(eventId);
    const email = req.session.email;

    if (!event) {
      return res.status(404).send('Event not found');
    }
    const similarEvents = await Image.find({
      dropdown1: event.dropdown1,
      _id: { $ne: eventId }
    });
    res.render('event-details', { event: event, similarEvents: similarEvents });
  } catch (error) {
    console.error(error);
  }
});

app.get('/bookings/:eventId', ensureAuthenticated, async (req, res) => {
  try {
    const eventId = req.params.eventId;
    const bookings = await Booking.find({ eventId: eventId });
    if (!Array.isArray(bookings) || bookings.length === 0) {
      return res.render('no-bookings-found', { eventId: eventId });
    } res.render('event-bookings', { bookings: bookings });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});





app.get('/filter-events', ensureAuthenticated, async (req, res) => {
  const dropdown1Value = req.query.dropdown1;
  const events = await Image.find({ dropdown1: dropdown1Value });
  res.render('events', { events: events });
});


app.post('/event-click', async (req, res) => {
  try {
    const { eventId } = req.body;
    if (!req.session.eventClicks) {
      req.session.eventClicks = {};
    }
    req.session.eventClicks[eventId] = (req.session.eventClicks[eventId] || 0) + 1;
    res.sendStatus(200);
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});
app.use(function (req, res, next) {
  if (req.session && req.session.eventClicks) {
    const eventClicks = req.session.eventClicks;
    Object.keys(eventClicks).forEach(async eventId => {
      try {
        await Image.findByIdAndUpdate(eventId, { $inc: { clicks: eventClicks[eventId] } });
      } catch (error) {
        console.error('Error updating click count:', error);
      }
    });
    delete req.session.eventClicks;
  }
  next();
});



app.get('/profile', ensureAuthenticated, async (req, res) => {
  try {
    const userEmail = req.session.email;
    if (!userEmail) {
      return res.status(401).send('Unauthorized');
    }

    const user = await User.findOne({ email: userEmail });
    if (!user) {
      return res.status(404).send('User not found');
    }
    // Fetch bookings for the user
    const bookings = await Booking.find({ userEmail: userEmail }).populate('eventId');

    // Map through bookings to fetch event details for each booking
    const bookingsWithEventDetails = bookings.map(booking => {
      const event = booking.eventId;
      return {
       ...booking.toObject(),
        eventDetails: {
          textbox4: event.textbox4, // Accessing textbox4 from the event document
          imagePath: event.imagePath, // Accessing textbox4 from the event document
          datePicker: event.datePicker // Accessing textbox4 from the event document
        }
      };
    });
    res.render('profile', { user: user, bookings: bookingsWithEventDetails });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});





app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).send('Error logging out');
    }
    res.redirect('/');
  });
});


app.get('/book-event/:id', async (req, res) => {
  const eventId = req.params.id;
  const event = await Image.findById(eventId);
  const userEmail = req.session.email;
  const user = await User.findOne({ email: userEmail });
  if (!event) {
    return res.status(404).send('Event not found')
  }

  res.render('booking', { event: event, eventId: eventId, user: user });
});
app.post('/book-event/id', async (req, res) => {
  try {

    let eventId = req.params.id;
    const event = await Image.findById(eventId)
    const userEmail = req.session.email;
    const user = await User.findOne({ email: userEmail });
    if (!event) {
      return res.status(404).send('Event not found');
    }
    console.log(user); // Debugging line
    res.render('booking', { event: event, user: user });
    if (!user) {
      return res.status(404).send('User not found');
    }
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});
const BookingSchema = new mongoose.Schema({
  bookingId: { type: mongoose.Schema.Types.ObjectId, required: true, unique: true },
  fullName: String,
  aadharNumber: String,
  eventId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Image' // Reference to the Image model
  },  amount: Number,
  orderId: String,
  quantity: Number,
  userEmail: String,
  createdAt: {
    type: Date,
    default: Date.now // This will automatically set the createdAt field to the current date and time
  },
  qrCodeUrl: String,
});

const Booking = mongoose.model('Booking', BookingSchema);

app.post("/payment", async (req, res) => {
  try {
    const { fullName, aadharNumber, eventId, amount, quantity } = req.body;

    var instance = new Razorpay({
      key_id: process.env.RAZORPAY_ID_KEY,
      key_secret: process.env.RAZORPAY_SECRET_KEY
    });
    let order = await instance.orders.create({
      amount: amount,
      currency: "INR",
      receipt: "receipt#1"
    });

    res.status(200).json({
      success: true,
      message: 'Payment order created successfully',
      order: order
    });
  } catch (error) {
    console.error(error);
    res.status(500).send({ error: 'An error occurred while creating the payment order.' });
  }
});
app.post("/saveBooking", async (req, res) => {
  try {
    const { fullName, aadharNumber, eventId, amount, quantity } = req.body;
    const bookingId = new mongoose.Types.ObjectId();
    const userEmail = req.session.email;
    // Define the path for the QR code
    const qrCodePath = path.join(__dirname, '../public/uploads/', bookingId.toString() + '.png');

    // Ensure the directory exists
    if (!fs.existsSync(path.dirname(qrCodePath))) {
      fs.mkdirSync(path.dirname(qrCodePath), { recursive: true });
    }

    // Generate QR code
    await QRCode.toFile(qrCodePath, bookingId.toString());
    const qrCodeResult = await cloudinary.uploader.upload(qrCodePath);
    const qrCodeUrl = qrCodeResult.secure_url; // This is the Cloudinary URL for the QR code

    // Delete the temporary QR code file after uploading to Cloudinary
    fs.unlinkSync(qrCodePath);
    
    const booking = new Booking({
      bookingId,
      fullName,
      aadharNumber,
      eventId,
      amount,
      orderId: req.body.orderId,
      quantity,
      userEmail,
      qrCodeUrl: qrCodeUrl // Save the Cloudinary URL of the QR code

    });

    await booking.save();

    const event = await Image.findById(eventId);
    const similarEvents = await Image.find({
      dropdown1: event.dropdown1,
      _id: { $ne: eventId }
    });
    if (event) {
      event.totalTickets -= quantity;
      await event.save();
      
      res.render('event-details', { event: event, similarEvents: similarEvents });

    } else {
      console.error('Event not found');
    }



    var mailOptions = {
      from: 'crowwd.in@gmail.com',
      to: userEmail,
      subject: 'Booking Confirmation',
      html: '<p>Your Booking for the event <strong>' + eventId + '</strong> for the quantity <strong>' + quantity + '</strong> has been booked successfully.</p><img src="' + qrCodeUrl + '" alt="QR Code">'
    };
    var transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'crowwd.in@gmail.com',
        pass: process.env.EMAIL_APP_PASS
      }
    });

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log(error);
      } else {
        console.log('Email sent: ' + info.response);
      }
    });

    res.status(201).json({
      success: true,
      message: 'Booking saved successfully',
      booking
    });
  } catch (error) {
    console.error(error);
    res.status(500).send({ error: 'An error occurred while saving the booking.' });
  }
});

app.get('/listevents', ensureAuthenticated, async (req, res) => {
  res.locals.messages = req.flash();
  res.render('listevent');
});
app.get('/dashboard_profile', ensureAuthenticated, async (req, res) => {

  try {
    const userEmail = req.session.email;
    if (!userEmail) {
      return res.status(401).send('Unauthorized');
    }

    const user = await User.findOne({ email: userEmail });

    if (!user) {
      return res.status(404).send('User not found');
    } res.render('dashboard_profile', { user: user });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

app.get('/billing', ensureAuthenticated, async (req, res) => {
  try {
    const userEmail = req.session.email;

    const user = await User.findOne({ email: userEmail });
    if (!user) {
      return res.status(404).send('User not found');
    }

    res.render('billing', { user: user });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

app.get('/verify-ticket', ensureAuthenticated , async (req, res) => {
  res.render('verify');
});


app.post("/scan-success", async (req, res) => {
  const decodedText = req.body.decodedText;
  try {
    const booking = await Booking.findOne({ bookingId: decodedText });
    if (booking) {
      res.json({id:booking.bookingId,name:booking.fullName,aadhar:booking.aadharNumber,quantity:booking.quantity});
    } else {
      // If no booking is found, send a response indicating failure
      res.json({ message: "No booking found with the provided QR code." });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "An error occurred while processing your request." });
  }});




const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});