const express = require("express");
const session = require('express-session');
const path = require("path");
const bcrypt = require('bcrypt');
const fs = require('fs'); // Add this line

const mongoose = require('mongoose');
const crypto = require('crypto');
const axios = require('axios');
const app = express();
const dotenv = require("dotenv");
const cookieParser = require('cookie-parser');
const QRCode = require('qrcode'); // Import the qrcode package

const multer = require('multer');
const flash = require('connect-flash');
require('dotenv').config({ path: './src/.env' });
app.use(flash());
app.use(express.json());
app.use(express.static("public"));
app.use(express.urlencoded({ extended: false }));
app.set("view engine", "ejs");
app.use(cookieParser('secret'));
const Recaptcha = require('express-recaptcha').RecaptchaV2;
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
const Razorpay = require("razorpay");
const cors = require("cors");
const MongoStore = require('connect-mongo');
app.use(cors());
var nodemailer = require('nodemailer');




mongoose.connect(process.env.MONGO_URI,)
  .then(() => console.log("Database Connected Successfully"))
  .catch(err => console.error("Database Connection Error: ", err))


const cloudinary = require('cloudinary').v2;
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET
});
function ensureAuthenticated(req, res, next) {
  if (req.session && req.session.email) {
    return next();
  }
  res.redirect('/');
}
const upload = multer({
  storage: multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, path.join(__dirname, '../public/uploads/'));
    },
    filename: function (req, file, cb) {
      cb(null, file.originalname);
    }
  })
});
app.use(session({
  cookie: { maxAge: 600000 },
  secret: process.env.SESSION_SECRET || 'crowwd123',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }), // Use MongoDB as session store

}));


async function calculateTotalAmountForToday(email) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);

  const bookings = await Booking.find({
    createdAt: { $gte: today, $lt: tomorrow },
    userEmail: email
  });

  let totalAmount = 0;
  bookings.forEach(booking => {
    totalAmount += booking.amount;
  });

  return totalAmount;
}

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
      event.totalAmount = totalAmount;
      grandTotal += totalAmount;

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




app.get('/admin', ensureAuthenticated, async (req, res) => {
  const name = req.session.name || 'Guest';
  const userEmail = req.session.email;
  const events = await Image.find({ email: userEmail });
  let grandTotal = 0;

  const todayAmount = await calculateTotalAmountForToday(userEmail);
  for (let event of events) {
    const bookings = await Booking.find({ eventId: event._id });
    const totalAmount = bookings.reduce((sum, booking) => sum + booking.amount, 0);
    event.totalAmount = totalAmount;
    grandTotal += totalAmount;

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

    const bookings = await Booking.find({ userEmail: userEmail });
    const eventIds = bookings.map(booking => booking.eventId);
    let bookedEvents = await Promise.all(eventIds.map(async (eventId) => {
      const event = await Image.findById(eventId);
      if (!event) {
        return null;
      }
      return event;
    }));

    bookedEvents = bookedEvents.filter(event => event !== null);

    const user = await User.findOne({ email: userEmail });

    if (!user) {
      return res.status(404).send('User not found');
    } res.render('profile', { bookedEvents: bookedEvents, user: user });
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
  console.log(user); // Debugging line

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
  eventId: String,
  amount: Number,
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
    if (event) {
      event.totalTickets -= quantity;
      await event.save();
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
        pass:process.env.EMAIL_APP_PASS
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

const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});