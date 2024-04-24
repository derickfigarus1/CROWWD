const express = require("express");
const app = express.Router();
const Image = require("../models/image");


// Define route for booking events
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
      const eventId = req.params.id;
      const event = await Image.findById(eventId);
      console.log(eventId);

      if (!event) {
        return res.status(404).send('Event not found');
      }
      // Fetch similar events
      const similarEvents = await Image.find({
        dropdown1: event.dropdown1,
        _id: { $ne: eventId }
      });
      console.log(similarEvents)
      res.render('event-details', { event: event, similarEvents: similarEvents });
  } catch (error) { 
      console.error(error);
      res.status(500).send('Server error');
  }
 });
 
 app.post('/book-event/:id', async (req, res) => {
  try {
      const eventId = req.params.id;
      const quantity = parseInt(req.body.quantity, 10); 
 
      // Checks if quantity is a valid number
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
  } catch (error) {
      console.error(error);
      res.status(500).send('An error occurred while booking the event.');
  }
 });


app.get('/filter-events', async (req, res) => {
 const dropdown1Value = req.query.dropdown1;
 const events = await Image.find({ dropdown1: dropdown1Value });
 res.render('events', { events: events });
});
module.exports = app;
