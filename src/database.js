const { default: mongoose } = require('mongoose');

require('dotenv').config({ path: './src/.env' });

const database = mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
 .then(() => console.log("mongoDB is connected"))
  .then(() => console.log("Database Connected Successfully"))
  .catch(err => console.error("Database Connection Error: ", err));

module.exports=database;