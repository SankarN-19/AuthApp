const mongoose = require("mongoose");

require("dotenv").config();

exports.dbConnect = () => {
  mongoose.connect(process.env.DATABASE_URL)
    .then(() => {
      console.log("DB connection is successful");
    })
    .catch((err) => {
      console.log("DB Connection issues");
      console.error(err);
      process.exit(1);
    });
};