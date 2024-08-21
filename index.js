const express = require("express");
const app = express();

require("dotenv").config();
const PORT = process.env.PORT || 4000;

//Cookie parser
const cookieParser = require("cookie-parser");
app.use(cookieParser());

app.use(express.json());

require("./config/database").dbConnect();

//route import and mount
const user = require("./routes/user");
app.use("/api/v1", user);

//activate
app.listen(PORT, () => {
  console.log(`App is running at ${PORT}`);
});