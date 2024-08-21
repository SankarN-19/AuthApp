//auth, isStudent, isAdmin  --> 3 middlewares
//Middlewares are the functions that is invoked when request is intercepted in middle, and then it is invoked.

const jwt = require("jsonwebtoken");
require("dotenv").config();

//middleware to check authenticity
exports.auth = (req, res, next) => {
  try {
    //all the ways to extract jwt token
    const token =
      req.body.token || //LESS SECURED WAY!
      req.cookie.token ||
      /*Authorization: Bearer <token> ----> req ke andar header ke andar mein 
      Authorization key ke jou value hai usme Bearer ko replace kardo empty 
      string se so that sirf token milega*/
      req.header("Authorization").replace("Bearer ", ""); //MOST SECURED WAY!

      console.log("cookie", req.cookie.token);
      console.log("body", req.body.token);
      console.log("header", req.header("Authorization"));

    //If token is not present, then send response
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Token's missing!",
      });
    }

    //verify the token
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      console.log(payload);

      req.user = payload;
    } catch (error) {
      return res.status(401).json({
        success: false,
        message: "Token's invalid",
      });
    }
    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Something went wrong, while verifying the token",
    });
  }
};

exports.isStudent = (req, res, next) => {
  try {
    if (req.user.role !== "Student") {
      return res.status(401).json({
        success: false,
        message: "This is a protected route for students",
      });
    }
    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "User role is not matching",
    });
  }
};

exports.isAdmin = (req, res, next) => {
  try {
    if (req.user.role !== "Admin") {
      return res.status(401).json({
        success: false,
        message: "This is a protected route for Admin",
      });
    }
    next();
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "User role is not matching",
    });
  }
};

