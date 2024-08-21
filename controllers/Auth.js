const bcrypt = require("bcrypt");
const User = require("../models/User");
const jwt = require("jsonwebtoken");
require("dotenv").config();

//signup route handler
//step1 : Fetch data from req body
//step2 : Check for existing user
//step3 : If user already exists return response
//step4 : Hash the password --successful(store) else (return response)
//step5 : Insert User entry into Db
//step6 : return response(200 status code)

exports.signup = async (req, res) => {
  try {
    //get data
    const { name, email, password, role } = req.body;
    //check if user already exists
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already Exists",
      });
    }

    //secure password
    let hashedPassword;
    try {
      hashedPassword = await bcrypt.hash(password, 10);
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: "Error in hashing Password",
      });
    }
    //create entry for user
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role,
    });
    return res.status(200).json({
      success: true,
      message: "User created successfully",
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: "User cannot be registered, please try again later",
    });
  }
};

//login route handler
//step1: Fetch email and pwd from req body
//step2: if(!email || !pwd) return response "Fill all details"
//step3: check email exists in database or not -> findOne use karo
//step4: if user doesnot exist return response
//step5: verify password ---> no(return response) / yes(create JWT token---->jwt.sign(payload,secret,options/config,callback))

exports.login = async (req, res) => {
  try {
    //fetch data
    const { email, password } = req.body;

    //validate on email and password
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Please fill all the details carefully",
      });
    }

    //check for registered user
    let user = await User.findOne({ email }).lean(); //lean is used to convert a mongoose document to a plain javascript Object
    //if not a registered user
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User is not registered",
      });
    }

    const payload = {
      email: user.email,
      id: user._id,
      role: user.role,
    };
    //verify password and generate a JWT token
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (isPasswordMatch) {
      //password match ho gya
      //create token
      //Syntax : let token = jwt.sign(payload, secret_key, options);
      let token = jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: "2h",
      });

      // user = user.toObject(); //This is used when .lean() is not used

      //token ab hum user ke andar bhej denge jou database mein store ho jayega
      user.token = token;
      //jab user ke object ko hum response mein bhejenge tab password bhi chala jayega..iss liye undefined!
      user.password = undefined;

      //options for cookies
      const options = {
        expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
        httpOnly: true,
      };

      //Create cookie
      //Syntax: 1.cookie name, 2.cookie value, 3.options
      res.cookie("myPookie", token, options).status(200).json({
        success: true,
        token,
        user,
        message: "User Logged in successfully",
      });
    } else {
      //password didn't match
      return res.status(403).json({
        success: false,
        message: "Incorrect Password.",
      });
    }
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "Login Failure",
    });
  }
};
