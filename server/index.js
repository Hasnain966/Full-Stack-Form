const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const MongoStore = require("connect-mongo");
const UserModel = require("./model/User.js");
var jwt = require("jsonwebtoken");
var cookieParser = require("cookie-parser");
dotenv.config();

const app = express();
app.use(cookieParser());
app.use(express.json());

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Failed to connect to MongoDB", err));

app.listen(process.env.PORT, () => {
  console.log(`Server is running on port ${process.env.PORT}`);
});

app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const existingUser = await UserModel.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new UserModel({ name, email, password: hashedPassword });
    const savedUser = await newUser.save();
    res.status(201).json(savedUser);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    let user = await UserModel.findOne({ email });
    if (user) {
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch) {
        // token generation
        const token = jwt.sign({ access_token: user._id }, process.env.JWT);
        // cookie generation
        res
          .cookie("access_token", token, {
            httpOnly: true,
          })
          .send({
            message: "user logged in succesfuly",
            user,
          });
      } else {
        res.status(401).json("Password doesn't match");
      }
    } else {
      res.status(404).json("No Records found");
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/logout", (req, res) => {
  try {
    // Clear the access_token cookie
    res
      .clearCookie("access_token", {
        httpOnly: true,
      })
      .send({
        message: "User logged out successfully",
      });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/allUser", async (req, res) => {
  // if (req.session.user) {
  //     res.json({ user: req.session.user });
  // } else {
  //     res.status(401).json("Not authenticated");
  // }

  const allUsers = await UserModel.find();
  res.send(allUsers);
});

// getting singleUser
app.get("/user/:id", async (req, res) => {
    const token = req.cookies.access_token;
try {
    // if (!token) return next(createError(404, "User not authenticated"));
  
    const user = jwt.verify(token, process.env.JWT );
    console.log(user,"--user")
  
    const desiredUser = await UserModel.findById(req.params.id)
    res.send(desiredUser)
} catch (error) {
    res.send(
        {
            "message": error.message,
            "status":error.status        
        }
    )
}
});
