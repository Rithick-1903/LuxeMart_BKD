import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());


// ================= DATABASE =================

mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("MongoDB Connected"))
.catch((err) => console.log(err));


// ================= USER MODEL =================

const userSchema = new mongoose.Schema({

  name: {
    type: String,
    required: true
  },

  email: {
    type: String,
    required: true,
    unique: true
  },

  phone: {
    type: String,
    required: true
  },

  password: {
    type: String,
    required: true
  }

});

const User = mongoose.model("User", userSchema);


// ================= REGISTER =================

app.post("/api/auth/register", async (req, res) => {

  try {

    const {
      name,
      email,
      phone,
      password
    } = req.body;

    // CHECK USER
    const userExists = await User.findOne({
      email
    });

    if (userExists) {

      return res.status(400).json({
        message: "User already exists"
      });

    }

    // HASH PASSWORD
    const hashedPassword =
      await bcrypt.hash(password, 10);

    // SAVE USER
    const user = await User.create({

      name,
      email,
      phone,
      password: hashedPassword

    });

    res.status(201).json({

      message: "Registration Successful",

      user

    });

  } catch (error) {

    res.status(500).json({
      message: error.message
    });

  }

});



app.post("/api/auth/login", async (req, res) => {

  try {

    const { email, password } = req.body;

    // CHECK USER
    const user = await User.findOne({
      email
    });

    if (!user) {

      return res.status(400).json({
        message:
          "No account found. Please Register"
      });

    }

    // CHECK PASSWORD
    const isMatch =
      await bcrypt.compare(
        password,
        user.password
      );

    if (!isMatch) {

      return res.status(400).json({
        message: "Invalid Password"
      });

    }

   
    const token = jwt.sign(

      { id: user._id },

      process.env.JWT_SECRET,

      { expiresIn: "7d" }

    );

    res.status(200).json({

      message: "Login Successful",

      token,

      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }

    });

  } catch (error) {

    res.status(500).json({
      message: error.message
    });

  }

});



app.get("/", (req, res) => {

  res.send("Backend Running");

});



const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {

  console.log(`Server Running On ${PORT}`);

});