require('dotenv').config();


const port = process.env.PORT || 5000;
const express = require("express");
const app = express();
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const cors = require("cors");
const { error } = require("console");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);


app.use(express.json());
app.use(cors());

//Database connection with mongodb
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error("MongoDB connection error:", err));


//Api creation

app.get("/", (req, res) => {
  res.send("Express App is Running");
});

//Image storage engine
const storage = multer.diskStorage({
  destination: "./upload/images",
  filename: (req, file, cb) => {
    return cb(
      null,
      `${file.fieldname}_${Date.now()}${path.extname(file.originalname)}`
    );
  },
});

const upload = multer({ storage: storage });

//Creating Upload Endpoint for Images

app.use("/images", express.static("upload/images"));

app.post("/upload", upload.array("product", 4), (req, res) => {
  const image_urls = req.files.map(file => `${req.protocol}://${req.get('host')}/images/${file.filename}`);
  res.json({
    success: 1,
    image_urls: image_urls,
  });
});


//Schema for Creating Products

const Product = mongoose.model("Product", {
  id: {
    type: Number,
    required: true,
  },
  name: {
    type: String,
    required: true,
  },
  image: {
    type: [String],
    required: true,
  },
  category: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  new_price: {
    type: Number,
    required: true,
  },
  old_price: {
    type: Number,
    required: true,
  },
  date: {
    type: Date,
    default: Date.now,
  },
  available: {
    type: Boolean,
    default: true,
  },
});

//Creating API for Adding Product

app.post("/addproduct", async (req, res) => {
  let products = await Product.find({});
  let id;
  if (products.length > 0) {
    let last_product_array = products.slice(-1);
    let last_product = last_product_array[0];
    id = last_product.id + 1;
  } else {
    id = 1;
  }

  const product = new Product({
    id: id,
    name: req.body.name,
    image: req.body.image,
    category: req.body.category,
    new_price: req.body.new_price,
    old_price: req.body.old_price,
  });
  console.log(product);
  await product.save();
  console.log("Saved");
  res.json({
    success: true,
    name: req.body.name,
  });
});

//Creating API for Deleting Product

app.post("/removeproduct", async (req, res) => {
  await Product.findOneAndDelete({ id: req.body.id });
  console.log("Removed");
  res.json({
    success: true,
    name: req.body.name,
  });
});

//Creating API for geting all Products

app.get("/allproducts", async (req, res) => {
  let products = await Product.find({});
  console.log("All Products are Fetched");
  res.send(products);
});

// Schema Creating for user model

const Users = mongoose.model("Users", {
  name: {
    type: String,
  },
  email: {
    type: String,
    unique: true,
  },
  password: {
    type: String,
  },
  cartData: {
    type: Object,
  },
  date: {
    type: Date,
    default: Date.now,
  },
});

// Creating Endpoint for user registration

app.post("/signup", async (req, res) => {
  let check = await Users.findOne({ email: req.body.email });
  if (check) {
    return res
      .status(400)
      .json({
        success: false,
        errors: "Existing user found with same email address",
      });
  }
  let cart = {};
  for (let i = 0; i < 300; i++) {
    cart[i] = 0;
  }
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const user = new Users({
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword,
    cartData: cart,
  });

  await user.save();

  const data = {
    user: {
      id: user.id,
    },
  };

  const token = jwt.sign(data, process.env.JWT_SECRET);
  res.json({ success: true, token });
});

// Creating Endpoint for user login

app.post("/login", async (req, res) => {
  let user = await Users.findOne({ email: req.body.email });
  if (user) {
const passCompare = await bcrypt.compare(req.body.password, user.password);
    if (passCompare) {
      const data = {
        user: {
          id: user.id,
        },
      };
      const token = jwt.sign(data, process.env.JWT_SECRET);
      res.json({ success: true, token });
    }
    else {
        res.json({ success: false, errors: "Wrong Password" });
      }
  }
  else {
      res.json({ success: false, errors: "Wrong Email Id" });
  }
  // i<f (data.success) {
  //   const decoded = jwt.verify(token, process.env.JWT_SECRET); // <-- GET user.id here
  //   const userId = decoded.user.id;
  //   setUserData({ _id: userId }); // <-- Properly store user ID
  //   localStorage.setItem("token", data.token); // optionally persist
  // }>
  if (passCompare) {
  const data = { user: { id: user.id } };
  const token = jwt.sign(data, process.env.JWT_SECRET);
  res.json({ success: true, token });
}

});

// Get login user details

app.get("/getuser", async (req, res) => {
  const token = req.header("auth-token");
  if (!token) {
    return res.status(401).json({ success: false, message: "Access Denied" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.user.id;

    const user = await Users.findById(userId).select("-password"); // Don't send password
    res.json({ success: true, user });
  } catch (err) {
    res.status(400).json({ success: false, message: "Invalid Token" });
  }
});

// schema for cart

const CartItemSchema = new mongoose.Schema({
  productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
  quantity: { type: Number, required: true, default: 1 },
});

const CartSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true }, // Or mongoose.Schema.Types.ObjectId if using users
  items: [CartItemSchema],
});

const Cart = mongoose.model("Cart", CartSchema);

// Creating endpoint for adding products in cart data

app.post("/cart/add", async (req, res) => {
  const { userId, productId, quantity = 1 } = req.body;

  console.log("Adding to cart - userId:", userId, "productId:", productId);

  if (!userId || !productId) {
    return res.status(400).json({ success: false, message: "Missing userId or productId" });
  }

  try {
    let cart = await Cart.findOne({ userId });

    if (!cart) {
      cart = new Cart({ userId, items: [] });
    }

    const existingItem = cart.items.find(item => item.productId.toString() === productId);

    if (existingItem) {
      existingItem.quantity += quantity;
    } else {
      cart.items.push({ productId, quantity });
    }

    await cart.save();

    res.json({ success: true, message: "Item added to cart", cart });
  } catch (error) {
    console.error("Add to cart error:", error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});



// POST /cart/update
app.post("/cart/update", async (req, res) => {
  const { userId, productId, quantity } = req.body;

  try {
    const cart = await Cart.findOne({ userId });

    if (!cart) return res.status(404).json({ success: false, message: "Cart not found" });

    const item = cart.items.find(item => item.productId.toString() === productId);

    if (!item) return res.status(404).json({ success: false, message: "Product not in cart" });

    if (quantity <= 0) {
      cart.items = cart.items.filter(item => item.productId.toString() !== productId);
    } else {
      item.quantity = quantity;
    }

    await cart.save();

    res.json({ success: true, message: "Cart updated", cart });
  } catch (error) {
    console.error("Update cart error:", error);
    res.status(500).json({ success: false });
  }
});


// POST /cart/remove
app.post("/cart/remove", async (req, res) => {
  const { userId, productId } = req.body;

  try {
    const cart = await Cart.findOne({ userId });

    if (!cart) return res.status(404).json({ success: false });

    cart.items = cart.items.filter(item => item.productId.toString() !== productId);

    await cart.save();

    res.json({ success: true, message: "Item removed from cart" });
  } catch (error) {
    console.error("Remove cart item error:", error);
    res.status(500).json({ success: false });
  }
});


// GET /cart/:userId
app.get("/cart/:userId", async (req, res) => {
  try {
    const cart = await Cart.findOne({ userId: req.params.userId }).populate("items.productId");

    if (!cart) {
      return res.json({ success: true, items: [] });
    }

    res.json({ success: true, items: cart.items });
  } catch (error) {
    console.error("Get cart error:", error);
    res.status(500).json({ success: false });
  }
});



app.listen(port, (error) => {
  if (!error) {
    console.log("Server Running on Port" + port);
  } else {
    console.log("Error" + error);
  }
});
