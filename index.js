require("dotenv").config();

const port = process.env.PORT || 5000;
const express = require("express");
const app = express();
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const cors = require("cors");
// const { error } = require("console");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
// const { type } = require("os");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

app.use(express.json());
app.use(cors());

//Database connection with mongodb
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

//Api creation

app.get("/", (req, res) => {
  res.send("Express App is Running");
});

// cloudinary Configaration
const { v2: cloudinary } = require('cloudinary');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
// const multer = require('multer');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'products', // Cloudinary folder name
    allowed_formats: ['jpg', 'png', 'jpeg'],
  },
});

const upload = multer({ storage });

//Creating Upload Endpoint for Images
 
// app.use("/images", express.static("upload/images"));

app.post("/upload", upload.array("product", 4), (req, res) => {
  try {
    const image_urls = req.files.map(file => file.path);
    res.json({
      success: 1,
      image_urls: image_urls,
    });
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ success: 0, message: "Upload failed", error: err });
  }
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
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user",
  },
});

// Creating Endpoint for user registration

app.post("/signup", async (req, res) => {
  let check = await Users.findOne({ email: req.body.email });
  if (check) {
    return res.status(400).json({
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
    role: "user",
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

//for security
const verifyToken = (req, res, next) => {
  const bearerHeader = req.headers["authorization"];

  if (typeof bearerHeader === "undefined") {
    return res
      .status(401)
      .json({ success: false, message: "Unauthorized - No token provided" });
  }

  const token = bearerHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res
        .status(403)
        .json({ success: false, message: "Invalid or expired token" });
    }

    req.user = user.user;
    next();
  });
};

// Creating Endpoint for user login

app.post("/login", async (req, res) => {
  let user = await Users.findOne({ email: req.body.email });
  if (user) {
    const passCompare = await bcrypt.compare(req.body.password, user.password);
    if (passCompare) {
      const data = {
        user: {
          id: user.id,
          role: user.role,
        },
      };
      const token = jwt.sign(data, process.env.JWT_SECRET);
      res.json({ success: true, token });
    } else {
      res.json({ success: false, errors: "Wrong Password" });
    }
  } else {
    res.json({ success: false, errors: "Wrong Email Id" });
  }
  // i<f (data.success) {
  //   const decoded = jwt.verify(token, process.env.JWT_SECRET); // <-- GET user.id here
  //   const userId = decoded.user.id;
  //   setUserData({ _id: userId }); // <-- Properly store user ID
  //   localStorage.setItem("token", data.token); // optionally persist
  // }>
  //   if (passCompare) {
  //   const data = { user: { id: user.id } };
  //   const token = jwt.sign(data, process.env.JWT_SECRET);
  //   res.json({ success: true, token });
  // }
});

// Get login user details

app.get("/getuser", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await Users.findById(userId).select("-password");

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    res.json({ success: true, user });
  } catch (err) {
    console.error("Error in /getuser:", err);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});


//schema for review
const reviewSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "Users" },
  rating: { type: Number, required: true },
  comment: { type: String },
  createdAt: { type: Date, default: Date.now },
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
  reviews: [reviewSchema],
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
    description: req.body.description,
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

// schema for cart

const CartItemSchema = new mongoose.Schema({
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Product",
    required: true,
  },
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
    return res
      .status(400)
      .json({ success: false, message: "Missing userId or productId" });
  }

  try {
    let cart = await Cart.findOne({ userId });

    if (!cart) {
      cart = new Cart({ userId, items: [] });
    }

    const existingItem = cart.items.find(
      (item) => item.productId.toString() === productId
    );

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

    if (!cart)
      return res
        .status(404)
        .json({ success: false, message: "Cart not found" });

    const item = cart.items.find(
      (item) => item.productId.toString() === productId
    );

    if (!item)
      return res
        .status(404)
        .json({ success: false, message: "Product not in cart" });

    if (quantity <= 0) {
      cart.items = cart.items.filter(
        (item) => item.productId.toString() !== productId
      );
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

    cart.items = cart.items.filter(
      (item) => item.productId.toString() !== productId
    );

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
    const cart = await Cart.findOne({ userId: req.params.userId }).populate(
      "items.productId"
    );

    if (!cart) {
      return res.json({ success: true, items: [] });
    }

    res.json({ success: true, items: cart.items });
  } catch (error) {
    console.error("Get cart error:", error);
    res.status(500).json({ success: false });
  }
});

// Schema Creating for Address model

const Address = mongoose.model("Address", {
  userId: {
    type: String,
    required: true,
  },
  fullName: String,
  phoneNumber: String,
  pincode: String,
  area: String,
  city: String,
  state: String,
});

//creating endpoints for adding address
app.post("/address/add", verifyToken, async (req, res) => {
  const { fullName, phoneNumber, pincode, area, city, state } = req.body;

  try {
    const address = new Address({
      userId: req.user.id,
      fullName,
      phoneNumber,
      pincode,
      area,
      city,
      state,
    });

    await address.save();
    res.json({ success: true, message: "Address added successfully", address });
  } catch (error) {
    console.error("Add address error:", error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

//api to fetch address
app.get("/address/get", verifyToken, async (req, res) => {
  try {
    const addresses = await Address.find({ userId: req.user.id });
    res.json({ success: true, addresses });
  } catch (error) {
    console.error("Get address error:", error);
    res.status(500).json({ success: false });
  }
});

// Delete a specific address by ID
app.delete("/address/delete/:id", verifyToken, async (req, res) => {
  try {
    const address = await Address.findOneAndDelete({
      _id: req.params.id,
      userId: req.user.id,
    });

    if (!address) {
      return res
        .status(404)
        .json({ success: false, message: "Address not found" });
    }

    res.json({ success: true, message: "Address deleted" });
  } catch (error) {
    console.error("Delete address error:", error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

//schema for order
const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  addressId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Address",
    required: true,
  },
  items: [
    {
      productId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Product",
        required: true,
      },
      quantity: { type: Number, required: true },
      priceAtPurchase: { type: Number, required: true },
    },
  ],
  totalAmount: { type: Number, required: true },
  paymentMethod: {
    type: String,
    enum: ["cod", "razorpay"],
    required: true,
  },
  paymentStatus: {
    type: String,
    enum: ["pending", "paid"],
    default: "pending",
  },
  orderStatus: {
    type: String,
    enum: ["placed", "shipped", "delivered", "cancelled"],
    default: "placed",
  },
  razorpayOrderId: { type: String },
  razorpayPaymentId: { type: String },
  razorpaySignature: { type: String },
  createdAt: { type: Date, default: Date.now },
});

const Order = mongoose.model("Order", orderSchema);

// POST /order/create
app.post("/order/create", verifyToken, async (req, res) => {
  try {
    const { addressId, items, paymentMethod, paymentStatus, razorpayOrderId } =
      req.body;

    const userId = req.user.id;

    if (!userId || !addressId || !items || items.length === 0) {
      return res.status(400).json({ message: "Missing required order data" });
    }

    // ✅ If it's Razorpay, prevent duplicate
    if (paymentMethod === "razorpay" && razorpayOrderId) {
      const existing = await Order.findOne({ razorpayOrderId });
      if (existing) {
        return res.status(400).json({ message: "Duplicate Razorpay order" });
      }
    }

    let totalAmount = 0;
    const orderItems = [];

    for (const item of items) {
      const product = await Product.findById(item.productId);
      if (!product)
        return res.status(404).json({ message: "Product not found" });

      const itemTotal = product.new_price * item.quantity;
      totalAmount += itemTotal;

      orderItems.push({
        productId: product._id,
        quantity: item.quantity,
        priceAtPurchase: product.new_price,
      });
    }

    const newOrder = await Order.create({
      userId,
      addressId,
      items: orderItems,
      totalAmount,
      paymentMethod,
      paymentStatus: paymentStatus || "pending",
      razorpayOrderId,
    });

    return res.status(201).json({ success: true, order: newOrder });
  } catch (err) {
    console.error("Order creation error:", err);
    return res
      .status(500)
      .json({ message: "Server error while creating order" });
  }
});

//api to fetch myorder
app.get("/order/myorders", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id; // or req.user._id depending on your JWT payload

    const orders = await Order.find({ userId })
      .populate("items.productId") // populate product details
      .populate("addressId") // populate address details
      .sort({ createdAt: -1 });

    // Format the data to match frontend expected shape (optional)
    const formattedOrders = orders.map((order) => ({
      items: order.items.map((item) => ({
        product: {
          name: item.productId.name,
          // add other product fields if needed
        },
        quantity: item.quantity,
      })),
      address: {
        fullName: order.addressId.fullName,
        area: order.addressId.area,
        city: order.addressId.city,
        state: order.addressId.state,
        phoneNumber: order.addressId.phoneNumber,
      },
      amount: order.totalAmount,
      date: order.createdAt,
      status: order.orderStatus,
      paymentMethod: order.paymentMethod,
      paymentStatus: order.paymentStatus,
    }));

    res.json({ success: true, orders: formattedOrders });
  } catch (error) {
    console.error("Error fetching orders:", error);
    res
      .status(500)
      .json({ success: false, message: "Server error fetching orders" });
  }
});

// Order Model Example
const Orders = mongoose.model("Orders", {
  userId: String,
  items: Array,
  amount: Number,
  address: Object,
  date: Date,
});

app.get("/admin/orders", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await Users.findById(userId);

    if (!user || user.role !== "admin") {
      return res.status(403).json({ success: false, message: "Access denied" });
    }

    const orders = await Order.find({})
      .populate("items.productId")
      .populate("addressId")
      .sort({ createdAt: -1 });

    const formattedOrders = orders.map((order) => ({
      items: order.items.map((item) => ({
        product: {
          name: item.productId.name,
        },
        quantity: item.quantity,
      })),
      address: {
        fullName: order.addressId.fullName,
        area: order.addressId.area,
        city: order.addressId.city,
        state: order.addressId.state,
        phoneNumber: order.addressId.phoneNumber,
      },
      amount: order.totalAmount,
      date: order.createdAt,
      status: order.orderStatus,
      paymentMethod: order.paymentMethod,
      paymentStatus: order.paymentStatus,
    }));

    res.json({ success: true, orders: formattedOrders });
  } catch (error) {
    console.error("Error fetching all orders:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

//api for razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

app.post("/razorpay/create-order", verifyToken, async (req, res) => {
  try {
    const { addressId, items } = req.body;
    const userId = req.user.id;

    if (!userId || !addressId || !items || items.length === 0) {
      return res.status(400).json({ message: "Missing required data" });
    }

    let totalAmount = 0;
    const orderItems = [];

    for (const item of items) {
      const product = await Product.findById(item.productId);
      if (!product)
        return res.status(404).json({ message: "Product not found" });

      const itemTotal = product.new_price * item.quantity;
      totalAmount += itemTotal;

      orderItems.push({
        productId: product._id,
        quantity: item.quantity,
        priceAtPurchase: product.new_price,
      });
    }

    // STEP 1: Create Order in MongoDB (without Razorpay ID yet)
    const newOrder = await Order.create({
      userId,
      addressId,
      items: orderItems,
      totalAmount,
      paymentMethod: "razorpay",
      paymentStatus: "pending",
    });

    // STEP 2: Create Razorpay Order
    const razorpayOrder = await razorpay.orders.create({
      amount: totalAmount * 100, // in paise
      currency: "INR",
      receipt: `receipt_order_${newOrder._id}`,
      payment_capture: 1,
    });

    // STEP 3: Update the order with razorpayOrderId
    newOrder.razorpayOrderId = razorpayOrder.id;
    await newOrder.save(); // this is more reliable than `findByIdAndUpdate`

    return res.status(200).json({
      success: true,
      razorpayOrder,
      mongoOrderId: newOrder._id,
    });
  } catch (err) {
    console.error("Create Razorpay Order Failed:", err);
    return res
      .status(500)
      .json({ message: "Server error creating Razorpay order" });
  }
});

app.post("/razorpay/verify-payment", async (req, res) => {
  const {
    razorpay_order_id,
    razorpay_payment_id,
    razorpay_signature,
    mongoOrderId,
  } = req.body;

  const secret = process.env.RAZORPAY_KEY_SECRET;

  const generated_signature = crypto
    .createHmac("sha256", secret)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest("hex");

  if (generated_signature === razorpay_signature) {
    try {
      const order = await Order.findByIdAndUpdate(
        mongoOrderId,
        {
          paymentStatus: "paid",
          razorpayPaymentId: razorpay_payment_id,
          razorpayOrderId: razorpay_order_id, // Optional: Save if not saved earlier
          razorpaySignature: razorpay_signature,
        },
        { new: true }
      );

      if (!order) {
        return res
          .status(404)
          .json({ success: false, message: "Order not found" });
      }

      return res.status(200).json({
        success: true,
        message: "Payment verified and status updated",
        order,
      });
    } catch (err) {
      console.error("Error updating payment status:", err);
      return res.status(500).json({ success: false, message: "Server error" });
    }
  } else {
    return res
      .status(400)
      .json({ success: false, message: "Invalid signature" });
  }
});

//creating api for review

// POST /reviews/:productId
app.post("/reviews/:productId", verifyToken, async (req, res) => {
  const { rating, comment } = req.body;
  const userId = req.user.id; // from JWT middleware
  const { productId } = req.params;

  try {
    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ message: "Product not found" });

    const alreadyReviewed = product.reviews.find(
  (r) => r.userId && r.userId.toString() === userId
);


    if (alreadyReviewed) {
      return res
        .status(400)
        .json({ message: "You already reviewed this product" });
    }

    product.reviews.push({ userId, rating, comment });
    await product.save();
    res.status(201).json({ message: "Review added" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/product/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id).populate(
      "reviews.userId",
      "name"
    );
    if (!product) return res.status(404).json({ message: "Product not found" });

    res.json(product);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

//Contact Schema
const contactSchema = new mongoose.Schema({
  name: String,
  email: String,
  message: String,
}, { timestamps: true });

const Contact = mongoose.model("Contact", contactSchema);

// Api for contact option via mail
app.post("/contact", async (req, res) => {
  const { name, email, message } = req.body;

  try {
    // Store in DB
    await Contact.create({ name, email, message });

    // Send email
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.SMTP_USER, // your Gmail or domain email
        pass: process.env.SMTP_PASS,
      },
    });

    await transporter.sendMail({
      from: `"Spoonful Contact" <${process.env.SMTP_USER}>`,
      to: process.env.CONTACT_EMAIL,
      subject: "New Contact Message",
      text: `From: ${name} (${email})\n\n${message}`,
    });

    res.status(200).json({ success: true, message: "Message sent successfully." });
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ success: false, message: "Something went wrong." });
  }
});

//api for messages displaing in Admin page
app.get("/contacts", async (req, res) => {
  // Optional: Check if admin
  const messages = await Contact.find().sort({ createdAt: -1 });
  res.json(messages);
});


app.listen(port, (error) => {
  if (!error) {
    console.log("Server Running on Port" + port);
  } else {
    console.log("Error" + error);
  }
});
