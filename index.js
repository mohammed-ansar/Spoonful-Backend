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
const { OAuth2Client } = require("google-auth-library");
const { createSlugBase } = require("./utils/slug");

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
const { v2: cloudinary } = require("cloudinary");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
// const multer = require('multer');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "products", // Cloudinary folder name
    allowed_formats: ["jpg", "png", "jpeg"],
  },
});

const upload = multer({ storage });
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const createAuthToken = (user) =>
  jwt.sign(
    {
      user: {
        id: user.id,
        role: user.role,
      },
    },
    process.env.JWT_SECRET
  );

const createEmptyCart = () => {
  const cart = {};
  for (let i = 0; i < 300; i++) {
    cart[i] = 0;
  }
  return cart;
};

const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

//Creating Upload Endpoint for Images

// app.use("/images", express.static("upload/images"));

app.post("/upload", verifyToken, verifyAdmin, upload.array("product", 4), (req, res) => {
  try {
    const image_urls = req.files.map((file) => file.path);
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
  googleId: {
    type: String,
    unique: true,
    sparse: true,
  },
  authProvider: {
    type: String,
    enum: ["local", "google"],
    default: "local",
  },
  profileImage: {
    type: String,
  },
  emailVerified: {
    type: Boolean,
    default: false,
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
  claimedCoupons: [{ type: mongoose.Schema.Types.ObjectId, ref: "Coupon" }],
  spoonPoints: { type: Number, default: 0 },
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
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const user = new Users({
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword,
    authProvider: "local",
    cartData: createEmptyCart(),
    role: "user",
  });

  await user.save();

  const token = createAuthToken(user);
  res.json({ success: true, token });
});

//for security
function verifyToken(req, res, next) {
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
}

async function verifyAdmin(req, res, next) {
  try {
    const user = await Users.findById(req.user.id);

    if (!user || user.role !== "admin") {
      return res.status(403).json({ success: false, message: "Access denied" });
    }

    next();
  } catch (error) {
    console.error("Admin verification error:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
}

function verifyOwnUserParam(paramName = "userId") {
  return (req, res, next) => {
    if (req.params[paramName] !== req.user.id) {
      return res.status(403).json({ success: false, message: "Access denied" });
    }

    next();
  };
}

// Creating Endpoint for user login

app.post("/login", async (req, res) => {
  let user = await Users.findOne({ email: req.body.email });
  if (user) {
    if (!user.password) {
      return res.json({
        success: false,
        errors: "Please continue with Google for this account.",
      });
    }

    const passCompare = await bcrypt.compare(req.body.password, user.password);
    if (passCompare) {
      const token = createAuthToken(user);
      res.json({ success: true, token });
    } else {
      res.json({ success: false, errors: "Wrong Password" });
    }
  } else {
    res.json({ success: false, errors: "Wrong Email Id" });
  }
});

app.post("/auth/google", async (req, res) => {
  try {
    const { credential } = req.body;

    if (!process.env.GOOGLE_CLIENT_ID) {
      return res.status(500).json({
        success: false,
        errors: "Google login is not configured on the server.",
      });
    }

    if (!credential) {
      return res
        .status(400)
        .json({ success: false, errors: "Missing Google credential." });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    if (!payload?.email || !payload?.sub) {
      return res
        .status(401)
        .json({ success: false, errors: "Invalid Google account." });
    }

    if (!payload.email_verified) {
      return res.status(401).json({
        success: false,
        errors: "Please verify your Google email before continuing.",
      });
    }

    const email = payload.email.toLowerCase();
    const emailRegex = new RegExp(`^${escapeRegExp(email)}$`, "i");
    let user = await Users.findOne({ email: emailRegex });

    if (user?.role === "admin") {
      return res.status(403).json({
        success: false,
        errors: "Google login is available for customer accounts only.",
      });
    }

    if (user) {
      let changed = false;

      if (!user.googleId) {
        user.googleId = payload.sub;
        changed = true;
      } else if (user.googleId !== payload.sub) {
        return res.status(409).json({
          success: false,
          errors: "This email is already linked to a different Google account.",
        });
      }

      if (!user.authProvider) {
        user.authProvider = user.password ? "local" : "google";
        changed = true;
      }
      if (!user.profileImage && payload.picture) {
        user.profileImage = payload.picture;
        changed = true;
      }
      if (!user.emailVerified) {
        user.emailVerified = true;
        changed = true;
      }
      if (changed) await user.save();
    } else {
      user = new Users({
        name: payload.name || email.split("@")[0],
        email,
        googleId: payload.sub,
        authProvider: "google",
        profileImage: payload.picture,
        emailVerified: true,
        cartData: createEmptyCart(),
        role: "user",
      });

      await user.save();
    }

    const token = createAuthToken(user);
    res.json({ success: true, token });
  } catch (error) {
    console.error("Google auth error:", error);
    res.status(401).json({
      success: false,
      errors: "Google login failed. Please try again.",
    });
  }
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

// Endpoint to change user name and email
app.put("/update-profile", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { name, email } = req.body;

    // Check if new email already exists for someone else
    const existing = await Users.findOne({ email });
    if (existing && existing._id.toString() !== userId) {
      return res
        .status(400)
        .json({ success: false, message: "Email already in use" });
    }

    const updatedUser = await Users.findByIdAndUpdate(
      userId,
      { name, email },
      { new: true }
    ).select("-password");

    res.json({ success: true, user: updatedUser });
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Endpoint to change password
app.put("/change-password", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { currentPassword, newPassword } = req.body;

    const user = await Users.findById(userId);
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res
        .status(400)
        .json({ success: false, message: "Current password is incorrect" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ success: true, message: "Password changed successfully" });
  } catch (error) {
    console.error("Error changing password:", error);
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
const productVariantSchema = new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  image: { type: String, default: "" },
  stock: { type: Number },
});

const Product = mongoose.model("Product", {
  id: {
    type: Number,
    required: true,
  },
  name: {
    type: String,
    required: true,
  },
  slug: {
    type: String,
    unique: true,
    sparse: true,
    index: true,
  },
  image: {
    type: [String],
    required: true,
  },
  category: {
    type: String,
    required: true,
  },
  quantity: {
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
  variants: { type: [productVariantSchema], default: [] },
  featured: { type: Boolean, default: false },
  isOffer: { type: Boolean, default: false },
  offerText: { type: String, default: "" },
  offerBadge: { type: String, default: "" },
  displayOrder: { type: Number, default: 0 },
  isVisible: { type: Boolean, default: true },
  productLabel: { type: String, default: "" },
  stockQuantity: { type: Number },
  suitableAge: { type: String, default: "" },
  benefits: { type: [String], default: [] },
  ingredients: { type: [String], default: [] },
  allergenNote: { type: String, default: "" },
  safetyNote: { type: String, default: "" },
  preparationInstructions: { type: [String], default: [] },
  storageInstructions: { type: String, default: "" },
  shelfLife: { type: String, default: "" },
  deliveryInfo: { type: String, default: "" },
  faqs: [
    {
      question: { type: String },
      answer: { type: String },
    },
  ],
  reviews: [reviewSchema],
});

const truthyQuery = (value) => value === true || value === "true" || value === "1";
const hasFiniteNumber = (value) => Number.isFinite(Number(value));
const isObjectId = (value) =>
  typeof value === "string" &&
  /^[0-9a-fA-F]{24}$/.test(value) &&
  mongoose.Types.ObjectId.isValid(value);
const normalizeVariants = (variants = []) =>
  Array.isArray(variants)
    ? variants
        .map((variant) => ({
          name: String(variant.name || "").trim(),
          price: Number(variant.price),
          image: String(variant.image || "").trim(),
          stock:
            variant.stock === "" || typeof variant.stock === "undefined"
              ? undefined
              : Number(variant.stock),
        }))
        .filter((variant) => variant.name && Number.isFinite(variant.price))
    : [];

const getProductStock = (product, variant) => {
  if (variant && hasFiniteNumber(variant.stock)) return Number(variant.stock);
  if (hasFiniteNumber(product.stockQuantity)) return Number(product.stockQuantity);
  return null;
};

const ensurePurchasable = (product, variant, quantity) => {
  if (!product.available || product.isVisible === false) {
    const error = new Error("Product is unavailable");
    error.statusCode = 400;
    throw error;
  }

  const stock = getProductStock(product, variant);
  if (stock !== null && stock < quantity) {
    const error = new Error(stock <= 0 ? "Product is out of stock" : "Insufficient stock");
    error.statusCode = 400;
    throw error;
  }
};

const generateUniqueProductSlug = async (value, excludeMongoId) => {
  const baseSlug = createSlugBase(value);
  let slug = baseSlug;
  let suffix = 2;

  while (
    await Product.exists({
      slug,
      ...(excludeMongoId ? { _id: { $ne: excludeMongoId } } : {}),
    })
  ) {
    slug = `${baseSlug}-${suffix}`;
    suffix += 1;
  }

  return slug;
};

const resolveProductIdentifier = async (identifier) => {
  const normalizedIdentifier = createSlugBase(identifier);
  const slugMatch = await Product.findOne({ slug: normalizedIdentifier }).populate(
    "reviews.userId",
    "name"
  );

  if (slugMatch) return slugMatch;

  if (isObjectId(identifier)) {
    return Product.findById(identifier).populate("reviews.userId", "name");
  }

  if (/^\d+$/.test(identifier)) {
    return Product.findOne({ id: Number(identifier) }).populate(
      "reviews.userId",
      "name"
    );
  }

  return null;
};

//Creating API for Adding Product

app.post("/addproduct", verifyToken, verifyAdmin, async (req, res) => {
  let products = await Product.find({});
  let id;
  if (products.length > 0) {
    let last_product_array = products.slice(-1);
    let last_product = last_product_array[0];
    id = last_product.id + 1;
  } else {
    id = 1;
  }

  const requestedSlug = String(req.body.slug || "").trim();
  const slug = requestedSlug
    ? createSlugBase(requestedSlug)
    : await generateUniqueProductSlug(req.body.name);

  if (requestedSlug && (await Product.exists({ slug }))) {
    return res
      .status(400)
      .json({ success: false, message: "Product slug already exists" });
  }

  const product = new Product({
    id: id,
    name: req.body.name,
    slug,
    image: req.body.image,
    category: req.body.category,
    quantity: req.body.quantity,
    description: req.body.description,
    new_price: req.body.new_price,
    old_price: req.body.old_price,
    variants: normalizeVariants(req.body.variants),
    featured: Boolean(req.body.featured),
    isOffer: Boolean(req.body.isOffer),
    offerText: req.body.offerText || "",
    offerBadge: req.body.offerBadge || "",
    displayOrder: Number(req.body.displayOrder) || 0,
    isVisible:
      typeof req.body.isVisible === "undefined" ? true : Boolean(req.body.isVisible),
    productLabel: req.body.productLabel || "",
    stockQuantity:
      req.body.stockQuantity === "" || typeof req.body.stockQuantity === "undefined"
        ? undefined
        : Number(req.body.stockQuantity),
    suitableAge: req.body.suitableAge,
    benefits: req.body.benefits,
    ingredients: req.body.ingredients,
    allergenNote: req.body.allergenNote,
    safetyNote: req.body.safetyNote,
    preparationInstructions: req.body.preparationInstructions,
    storageInstructions: req.body.storageInstructions,
    shelfLife: req.body.shelfLife,
    deliveryInfo: req.body.deliveryInfo,
    faqs: req.body.faqs,
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

app.post("/removeproduct", verifyToken, verifyAdmin, async (req, res) => {
  await Product.findOneAndDelete({ id: req.body.id });
  console.log("Removed");
  res.json({
    success: true,
    name: req.body.name,
  });
});

//Creating API for geting all Products

app.get("/allproducts", async (req, res) => {
  try {
    const includeHidden = truthyQuery(req.query.includeHidden);
    if (includeHidden) {
      const bearerHeader = req.headers["authorization"];
      const token = bearerHeader?.split(" ")[1];
      let decoded = null;
      try {
        decoded = token ? jwt.verify(token, process.env.JWT_SECRET) : null;
      } catch {
        return res.status(403).json({ success: false, message: "Access denied" });
      }
      const user = decoded?.user?.id ? await Users.findById(decoded.user.id) : null;
      if (!user || user.role !== "admin") {
        return res.status(403).json({ success: false, message: "Access denied" });
      }
    }

    const query = includeHidden ? {} : { isVisible: { $ne: false } };
    const products = await Product.find(query).sort({
      displayOrder: 1,
      date: -1,
      _id: 1,
    });

    const productsWithRating = products.map((product) => {
      const avgRating =
        product.reviews.length > 0
          ? product.reviews.reduce((sum, r) => sum + r.rating, 0) /
            product.reviews.length
          : 0;
      console.log(avgRating);

      return {
        ...product.toObject(),
        averageRating: avgRating,
      };
    });

    console.log("All Products with Ratings are Fetched");
    res.json(productsWithRating);
  } catch (err) {
    console.error("Error fetching products:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// API: /updateproduct
app.post("/updateproduct", verifyToken, verifyAdmin, async (req, res) => {
  const {
    id,
    name,
    description,
    image,
    category,
    quantity,
    new_price,
    old_price,
    slug,
    suitableAge,
    variants,
    featured,
    isOffer,
    offerText,
    offerBadge,
    displayOrder,
    isVisible,
    productLabel,
    stockQuantity,
    benefits,
    ingredients,
    allergenNote,
    safetyNote,
    preparationInstructions,
    storageInstructions,
    shelfLife,
    deliveryInfo,
    faqs,
  } = req.body;

  try {
    const existingProduct = await Product.findOne({ id });

    if (!existingProduct) {
      return res
        .status(404)
        .json({ success: false, message: "Product not found" });
    }

    const requestedSlug = String(slug || "").trim();
    const nextSlug = requestedSlug
      ? createSlugBase(requestedSlug)
      : existingProduct.slug || (await generateUniqueProductSlug(name, existingProduct._id));
    const duplicateSlug = await Product.exists({
      slug: nextSlug,
      _id: { $ne: existingProduct._id },
    });

    if (duplicateSlug) {
      return res
        .status(400)
        .json({ success: false, message: "Product slug already exists" });
    }

    const updatedProduct = await Product.findOneAndUpdate(
      { id: id },
      {
        name,
        slug: nextSlug,
        description,
        image,
        category,
        quantity,
        new_price,
        old_price,
        suitableAge,
        variants: normalizeVariants(variants),
        featured: Boolean(featured),
        isOffer: Boolean(isOffer),
        offerText: offerText || "",
        offerBadge: offerBadge || "",
        displayOrder: Number(displayOrder) || 0,
        isVisible:
          typeof isVisible === "undefined" ? true : Boolean(isVisible),
        productLabel: productLabel || "",
        stockQuantity:
          stockQuantity === "" || typeof stockQuantity === "undefined"
            ? undefined
            : Number(stockQuantity),
        benefits,
        ingredients,
        allergenNote,
        safetyNote,
        preparationInstructions,
        storageInstructions,
        shelfLife,
        deliveryInfo,
        faqs,
      },
      { new: true }
    );

    if (!updatedProduct) {
      return res
        .status(404)
        .json({ success: false, message: "Product not found" });
    }

    res.json({ success: true, product: updatedProduct });
  } catch (err) {
    console.error("Update failed:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// schema for cart

const CartItemSchema = new mongoose.Schema({
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Product",
    required: true,
  },
  variantId: { type: mongoose.Schema.Types.ObjectId },
  selectedVariant: {
    name: { type: String },
    price: { type: Number },
  },
  quantity: { type: Number, required: true, default: 1 },
});

const CartSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true }, // Or mongoose.Schema.Types.ObjectId if using users
  items: [CartItemSchema],
});

const Cart = mongoose.model("Cart", CartSchema);

// Creating endpoint for adding products in cart data

app.post("/cart/add", verifyToken, async (req, res) => {
  const { userId, productId, variantId, quantity = 1 } = req.body;
  const ownerId = req.user.id;

  console.log("Adding to cart - userId:", userId, "productId:", productId);

  if (userId && userId !== ownerId) {
    return res.status(403).json({ success: false, message: "Access denied" });
  }

  if (!productId) {
    return res
      .status(400)
      .json({ success: false, message: "Missing productId" });
  }

  try {
    const requestedQuantity = Number(quantity);
    if (!Number.isFinite(requestedQuantity) || requestedQuantity <= 0) {
      return res.status(400).json({ success: false, message: "Invalid quantity" });
    }

    const product = await Product.findById(productId);
    if (!product) {
      return res.status(404).json({ success: false, message: "Product not found" });
    }

    const selectedVariant = variantId
      ? product.variants.id(variantId)
      : product.variants?.length
        ? product.variants[0]
        : null;

    if (product.variants?.length && !selectedVariant) {
      return res.status(400).json({ success: false, message: "Please select a valid variant" });
    }

    ensurePurchasable(product, selectedVariant, requestedQuantity);

    let cart = await Cart.findOne({ userId: ownerId });

    if (!cart) {
      cart = new Cart({ userId: ownerId, items: [] });
    }

    const existingItem = cart.items.find(
      (item) =>
        item.productId.toString() === productId &&
        String(item.variantId || "") === String(selectedVariant?._id || "")
    );

    if (existingItem) {
      ensurePurchasable(product, selectedVariant, existingItem.quantity + requestedQuantity);
      existingItem.quantity += requestedQuantity;
    } else {
      cart.items.push({
        productId,
        variantId: selectedVariant?._id,
        selectedVariant: selectedVariant
          ? { name: selectedVariant.name, price: selectedVariant.price }
          : undefined,
        quantity: requestedQuantity,
      });
    }

    await cart.save();

    res.json({ success: true, message: "Item added to cart", cart });
  } catch (error) {
    console.error("Add to cart error:", error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

// POST /cart/update
app.post("/cart/update", verifyToken, async (req, res) => {
  const { userId, productId, variantId, quantity } = req.body;
  const ownerId = req.user.id;

  if (userId && userId !== ownerId) {
    return res.status(403).json({ success: false, message: "Access denied" });
  }

  try {
    const cart = await Cart.findOne({ userId: ownerId });

    if (!cart)
      return res
        .status(404)
        .json({ success: false, message: "Cart not found" });

    const item = cart.items.find(
      (item) =>
        item.productId.toString() === productId &&
        String(item.variantId || "") === String(variantId || "")
    );

    if (!item)
      return res
        .status(404)
        .json({ success: false, message: "Product not in cart" });

    if (quantity <= 0) {
      cart.items = cart.items.filter(
        (item) =>
          !(
            item.productId.toString() === productId &&
            String(item.variantId || "") === String(variantId || "")
          )
      );
    } else {
      const product = await Product.findById(productId);
      if (!product) {
        return res.status(404).json({ success: false, message: "Product not found" });
      }
      const selectedVariant = variantId ? product.variants.id(variantId) : null;
      ensurePurchasable(product, selectedVariant, Number(quantity));
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
app.post("/cart/remove", verifyToken, async (req, res) => {
  const { userId, productId, variantId } = req.body;
  const ownerId = req.user.id;

  if (userId && userId !== ownerId) {
    return res.status(403).json({ success: false, message: "Access denied" });
  }

  try {
    const cart = await Cart.findOne({ userId: ownerId });

    if (!cart) return res.status(404).json({ success: false });

    cart.items = cart.items.filter(
      (item) =>
        !(
          item.productId.toString() === productId &&
          String(item.variantId || "") === String(variantId || "")
        )
    );

    await cart.save();

    res.json({ success: true, message: "Item removed from cart" });
  } catch (error) {
    console.error("Remove cart item error:", error);
    res.status(500).json({ success: false });
  }
});

// GET /cart/:userId
app.get("/cart/:userId", verifyToken, verifyOwnUserParam("userId"), async (req, res) => {
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

// PUT /address/update/:id
app.put("/address/update/:id", verifyToken, async (req, res) => {
  try {
    const updatedAddress = await Address.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.id },
      req.body,
      { new: true }
    );

    if (!updatedAddress) {
      return res
        .status(404)
        .json({ success: false, message: "Address not found" });
    }

    res.json({
      success: true,
      message: "Address updated",
      address: updatedAddress,
    });
  } catch (error) {
    console.error("Update error:", error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

// GET /address/get/:id
app.get("/address/get/:id", verifyToken, async (req, res) => {
  try {
    const address = await Address.findOne({
      _id: req.params.id,
      userId: req.user.id,
    });

    if (!address) {
      return res
        .status(404)
        .json({ success: false, message: "Address not found" });
    }

    res.json({ success: true, address });
  } catch (error) {
    console.error("Get single address error:", error);
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
      variantId: { type: mongoose.Schema.Types.ObjectId },
      selectedVariant: {
        name: { type: String },
        price: { type: Number },
      },
    },
  ],
  codFee: { type: Number, default: 0 },
  subtotal: { type: Number, default: 0 },
  shippingFee: { type: Number, default: 0 },
  discountAmount: { type: Number, default: 0 },
  finalTotal: { type: Number, default: 0 },
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
    enum: [
      "pending",
      "placed",
      "confirmed",
      "packed",
      "shipped",
      "delivered",
      "cancelled",
    ],
    default: "placed",
  },
  coupon: {
    code: { type: String },
    rewardType: {
      type: String,
      enum: ["discount", "points", "sample", "recipe", "cashback"],
    },
    rewardValue: { type: mongoose.Schema.Types.Mixed }, // allow string or number
  },

  razorpayOrderId: { type: String },
  razorpayPaymentId: { type: String },
  razorpaySignature: { type: String },
  createdAt: { type: Date, default: Date.now },
});

const Order = mongoose.model("Order", orderSchema);

const SHIPPING_CHARGE = 50;
const FREE_SHIPPING_MINIMUM = 450;
const COD_CONVENIENCE_FEE = 30;

const toMoney = (amount) => Math.max(0, Math.round(Number(amount || 0)));

const calculateOrderPricing = async ({
  items,
  userId,
  couponCode,
  includeCodFee = false,
}) => {
  const orderItems = [];
  let subtotal = 0;

  // Recalculate every line item from database prices so the client cannot
  // change product price, quantity math, shipping, or discount totals.
  for (const item of items) {
    const quantity = Number(item.quantity);

    if (!Number.isFinite(quantity) || quantity <= 0) {
      const error = new Error("Invalid item quantity");
      error.statusCode = 400;
      throw error;
    }

    const product = await Product.findById(item.productId);
    if (!product) {
      const error = new Error("Product not found");
      error.statusCode = 404;
      throw error;
    }

    const selectedVariant = item.variantId
      ? product.variants.id(item.variantId)
      : product.variants?.length
        ? product.variants[0]
        : null;

    if (product.variants?.length && !selectedVariant) {
      const error = new Error("Please select a valid product variant");
      error.statusCode = 400;
      throw error;
    }

    ensurePurchasable(product, selectedVariant, quantity);

    const priceAtPurchase = selectedVariant
      ? Number(selectedVariant.price)
      : Number(product.new_price);
    subtotal += priceAtPurchase * quantity;

    orderItems.push({
      productId: product._id,
      quantity,
      priceAtPurchase,
      variantId: selectedVariant?._id,
      selectedVariant: selectedVariant
        ? { name: selectedVariant.name, price: selectedVariant.price }
        : undefined,
    });
  }

  subtotal = toMoney(subtotal);

  let discountAmount = 0;
  let appliedCoupon;

  if (couponCode) {
    const claimedCoupon = await ClaimedCoupon.findOne({
      code: couponCode.trim(),
      userId,
      status: "Not Used",
    });

    if (
      claimedCoupon &&
      claimedCoupon.rewardType === "discount" &&
      Number(claimedCoupon.rewardValue) > 0
    ) {
      discountAmount = Math.min(
        subtotal,
        toMoney(Number(claimedCoupon.rewardValue))
      );
      appliedCoupon = claimedCoupon;
    }
  }

  const discountedSubtotal = toMoney(subtotal - discountAmount);
  const shippingFee =
    orderItems.length === 0 || discountedSubtotal >= FREE_SHIPPING_MINIMUM
      ? 0
      : SHIPPING_CHARGE;
  const codFee = includeCodFee ? COD_CONVENIENCE_FEE : 0;
  const finalTotal = toMoney(discountedSubtotal + shippingFee + codFee);

  return {
    orderItems,
    subtotal,
    shippingFee,
    discountAmount,
    codFee,
    finalTotal,
    appliedCoupon,
  };
};

// POST /order/create
app.post("/order/create", verifyToken, async (req, res) => {
  try {
    const {
      addressId,
      items,
      paymentMethod,
      paymentStatus,
      razorpayOrderId,
      couponCode,
    } = req.body;

    const userId = req.user.id;

    if (!userId || !addressId || !items || items.length === 0) {
      return res.status(400).json({ message: "Missing required order data" });
    }

    // Prevent duplicate Razorpay orders
    if (paymentMethod === "razorpay" && razorpayOrderId) {
      const existing = await Order.findOne({ razorpayOrderId });
      if (existing) {
        return res.status(400).json({ message: "Duplicate Razorpay order" });
      }
    }

    const pricing = await calculateOrderPricing({
      items,
      userId,
      couponCode,
      includeCodFee: paymentMethod === "cod",
    });

    const newOrder = await Order.create({
      userId,
      addressId,
      items: pricing.orderItems,
      subtotal: pricing.subtotal,
      shippingFee: pricing.shippingFee,
      discountAmount: pricing.discountAmount,
      finalTotal: pricing.finalTotal,
      totalAmount: pricing.finalTotal,
      codFee: pricing.codFee,
      paymentMethod,
      paymentStatus: paymentStatus || "pending",
      razorpayOrderId,
      coupon: pricing.appliedCoupon
        ? {
            code: pricing.appliedCoupon.code,
            rewardType: pricing.appliedCoupon.rewardType,
            rewardValue: pricing.appliedCoupon.rewardValue,
          }
        : undefined,
    });

    // Mark coupon as used
    if (pricing.appliedCoupon) {
      await ClaimedCoupon.findOneAndUpdate(
        { code: pricing.appliedCoupon.code, userId },
        { $set: { status: "Used" } }
      );
    }

    return res.status(201).json({ success: true, order: newOrder });
  } catch (err) {
    console.error("Order creation error:", err);
    if (err.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
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
        product: item.productId
          ? {
              name: item.productId.name,
              // Add other fields as needed
            }
          : {
              name: "Product Deleted",
            },
        quantity: item.quantity,
        selectedVariant: item.selectedVariant || null,
        priceAtPurchase: item.priceAtPurchase,
      })),
      address: {
        fullName: order.addressId.fullName,
        area: order.addressId.area,
        city: order.addressId.city,
        state: order.addressId.state,
        phoneNumber: order.addressId.phoneNumber,
      },
      amount: order.totalAmount,
      subtotal: order.subtotal,
      shippingFee: order.shippingFee,
      discountAmount: order.discountAmount,
      finalTotal: order.finalTotal,
      date: order.createdAt,
      status: order.orderStatus,
      paymentMethod: order.paymentMethod,
      paymentStatus: order.paymentStatus,
      coupon: order.coupon
        ? {
            code: order.coupon.code,
            rewardType: order.coupon.rewardType,
            rewardValue: order.coupon.rewardValue,
          }
        : null,
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

// app.get("/admin/orders", verifyToken, async (req, res) => {
//   try {
//     const userId = req.user.id;
//     const user = await Users.findById(userId);

//     if (!user || user.role !== "admin") {
//       return res.status(403).json({ success: false, message: "Access denied" });
//     }

//     const orders = await Order.find({})
//       .populate("items.productId")
//       .populate("addressId")
//       .sort({ createdAt: -1 });

//     const formattedOrders = orders.map((order) => ({
//       items: order.items.map((item) => ({
//         product: {
//           name: item.productId.name,
//         },
//         quantity: item.quantity,
//       })),
//       address: {
//         fullName: order.addressId.fullName,
//         area: order.addressId.area,
//         city: order.addressId.city,
//         state: order.addressId.state,
//         phoneNumber: order.addressId.phoneNumber,
//       },
//       amount: order.totalAmount,
//       date: order.createdAt,
//       status: order.orderStatus,
//       paymentMethod: order.paymentMethod,
//       paymentStatus: order.paymentStatus,
//     }));

//     res.json({ success: true, orders: formattedOrders });
//   } catch (error) {
//     console.error("Error fetching all orders:", error);
//     res.status(500).json({ success: false, message: "Internal server error" });
//   }
// });
const ORDER_STATUSES = [
  "pending",
  "confirmed",
  "packed",
  "shipped",
  "delivered",
  "cancelled",
];

app.get("/admin/orders", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const orders = await Order.find({})
      .populate("items.productId")
      .populate("addressId")
      .sort({ createdAt: -1 });

    const formattedOrders = orders.map((order) => ({
      id: order._id,
      _id: order._id,
      items: order.items.map((item) => ({
        product: {
          name: item.productId?.name || "Unknown Product",
        },
        quantity: item.quantity,
        selectedVariant: item.selectedVariant || null,
        priceAtPurchase: item.priceAtPurchase,
      })),
      address: {
        fullName: order.addressId?.fullName || "N/A",
        area: order.addressId?.area || "N/A",
        city: order.addressId?.city || "N/A",
        state: order.addressId?.state || "N/A",
        phoneNumber: order.addressId?.phoneNumber || "N/A",
      },
      amount: order.totalAmount,
      subtotal: order.subtotal,
      shippingFee: order.shippingFee,
      discountAmount: order.discountAmount,
      finalTotal: order.finalTotal,
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

app.put("/admin/orders/:id/status", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const { status } = req.body;

    if (!ORDER_STATUSES.includes(status)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid order status" });
    }

    const order = await Order.findByIdAndUpdate(
      req.params.id,
      { orderStatus: status },
      { new: true }
    );

    if (!order) {
      return res
        .status(404)
        .json({ success: false, message: "Order not found" });
    }

    return res.json({
      success: true,
      message: "Order status updated",
      order,
    });
  } catch (error) {
    console.error("Order status update error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
});


//api for razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

app.post("/razorpay/create-order", verifyToken, async (req, res) => {
  try {
    const { addressId, items, couponCode } = req.body;

    const userId = req.user.id;

    if (!userId || !addressId || !items || items.length === 0) {
      return res.status(400).json({ message: "Missing required data" });
    }

    const pricing = await calculateOrderPricing({
      items,
      userId,
      couponCode,
      includeCodFee: false,
    });

    // STEP 1: Create Order in MongoDB (with coupon details if any)
    const newOrder = await Order.create({
      userId,
      addressId,
      items: pricing.orderItems,
      subtotal: pricing.subtotal,
      shippingFee: pricing.shippingFee,
      discountAmount: pricing.discountAmount,
      finalTotal: pricing.finalTotal,
      totalAmount: pricing.finalTotal,
      paymentMethod: "razorpay",
      paymentStatus: "pending",
      coupon: pricing.appliedCoupon
        ? {
            code: pricing.appliedCoupon.code,
            rewardType: pricing.appliedCoupon.rewardType,
            rewardValue: pricing.appliedCoupon.rewardValue,
          }
        : undefined,
    });

    // STEP 2: Create Razorpay Order
    const razorpayOrder = await razorpay.orders.create({
      amount: pricing.finalTotal * 100, // in paise
      currency: "INR",
      receipt: `receipt_order_${newOrder._id}`,
      payment_capture: 1,
    });

    // STEP 3: Update the order with razorpayOrderId
    newOrder.razorpayOrderId = razorpayOrder.id;
    await newOrder.save();

    return res.status(200).json({
      success: true,
      razorpayOrder,
      mongoOrderId: newOrder._id,
      pricing: {
        subtotal: pricing.subtotal,
        shippingFee: pricing.shippingFee,
        discountAmount: pricing.discountAmount,
        finalTotal: pricing.finalTotal,
      },
    });
  } catch (err) {
    console.error("Create Razorpay Order Failed:", err);
    if (err.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
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
      // After payment verified and order updated
      const couponCode =
        order?.coupon?.code || req.body.couponCode || req.body.code || null;

      const userId = order.userId;

      if (couponCode) {
        await ClaimedCoupon.findOneAndUpdate(
          { code: couponCode, userId },
          { $set: { status: "Used" } }
        );
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
  const userId = req.user.id;
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

    // ✅ Re-fetch product with populated reviews
    const updatedProduct = await Product.findById(productId).populate(
      "reviews.userId",
      "name"
    );

    res.status(201).json(updatedProduct);
  } catch (error) {
    console.error("Review creation failed:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/product/:identifier", async (req, res) => {
  try {
    const product = await resolveProductIdentifier(req.params.identifier);

    if (!product) return res.status(404).json({ message: "Product not found" });
    if (product.isVisible === false) {
      return res.status(404).json({ message: "Product not found" });
    }

    const averageRating =
      product.reviews.length > 0
        ? product.reviews.reduce((acc, r) => acc + r.rating, 0) /
          product.reviews.length
        : 0;

    res.json({
      ...product.toObject(),
      averageRating,
    });
  } catch (error) {
    console.error("Product lookup failed:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// PATCH /reviews/:productId
app.patch("/reviews/:productId", verifyToken, async (req, res) => {
  const { rating, comment } = req.body;
  const { productId } = req.params;
  const userId = req.user.id;

  try {
    const product = await Product.findById(productId);
    const review = product.reviews.find((r) => r.userId.toString() === userId);

    if (!review) return res.status(404).json({ message: "Review not found" });

    review.rating = rating;
    review.comment = comment;

    await product.save();
    res.json({ message: "Review updated" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

/// DELETE /reviews/:productId/:reviewId
app.delete("/reviews/:productId/:reviewId", verifyToken, async (req, res) => {
  const { productId, reviewId } = req.params;
  const userId = req.user.id;

  try {
    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ message: "Product not found" });

    const review = product.reviews.find((r) => r._id.toString() === reviewId);

    // console.log("Found review:", review);

    if (!review) return res.status(404).json({ message: "Review not found" });
    if (review.userId.toString() !== userId)
      return res.status(403).json({ message: "Unauthorized" });

    // Remove review by filtering
    product.reviews = product.reviews.filter(
      (r) => r._id.toString() !== reviewId
    );

    await product.save();

    res.json({ message: "Review deleted" });
  } catch (err) {
    console.error("Error deleting review:", err);
    res.status(500).json({ message: "Server error" });
  }
});

//Contact Schema
const contactSchema = new mongoose.Schema(
  {
    name: String,
    email: String,
    message: String,
  },
  { timestamps: true }
);

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

    res
      .status(200)
      .json({ success: true, message: "Message sent successfully." });
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ success: false, message: "Something went wrong." });
  }
});

//api for messages displaing in Admin page
app.get("/contacts", verifyToken, verifyAdmin, async (req, res) => {
  const messages = await Contact.find().sort({ createdAt: -1 });
  res.json(messages);
});

// Schema for coupon
const couponSchema = new mongoose.Schema({
  code: { type: String, unique: true },
  rewardType: {
    type: String,
    enum: ["discount", "points", "sample", "recipe"],
    required: true,
  },
  rewardValue: { type: mongoose.Schema.Types.Mixed }, // 10, 20, or sample ID
  claimed: { type: Boolean, default: false },
  claimedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Users",
    default: null,
  },
  used: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

const Coupon = mongoose.model("Coupon", couponSchema);

// API route for claiming a coupon
app.post("/coupon/claim", verifyToken, async (req, res) => {
  const { code, userId } = req.body;
  const ownerId = req.user.id;

  if (userId && userId !== ownerId) {
    return res.status(403).json({ success: false, msg: "Access denied." });
  }

  if (!code) {
    return res
      .status(400)
      .json({ success: false, msg: "Coupon code is required." });
  }

  try {
    const coupon = await Coupon.findOne({ code });

    if (!coupon) {
      return res.status(404).json({ success: false, msg: "Coupon not found." });
    }

    if (coupon.claimed) {
      return res
        .status(400)
        .json({ success: false, msg: "Coupon already claimed." });
    }

    // Mark coupon as claimed
    coupon.claimed = true;
    coupon.claimedBy = ownerId;
    await coupon.save();

    // Add to ClaimedCoupon collection
    const claimed = new ClaimedCoupon({
      userId: ownerId,
      code: coupon.code,
      rewardValue: coupon.rewardValue, // match with frontend
      rewardType: coupon.rewardType,
      status: "Not Used",
    });
    await claimed.save();

    // Add this inside your try block, after coupon is claimed and saved
    if (coupon.rewardType === "points") {
      await ClaimedCoupon.updateOne({ code, userId: ownerId }, { status: "Used" });

      const user = await Users.findById(ownerId);
      if (user) {
        user.spoonPoints =
          (user.spoonPoints || 0) + parseInt(coupon.rewardValue);
        await user.save();
      }
    }

    return res.status(200).json({
      success: true,
      msg: "Coupon claimed successfully.",
      rewardType: coupon.rewardType,
    });
  } catch (err) {
    console.error("Error claiming coupon:", err);
    return res
      .status(500)
      .json({ success: false, msg: "Something went wrong." });
  }
});

// Coupon Insert API
app.post("/insert-coupons", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const coupons = req.body;

    if (!Array.isArray(coupons)) {
      return res
        .status(400)
        .json({ error: "Invalid data format (expecting array)" });
    }

    await Coupon.insertMany(coupons, { ordered: false });

    return res.status(200).json({ message: "Coupons inserted successfully" });
  } catch (error) {
    console.error("Insert error:", error);
    return res.status(500).json({ error: "Failed to insert coupons" });
  }
});

//Schema for claimed coupons
const claimedCouponSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  code: { type: String, required: true },
  rewardValue: { type: String, required: true },
  rewardType: {
    type: String,
    enum: ["discount", "points", "sample", "recipe", "cashback"],
    required: true,
  },
  status: { type: String, default: "Not Used" }, // or "Used"
});

const ClaimedCoupon = mongoose.model("ClaimedCoupon", claimedCouponSchema);

// GET /coupon/claimed/:userId
app.get("/coupon/claimed/:userId", verifyToken, verifyOwnUserParam("userId"), async (req, res) => {
  const { userId } = req.params;
  try {
    const claimedCoupons = await ClaimedCoupon.find({ userId }).sort({
      _id: -1,
    });

    res.status(200).json({
      success: true,
      claimedCoupons,
    });
  } catch (error) {
    console.error("Error fetching claimed coupons:", error);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// Redeem SpoonPoints as Discount Coupon
app.post("/redeem-discount", verifyToken, async (req, res) => {
  const userId = req.user.id;
  try {
    const user = await Users.findById(userId);
    if (!user || user.spoonPoints < 100) {
      return res
        .status(400)
        .json({ success: false, msg: "Not enough points." });
    }

    const pointsToUse = 100;
    const discountAmount = 10;
    const couponCode = `SPD-${Date.now().toString().slice(-5)}`;

    // Create a new Coupon
    const newCoupon = new Coupon({
      code: couponCode,
      rewardValue: discountAmount,
      rewardType: "discount",
      claimed: false,
      claimedBy: userId,
      used: false,
    });

    await newCoupon.save();

    // Deduct points
    user.spoonPoints -= pointsToUse;
    await user.save();

    return res.json({ success: true, msg: "Coupon created", code: couponCode });
  } catch (error) {
    console.error("Discount redeem error:", error);
    return res.status(500).json({ success: false, msg: "Server error" });
  }
});

// Schema for cashback
const cashbackSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Users",
    required: true,
  },
  upiId: { type: String, required: true },
  amount: { type: Number, required: true },
  status: {
    type: String,
    enum: ["Pending", "Approved", "Rejected"],
    default: "Pending",
  },
  requestedAt: { type: Date, default: Date.now },
});

const CashbackRequest = mongoose.model("CashbackRequest", cashbackSchema);

// Redeem SpoonPoints as Cashback
app.post("/redeem-cashback", verifyToken, async (req, res) => {
  const userId = req.user.id;
  const { upiId } = req.body;

  if (!upiId) {
    return res.status(400).json({ success: false, msg: "UPI ID required" });
  }

  try {
    const user = await Users.findById(userId);
    if (!user || user.spoonPoints < 100) {
      return res
        .status(400)
        .json({ success: false, msg: "Not enough points." });
    }

    const pointsToUse = 100;
    const cashbackAmount = 10;

    const cashback = new CashbackRequest({
      userId,
      upiId,
      amount: cashbackAmount,
      status: "Pending",
    });
    await cashback.save();

    // Deduct points
    user.spoonPoints -= pointsToUse;
    await user.save();

    return res.json({ success: true, msg: "Cashback request received" });
  } catch (error) {
    console.error("Cashback redeem error:", error);
    return res.status(500).json({ success: false, msg: "Server error" });
  }
});

// Backend: GET /user/spoonpoints
app.get("/user/spoonpoints", verifyToken, async (req, res) => {
  try {
    const user = await Users.findById(req.user.id);
    if (!user)
      return res.status(404).json({ success: false, msg: "User not found" });

    res.json({ success: true, spoonPoints: user.spoonPoints });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// POST /coupon/verify
app.post("/coupon/verify", verifyToken, async (req, res) => {
  const { code } = req.body;
  const userId = req.user.id;

  try {
    const claimedCoupon = await ClaimedCoupon.findOne({
      code: code.trim(),
      userId,
      status: "Not Used", // ✅ Correct field
    });

    if (!claimedCoupon) {
      return res.status(404).json({
        success: false,
        message: "Coupon not found or already used.",
      });
    }

    return res.status(200).json({
      success: true,
      coupon: claimedCoupon,
    });
  } catch (error) {
    console.error("Error verifying coupon:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// app.post("/admin/fix-spoonpoints", async (req, res) => {
//   try {
//     const users = await Users.find({});

//     for (const user of users) {
//       const claimed = await ClaimedCoupon.find({
//         userId: user._id,
//         rewardType: "points",
//       });

//       const totalPoints = claimed.reduce((acc, c) => {
//         const val = parseInt(c.rewardValue);
//         return acc + (isNaN(val) ? 0 : val);
//       }, 0);

//       user.spoonPoints = totalPoints;
//       await user.save();
//     }

//     return res.json({ success: true, msg: "SpoonPoints fixed for all users" });
//   } catch (err) {
//     console.error(err);
//     return res.status(500).json({ success: false, msg: "Server error" });
//   }
// });

// WARNING: Remove after running once or secure it properly (e.g. admin check)
// app.get("/admin/backfill-reward-types", async (req, res) => {
//   try {
//     const claimed = await ClaimedCoupon.find({ rewardType: { $exists: false } });

//     let updatedCount = 0;

//     for (const c of claimed) {
//       const original = await Coupon.findOne({ code: c.code });
//       if (original) {
//         c.rewardType = original.rewardType;
//         await c.save();
//         updatedCount++;
//       }
//     }

//     res.status(200).json({
//       success: true,
//       message: `Updated ${updatedCount} claimed coupons.`,
//     });
//   } catch (error) {
//     console.error("Backfill error:", error);
//     res.status(500).json({ success: false, message: "Server error" });
//   }
// });

app.listen(port, (error) => {
  if (!error) {
    console.log("Server Running on Port" + port);
  } else {
    console.log("Error" + error);
  }
});
