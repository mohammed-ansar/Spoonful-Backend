require("dotenv").config();

const mongoose = require("mongoose");
const { createSlugBase } = require("../utils/slug");

const reviewSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "Users" },
  rating: { type: Number, required: true },
  comment: { type: String },
  createdAt: { type: Date, default: Date.now },
});

const productVariantSchema = new mongoose.Schema({
  name: { type: String },
  price: { type: Number },
  image: { type: String },
  stock: { type: Number },
});

const productSchema = new mongoose.Schema({
  id: Number,
  name: String,
  slug: {
    type: String,
    unique: true,
    sparse: true,
    index: true,
  },
  image: [String],
  category: String,
  quantity: String,
  description: String,
  new_price: Number,
  old_price: Number,
  date: Date,
  available: Boolean,
  variants: [productVariantSchema],
  featured: Boolean,
  isOffer: Boolean,
  offerText: String,
  offerBadge: String,
  displayOrder: Number,
  isVisible: Boolean,
  productLabel: String,
  stockQuantity: Number,
  suitableAge: String,
  benefits: [String],
  ingredients: [String],
  allergenNote: String,
  safetyNote: String,
  preparationInstructions: [String],
  storageInstructions: String,
  shelfLife: String,
  deliveryInfo: String,
  faqs: [{ question: String, answer: String }],
  reviews: [reviewSchema],
});

const Product = mongoose.model("Product", productSchema);

const generateUniqueSlug = async (value, excludeMongoId) => {
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

const run = async () => {
  if (!process.env.MONGODB_URI) {
    throw new Error("Missing MONGODB_URI");
  }

  await mongoose.connect(process.env.MONGODB_URI);

  const products = await Product.find({
    $or: [{ slug: { $exists: false } }, { slug: "" }, { slug: null }],
  }).sort({ id: 1, createdAt: 1 });

  let updatedCount = 0;

  for (const product of products) {
    const slug = await generateUniqueSlug(product.name, product._id);
    await Product.updateOne({ _id: product._id }, { $set: { slug } });
    updatedCount += 1;

    console.log("Generated slug:");
    console.log(`${product.name} -> ${slug}`);
    console.log("");
  }

  console.log("Migration complete:");
  console.log(`${updatedCount} products updated.`);

  await mongoose.disconnect();
};

run().catch(async (error) => {
  console.error("Migration failed:", error);
  await mongoose.disconnect();
  process.exit(1);
});
