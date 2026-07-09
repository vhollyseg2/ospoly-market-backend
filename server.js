require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// MongoDB Connection with retry
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    console.log('✅ MongoDB Connected');
    return true;
  } catch (err) {
    console.error('❌ MongoDB Error:', err.message);
    return false;
  }
};

// Schemas
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  phone: String,
  role: { type: String, enum: ['buyer', 'seller', 'admin'], default: 'buyer' },
  isVerified: { type: Boolean, default: false },
  isBanned: { type: Boolean, default: false },
  avatar: String,
  sellerProfile: { 
    storeName: String, 
    description: String,
    rating: { type: Number, default: 0 }, 
    totalSales: { type: Number, default: 0 }, 
    isApproved: { type: Boolean, default: true },
    responseRate: { type: Number, default: 95 },
    fulfillmentRate: { type: Number, default: 98 }
  },
  address: {
    street: String,
    city: String,
    state: String,
    zipCode: String
  },
  refreshToken: String,
  createdAt: { type: Date, default: Date.now }
});
userSchema.pre('save', async function(next) { if (!this.isModified('password')) return next(); this.password = await bcrypt.hash(this.password, 12); next(); });
userSchema.methods.comparePassword = function(c) { return bcrypt.compare(c, this.password); };
const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
  seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  description: String,
  price: { type: Number, required: true },
  originalPrice: Number,
  category: { type: String, required: true },
  subcategory: String,
  condition: { type: String, enum: ['new', 'used'], default: 'new' },
  images: [String],
  stock: { type: Number, default: 1 },
  brand: String, 
  location: String,
  views: { type: Number, default: 0 },
  isApproved: { type: Boolean, default: true },
  isFeatured: { type: Boolean, default: false },
  isFlashDeal: { type: Boolean, default: false },
  rating: { type: Number, default: 0 },
  reviewCount: { type: Number, default: 0 },
  minimumOrder: { type: Number, default: 1 },
  tags: [String],
  createdAt: { type: Date, default: Date.now }
});
const Product = mongoose.model('Product', productSchema);

const cartSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{ product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' }, quantity: { type: Number, default: 1 } }],
  updatedAt: { type: Date, default: Date.now }
});
const Cart = mongoose.model('Cart', cartSchema);

const orderSchema = new mongoose.Schema({
  buyer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{ 
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' }, 
    seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, 
    title: String, 
    image: String, 
    price: Number, 
    quantity: Number 
  }],
  totalAmount: Number, 
  shippingCost: { type: Number, default: 500 }, 
  finalAmount: Number,
  status: { type: String, enum: ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'], default: 'pending' },
  paymentStatus: { type: String, enum: ['pending', 'paid', 'failed', 'refunded'], default: 'pending' },
  paymentMethod: { type: String, default: 'cash_on_delivery' },
  shippingAddress: { fullName: String, phone: String, street: String, city: String, state: String },
  trackingNumber: String,
  notes: String,
  statusHistory: [{ status: String, timestamp: { type: Date, default: Date.now }, note: String }],
  createdAt: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema);

// Auth middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies?.accessToken;
  if (!token) return res.status(401).json({ success: false, message: 'No token provided' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    User.findById(decoded.id).then(user => {
      if (!user || user.isBanned) return res.status(401).json({ success: false, message: 'User not found' });
      req.user = user; next();
    });
  } catch (err) { res.status(401).json({ success: false, message: 'Invalid token' }); }
};

// Seed Database
const seedDatabase = async () => {
  try {
    // Create Admin
    let admin = await User.findOne({ email: 'admin@ospolymarket.com' });
    if (!admin) {
      admin = await User.create({
        name: 'Ospoly Admin',
        email: 'admin@ospolymarket.com',
        password: 'Admin@123456',
        role: 'admin',
        isVerified: true,
        phone: '+2348012345678',
        sellerProfile: { storeName: 'Ospoly Official Store', description: 'Official campus marketplace store', rating: 4.8, totalSales: 520, isApproved: true }
      });
      console.log('✅ Admin: admin@ospolymarket.com / Admin@123456');
    }

    // Create Seller
    let seller = await User.findOne({ email: 'seller@ospolymarket.com' });
    if (!seller) {
      seller = await User.create({
        name: 'TechWorld Store',
        email: 'seller@ospolymarket.com',
        password: 'Seller@123456',
        role: 'seller',
        isVerified: true,
        phone: '+2348098765432',
        sellerProfile: { storeName: 'TechWorld Gadgets', description: 'Your trusted tech gadget hub for all student needs', rating: 4.7, totalSales: 280, isApproved: true, responseRate: 98, fulfillmentRate: 99 }
      });
      console.log('✅ Seller: seller@ospolymarket.com / Seller@123456');
    }

    // Create Buyer
    let buyer = await User.findOne({ email: 'buyer@ospolymarket.com' });
    if (!buyer) {
      buyer = await User.create({
        name: 'John Student',
        email: 'buyer@ospolymarket.com',
        password: 'Buyer@123456',
        role: 'buyer',
        isVerified: true,
        phone: '+2348055555555'
      });
      console.log('✅ Buyer: buyer@ospolymarket.com / Buyer@123456');
    }

    // Create More Sellers
    let seller2 = await User.findOne({ email: 'fashion@ospolymarket.com' });
    if (!seller2) {
      seller2 = await User.create({
        name: 'Campus Fashion Hub',
        email: 'fashion@ospolymarket.com',
        password: 'Fashion@123456',
        role: 'seller',
        isVerified: true,
        sellerProfile: { storeName: 'Campus Fashion Hub', description: 'Trendy fashion for campus life', rating: 4.5, totalSales: 180, isApproved: true }
      });
    }

    // Create Products
    const productCount = await Product.countDocuments();
    if (productCount === 0) {
      const products = [
        { seller: seller._id, title: 'Samsung Galaxy A54 5G - 128GB Deep Awesome', description: 'Brand new Samsung Galaxy A54 5G with 128GB storage. Features 6.4" Super AMOLED display, 5000mAh battery, 50MP camera. Perfect for students! Comes with 1 year warranty. Original Samsung product with complete accessories.', price: 185000, originalPrice: 210000, category: 'phones-accessories', condition: 'new', stock: 15, brand: 'Samsung', location: 'Lagos', images: [], isApproved: true, isFeatured: true, rating: 4.5, reviewCount: 23 },
        { seller: seller._id, title: 'iPhone 13 Pro Max 256GB - Graphite', description: 'Premium iPhone 13 Pro Max in excellent condition. Battery health 92%. 256GB storage. Includes original box, charger, and earphones. Factory unlocked, works with all networks. Perfect for students who want Apple quality at a great price!', price: 450000, originalPrice: 520000, category: 'phones-accessories', condition: 'used', stock: 3, brand: 'Apple', location: 'Lagos', images: [], isApproved: true, isFeatured: true, rating: 4.8, reviewCount: 15 },
        { seller: seller._id, title: 'JBL Tune 510BT Wireless Headphones - Black', description: 'New JBL Tune 510BT wireless headphones with 40-hour battery life. Pure Bass Sound, lightweight and comfortable design. Perfect for studying and listening to music. Foldable design, easy to carry around campus.', price: 35000, originalPrice: 45000, category: 'electronics', condition: 'new', stock: 25, brand: 'JBL', location: 'Lagos', images: [], isApproved: true, isFlashDeal: true, rating: 4.3, reviewCount: 42 },
        { seller: seller._id, title: 'HP Pavilion 15 Laptop - 8GB RAM 256GB SSD', description: 'Brand new HP Pavilion 15 laptop. Intel Core i5 11th generation, 8GB DDR4 RAM, 256GB NVMe SSD. 15.6" FHD display, Windows 11 pre-installed. Perfect for students programming and assignments. 1 year HP warranty.', price: 285000, originalPrice: 320000, category: 'electronics', condition: 'new', stock: 8, brand: 'HP', location: 'Lagos', images: [], isApproved: true, isFeatured: true, rating: 4.6, reviewCount: 31 },
        { seller: seller._id, title: 'Logitech MX Master 3 Wireless Mouse', description: 'Advanced wireless mouse with ultra-precise MagSpeed scroll wheel. 4000 DPI Darkfield sensor works on any surface. USB-C quick charging, 70 days battery life. Perfect for designers and power users. Compatible with Windows and Mac.', price: 45000, originalPrice: 55000, category: 'electronics', condition: 'new', stock: 20, brand: 'Logitech', location: 'Ibadan', images: [], isApproved: true, rating: 4.9, reviewCount: 67 },
        { seller: seller._id, title: 'Student Study Desk - Compact Wooden Design', description: 'Sturdy study desk perfect for small spaces. Features 2 spacious shelves, cable management hole. Easy to assemble. Solid wood construction. Great for dorm rooms and shared apartments. Available in walnut and oak finishes.', price: 45000, originalPrice: 55000, category: 'furniture', condition: 'new', stock: 12, brand: 'HomeStyle', location: 'Ibadan', images: [], isApproved: true, isFeatured: true, rating: 4.0, reviewCount: 18 },
        { seller: seller._id, title: 'Ergonomic Office Chair - Premium Comfort', description: 'Comfortable ergonomic chair with lumbar support, adjustable armrests. Breathable mesh back, padded seat cushion. Height adjustable, 360-degree swivel, tilt tension. Supports up to 250lbs. Perfect for long study sessions and late-night assignments.', price: 38000, originalPrice: 65000, category: 'furniture', condition: 'used', stock: 5, brand: 'OfficePro', location: 'Ibadan', images: [], isApproved: true, isFlashDeal: true, rating: 4.2, reviewCount: 28 },
        { seller: seller._id, title: 'Unisex Premium Hoodie - Heavy Cotton', description: 'High-quality unisex hoodie, 80% cotton 20% polyester. 380gsm heavy fleece. Soft inner lining, kangaroo pocket, double-lined hood. Available in S, M, L, XL, XXL sizes. Multiple colors: Black, Navy, Grey, Red, White. Perfect for campus weather!', price: 12000, originalPrice: 15000, category: 'fashion', condition: 'new', stock: 50, brand: 'CampusWear', location: 'Abuja', images: [], isApproved: true, isFeatured: true, rating: 4.6, reviewCount: 67 },
        { seller: seller._id, title: 'Air Jordan 1 Retro High - Sneakers Size 42', description: 'Authentic Air Jordan 1 Retro High sneakers. Used only twice, excellent condition. Original box and extra laces included. True to size. Classic black and red colorway. Perfect for students who want to look stylish on campus!', price: 65000, originalPrice: 85000, category: 'fashion', condition: 'used', stock: 2, brand: 'Nike', location: 'Lagos', images: [], isApproved: true, rating: 4.8, reviewCount: 12 },
        { seller: seller2._id, title: 'Samsung 32" LED Smart TV - UA32T4500', description: 'New Samsung 32-inch LED Smart TV with built-in WiFi. Full HD resolution (1920x1080). Access Netflix, YouTube, and more. HDR support for better picture quality. Perfect for dorm rooms and shared apartments. Wall mount included.', price: 125000, originalPrice: 145000, category: 'electronics', condition: 'new', stock: 8, brand: 'Samsung', location: 'Lagos', images: [], isApproved: true, rating: 4.4, reviewCount: 12 },
        { seller: seller2._id, title: 'Leather Backpack - 17" Laptop Compartment', description: 'Genuine leather backpack with padded laptop compartment (fits up to 17"), multiple organizational pockets, USB charging port. Water resistant exterior. Comfortable padded shoulder straps. Perfect for students carrying heavy textbooks and laptops.', price: 18500, originalPrice: 22000, category: 'fashion', condition: 'new', stock: 20, brand: 'TravelPro', location: 'Abuja', images: [], isApproved: true, rating: 4.7, reviewCount: 54 },
        { seller: seller2._id, title: 'Mini Refrigerator - 50L Compact', description: 'Compact 50L mini refrigerator, perfect for dorm rooms. Adjustable thermostat, reversible door, quiet operation (35dB). Energy efficient - only uses 0.8kWh per day. Separate freezer compartment. Perfect size for one person. 1 year warranty.', price: 85000, originalPrice: 98000, category: 'kitchen-home', condition: 'new', stock: 10, brand: 'CoolTech', location: 'Ibadan', images: [], isApproved: true, isFlashDeal: true, rating: 4.1, reviewCount: 35 },
        { seller: seller._id, title: 'Portable Power Bank 20000mAh - Fast Charging', description: 'High-capacity 20000mAh power bank with 2 USB outputs and Type-C input. 22.5W fast charging support. LED digital display shows remaining power. Can charge 3 devices simultaneously. Compact design fits in pocket. Safe for flights.', price: 8500, originalPrice: 12000, category: 'phones-accessories', condition: 'new', stock: 45, brand: 'PowerMax', location: 'Lagos', images: [], isApproved: true, rating: 4.3, reviewCount: 89 },
        { seller: seller2._id, title: 'Standing Desk Converter - Adjustable Height', description: 'Height adjustable standing desk converter. Sit-stand work station. Smooth gas lift mechanism. Spacious work surface (80x40cm). Cable management system. Fits up to 32" monitors. Perfect for home office and study setups. Easy to assemble.', price: 55000, originalPrice: 70000, category: 'furniture', condition: 'new', stock: 6, brand: 'FlexiSpot', location: 'Lagos', images: [], isApproved: true, rating: 4.5, reviewCount: 23 },
        { seller: seller._id, title: 'Mechanical Keyboard RGB - Cherry MX Blue', description: 'Professional mechanical keyboard with Cherry MX Blue switches. RGB backlighting with 16.8M colors. N-key rollover, anti-ghosting. Detachable USB-C cable. Aluminum frame construction. Perfect for gaming and typing. Windows/Mac compatible.', price: 25000, originalPrice: 35000, category: 'electronics', condition: 'new', stock: 15, brand: 'Corsair', location: 'Lagos', images: [], isApproved: true, isFlashDeal: true, rating: 4.7, reviewCount: 41 },
        { seller: seller2._id, title: 'Noise Cancelling Earbuds - True Wireless', description: 'True wireless earbuds with active noise cancellation. 30-hour total playtime with charging case. IPX5 water resistant. Touch controls, voice assistant support. Crystal clear calls with dual microphones. Perfect for studying in noisy environments.', price: 28000, originalPrice: 38000, category: 'electronics', condition: 'new', stock: 30, brand: 'Soundcore', location: 'Abuja', images: [], isApproved: true, rating: 4.4, reviewCount: 76 },
        { seller: seller._id, title: 'Webcam 1080P HD - Auto Focus', description: '1080P Full HD webcam with auto focus and auto light correction. Built-in stereo microphone with noise reduction. 90-degree wide angle lens. Universal mount fits laptops and tripods. Plug and play - no drivers needed. Perfect for online classes and meetings.', price: 15000, originalPrice: 20000, category: 'electronics', condition: 'new', stock: 25, brand: 'Logitech', location: 'Lagos', images: [], isApproved: true, rating: 4.5, reviewCount: 58 },
        { seller: seller2._id, title: 'Pressure Cooker 6L - Electric Multi-Cooker', description: '6L electric pressure cooker with 8 cooking functions. Digital display, timer, keep warm feature. Non-stick inner pot. Perfect for meal prep and busy students. Cook rice, soup, stew, beans faster. 1500W power. Includes recipe book.', price: 35000, originalPrice: 45000, category: 'kitchen-home', condition: 'new', stock: 12, brand: 'Instant', location: 'Ibadan', images: [], isApproved: true, rating: 4.6, reviewCount: 34 },
        { seller: seller._id, title: 'University Backpack - Waterproof Laptop Bag', description: 'Waterproof university backpack with padded 17" laptop compartment. Multiple pockets for books, water bottle, umbrella. Ergonomic design with breathable back padding. USB charging port. Anti-theft pocket. Durable 600D polyester. Perfect for daily campus use.', price: 8500, originalPrice: 11000, category: 'fashion', condition: 'new', stock: 40, brand: 'CampusGear', location: 'Lagos', images: [], isApproved: true, rating: 4.3, reviewCount: 92 },
        { seller: seller2._id, title: 'Air Fryer 5.5L - Digital Touch Screen', description: '5.5L large capacity air fryer with digital touch screen. 1800W power, 8 preset programs. Healthier cooking with 80% less oil. Non-stick basket, dishwasher safe. Timer up to 60 minutes. Perfect for quick meals between classes.', price: 45000, originalPrice: 55000, category: 'kitchen-home', condition: 'new', stock: 8, brand: 'Ninja', location: 'Abuja', images: [], isApproved: true, isFeatured: true, rating: 4.7, reviewCount: 45 },
      ];
      await Product.insertMany(products);
      console.log('✅ 20 Sample products created');
    }

    console.log('✅ Database seeding complete!');
  } catch (error) {
    console.error('❌ Seeding error:', error.message);
  }
};

// Routes

// Health Check
app.get('/api/health', (req, res) => res.json({ success: true, message: 'Ospoly Market API Running', version: '1.0.0', timestamp: new Date() }));

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role, phone } = req.body;
    if (await User.findOne({ email })) return res.status(400).json({ success: false, message: 'Email already exists' });
    const user = await User.create({ name, email, password, role: role || 'buyer', phone });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '30d' });
    user.refreshToken = refreshToken; 
    await user.save();
    res.cookie('accessToken', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.status(201).json({ success: true, data: { user: { _id: user._id, name: user.name, email: user.email, role: user.role, phone: user.phone, sellerProfile: user.sellerProfile }, accessToken: token } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password');
    if (!user) return res.status(401).json({ success: false, message: 'Invalid email or password' });
    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(401).json({ success: false, message: 'Invalid email or password' });
    if (user.isBanned) return res.status(403).json({ success: false, message: 'Account has been suspended' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '30d' });
    user.refreshToken = refreshToken; 
    user.lastLogin = new Date(); 
    await user.save();
    res.cookie('accessToken', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.json({ success: true, data: { user: { _id: user._id, name: user.name, email: user.email, role: user.role, phone: user.phone, avatar: user.avatar, sellerProfile: user.sellerProfile, address: user.address }, accessToken: token } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.post('/api/auth/logout', auth, async (req, res) => { 
  await User.findByIdAndUpdate(req.user._id, { refreshToken: '' }); 
  res.clearCookie('accessToken'); 
  res.clearCookie('refreshToken'); 
  res.json({ success: true }); 
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({ success: true, data: { user: { 
    _id: req.user._id, 
    name: req.user.name, 
    email: req.user.email, 
    phone: req.user.phone,
    role: req.user.role, 
    avatar: req.user.avatar, 
    sellerProfile: req.user.sellerProfile, 
    address: req.user.address,
    isVerified: req.user.isVerified 
  } } });
});

app.put('/api/auth/profile', auth, async (req, res) => {
  try {
    const { name, phone, address, sellerProfile } = req.body;
    const updates = {};
    if (name) updates.name = name;
    if (phone) updates.phone = phone;
    if (address) updates.address = address;
    if (sellerProfile && (req.user.role === 'seller' || req.user.role === 'admin')) updates.sellerProfile = sellerProfile;
    
    const user = await User.findByIdAndUpdate(req.user._id, updates, { new: true });
    res.json({ success: true, data: { user } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

// Product Routes
app.get('/api/products', async (req, res) => {
  try {
    const { page = 1, limit = 24, category, condition, minPrice, maxPrice, search, sort = '-createdAt', brand } = req.query;
    const query = { isApproved: true };
    if (category) query.category = category;
    if (condition) query.condition = condition;
    if (brand) query.brand = brand;
    if (minPrice || maxPrice) { 
      query.price = {}; 
      if (minPrice) query.price.$gte = Number(minPrice); 
      if (maxPrice) query.price.$lte = Number(maxPrice); 
    }
    if (search) query.title = { $regex: search, $options: 'i' };
    
    const skip = (Number(page) - 1) * Number(limit);
    const products = await Product.find(query)
      .populate('seller', 'name sellerProfile.storeName sellerProfile.rating sellerProfile.totalSales')
      .sort(sort)
      .skip(skip)
      .limit(Number(limit))
      .lean();
    const total = await Product.countDocuments(query);
    
    res.json({ 
      success: true, 
      data: { 
        products, 
        pagination: { 
          currentPage: Number(page), 
          totalPages: Math.ceil(total / limit), 
          totalProducts: total,
          hasMore: skip + products.length < total
        } 
      } 
    });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.get('/api/products/flash-deals', async (req, res) => {
  try {
    const products = await Product.find({ isApproved: true, isFlashDeal: true })
      .populate('seller', 'name sellerProfile.storeName')
      .limit(20)
      .lean();
    res.json({ success: true, data: { products } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.get('/api/products/featured', async (req, res) => {
  try {
    const products = await Product.find({ isApproved: true, isFeatured: true })
      .populate('seller', 'name sellerProfile.storeName')
      .limit(20)
      .lean();
    res.json({ success: true, data: { products } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.get('/api/products/categories', async (req, res) => {
  try {
    const categories = await Product.distinct('category', { isApproved: true });
    const categoryCounts = await Promise.all(
      categories.map(async (cat) => ({
        name: cat,
        count: await Product.countDocuments({ category: cat, isApproved: true })
      }))
    );
    res.json({ success: true, data: { categories: categoryCounts } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id)
      .populate('seller', 'name email sellerProfile.storeName sellerProfile.rating sellerProfile.totalSales sellerProfile.responseRate')
      .lean();
    if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
    await Product.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } });
    res.json({ success: true, data: { product } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.post('/api/products', auth, async (req, res) => {
  try {
    if (req.user.role !== 'seller' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Only sellers can create products' });
    }
    const { title, description, price, originalPrice, category, condition, stock, brand, location, images, isFlashDeal, isFeatured } = req.body;
    const product = await Product.create({
      seller: req.user._id,
      title, description, price, originalPrice, category, condition, stock, brand, location, images,
      isFlashDeal: isFlashDeal || false,
      isFeatured: isFeatured || false
    });
    res.status(201).json({ success: true, data: { product } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.put('/api/products/:id', auth, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
    if (product.seller.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Not authorized' });
    }
    const updates = req.body;
    const updatedProduct = await Product.findByIdAndUpdate(req.params.id, updates, { new: true });
    res.json({ success: true, data: { product: updatedProduct } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.delete('/api/products/:id', auth, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
    if (product.seller.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Not authorized' });
    }
    await Product.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

// Seller Products
app.get('/api/products/seller/my-products', auth, async (req, res) => {
  try {
    if (req.user.role !== 'seller' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Sellers only' });
    }
    const products = await Product.find({ seller: req.user._id }).sort('-createdAt').lean();
    res.json({ success: true, data: { products } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

// Cart Routes
app.get('/api/cart', auth, async (req, res) => {
  try {
    let cart = await Cart.findOne({ user: req.user._id })
      .populate({ 
        path: 'items.product', 
        select: 'title price images condition stock isApproved seller', 
        populate: { path: 'seller', select: 'name sellerProfile.storeName' } 
      })
      .lean();
    if (!cart) cart = { items: [] };
    const validItems = (cart.items || []).filter(i => i.product && i.product.isApproved && i.product.stock > 0);
    const itemCount = validItems.reduce((c, i) => c + i.quantity, 0);
    const subtotal = validItems.reduce((s, i) => s + (i.product.price * i.quantity), 0);
    res.json({ success: true, data: { cart: { _id: cart._id, items: validItems }, summary: { itemCount, subtotal, shipping: 500, total: subtotal + 500 } } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.post('/api/cart/add', auth, async (req, res) => {
  try {
    const { productId, quantity = 1 } = req.body;
    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
    if (product.stock < quantity) return res.status(400).json({ success: false, message: 'Not enough stock' });
    
    let cart = await Cart.findOne({ user: req.user._id });
    if (!cart) cart = new Cart({ user: req.user._id, items: [] });
    
    const existing = cart.items.find(i => i.product.toString() === productId);
    if (existing) {
      existing.quantity += quantity;
      if (existing.quantity > product.stock) existing.quantity = product.stock;
    } else {
      cart.items.push({ product: productId, quantity });
    }
    
    await cart.save();
    await cart.populate({ 
      path: 'items.product', 
      select: 'title price images condition stock seller', 
      populate: { path: 'seller', select: 'name sellerProfile.storeName' } 
    });
    
    const itemCount = cart.items.reduce((c, i) => c + i.quantity, 0);
    const subtotal = cart.items.reduce((s, i) => s + (i.product.price * i.quantity), 0);
    res.json({ success: true, data: { cart, summary: { itemCount, subtotal, shipping: 500, total: subtotal + 500 } } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.put('/api/cart/update', auth, async (req, res) => {
  try {
    const { productId, quantity } = req.body;
    if (quantity < 1) {
      return app.delete('/api/cart/remove/:productId').bind(req, res, next);
    }
    const cart = await Cart.findOne({ user: req.user._id });
    const item = cart?.items.find(i => i.product.toString() === productId);
    if (!item) return res.status(404).json({ success: false, message: 'Item not in cart' });
    
    const product = await Product.findById(productId);
    if (quantity > product.stock) return res.status(400).json({ success: false, message: 'Not enough stock' });
    
    item.quantity = quantity; 
    await cart.save();
    await cart.populate({ 
      path: 'items.product', 
      select: 'title price images condition stock seller', 
      populate: { path: 'seller', select: 'name sellerProfile.storeName' } 
    });
    
    const itemCount = cart.items.reduce((c, i) => c + i.quantity, 0);
    const subtotal = cart.items.reduce((s, i) => s + (i.product.price * i.quantity), 0);
    res.json({ success: true, data: { cart, summary: { itemCount, subtotal, shipping: 500, total: subtotal + 500 } } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.delete('/api/cart/remove/:productId', auth, async (req, res) => {
  try {
    const cart = await Cart.findOne({ user: req.user._id });
    if (!cart) return res.status(404).json({ success: false, message: 'Cart not found' });
    
    cart.items = cart.items.filter(i => i.product.toString() !== req.params.productId);
    await cart.save();
    await cart.populate({ 
      path: 'items.product', 
      select: 'title price images condition stock seller', 
      populate: { path: 'seller', select: 'name sellerProfile.storeName' } 
    });
    
    const itemCount = cart.items.reduce((c, i) => c + i.quantity, 0);
    const subtotal = cart.items.reduce((s, i) => s + (i.product.price * i.quantity), 0);
    res.json({ success: true, data: { cart, summary: { itemCount, subtotal, shipping: 500, total: subtotal + 500 } } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.delete('/api/cart/clear', auth, async (req, res) => { 
  await Cart.findOneAndUpdate({ user: req.user._id }, { items: [] }); 
  res.json({ success: true }); 
});

// Order Routes
app.post('/api/orders', auth, async (req, res) => {
  try {
    const { shippingAddress, paymentMethod = 'cash_on_delivery', notes } = req.body;
    
    if (!shippingAddress?.fullName || !shippingAddress?.phone || !shippingAddress?.street || !shippingAddress?.city || !shippingAddress?.state) {
      return res.status(400).json({ success: false, message: 'Please complete shipping address' });
    }
    
    const cart = await Cart.findOne({ user: req.user._id })
      .populate({ 
        path: 'items.product', 
        select: 'title price images condition stock seller isApproved', 
        populate: { path: 'seller', select: 'name' } 
      })
      .lean();
      
    if (!cart || cart.items.length === 0) return res.status(400).json({ success: false, message: 'Cart is empty' });
    
    const validItems = cart.items.filter(i => i.product && i.product.isApproved && i.product.stock >= i.quantity);
    if (validItems.length === 0) return res.status(400).json({ success: false, message: 'No items available' });
    
    const orderItems = validItems.map(i => ({ 
      product: i.product._id, 
      seller: i.product.seller._id, 
      title: i.product.title, 
      image: i.product.images?.[0] || '', 
      price: i.product.price, 
      quantity: i.quantity 
    }));
    
    const subtotal = validItems.reduce((s, i) => s + (i.product.price * i.quantity), 0);
    
    const order = await Order.create({ 
      buyer: req.user._id, 
      items: orderItems, 
      totalAmount: subtotal, 
      finalAmount: subtotal + 500, 
      shippingAddress, 
      paymentMethod,
      notes,
      statusHistory: [{ status: 'pending', note: 'Order placed successfully' }] 
    });
    
    // Clear cart
    await Cart.findOneAndUpdate({ user: req.user._id }, { items: [] });
    
    // Update stock
    for (const item of validItems) {
      await Product.findByIdAndUpdate(item.product._id, { $inc: { stock: -item.quantity } });
    }
    
    await order.populate('buyer', 'name email phone');
    res.status(201).json({ success: true, data: { order } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.get('/api/orders', auth, async (req, res) => {
  try {
    const orders = await Order.find({ buyer: req.user._id })
      .populate('items.product', 'title images')
      .sort('-createdAt')
      .lean();
    res.json({ success: true, data: { orders } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.get('/api/orders/:id', auth, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id)
      .populate('buyer', 'name email phone')
      .populate('items.product', 'title images')
      .lean();
    if (!order) return res.status(404).json({ success: false, message: 'Order not found' });
    if (order.buyer._id.toString() !== req.user._id.toString() && req.user.role !== 'admin' && order.items.every(i => i.seller.toString() !== req.user._id.toString())) {
      return res.status(403).json({ success: false, message: 'Not authorized' });
    }
    res.json({ success: true, data: { order } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

// Seller Order Routes
app.get('/api/orders/seller/stats', auth, async (req, res) => {
  try {
    if (req.user.role !== 'seller' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Sellers only' });
    }
    const orders = await Order.find({ 'items.seller': req.user._id })
      .populate('buyer', 'name email phone shippingAddress')
      .sort('-createdAt')
      .lean();
    
    const allOrders = orders.map(o => ({
      ...o,
      items: o.items.filter(i => i.seller.toString() === req.user._id.toString())
    })).filter(o => o.items.length > 0);
    
    const stats = {
      totalOrders: allOrders.length,
      totalRevenue: allOrders.reduce((s, o) => s + o.finalAmount, 0),
      pendingOrders: allOrders.filter(o => ['pending', 'confirmed'].includes(o.status)).length,
      completedOrders: allOrders.filter(o => o.status === 'delivered').length,
      processingOrders: allOrders.filter(o => o.status === 'processing').length
    };
    
    res.json({ success: true, data: { stats, recentOrders: allOrders.slice(0, 10) } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.get('/api/orders/seller/orders', auth, async (req, res) => {
  try {
    const orders = await Order.find({ 'items.seller': req.user._id })
      .populate('buyer', 'name email phone shippingAddress')
      .sort('-createdAt')
      .lean();
    
    const filtered = orders.map(o => ({
      ...o,
      items: o.items.filter(i => i.seller.toString() === req.user._id.toString())
    })).filter(o => o.items.length > 0);
    
    res.json({ success: true, data: { orders: filtered } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.put('/api/orders/:id/status', auth, async (req, res) => {
  try {
    const { status, note } = req.body;
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ success: false, message: 'Order not found' });
    
    const isSeller = order.items.some(i => i.seller.toString() === req.user._id.toString());
    if (!isSeller && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Not authorized' });
    }
    
    order.status = status;
    order.statusHistory.push({ status, note: note || `Status updated to ${status}` });
    
    if (status === 'delivered') {
      order.paymentStatus = 'paid';
      // Update seller stats
      await User.findByIdAndUpdate(req.user._id, { $inc: { 'sellerProfile.totalSales': 1 } });
    }
    
    await order.save();
    res.json({ success: true, data: { order } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

// Admin Routes
app.get('/api/admin/dashboard', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
    
    const [totalUsers, totalSellers, totalProducts, totalOrders, pendingProducts, totalRevenue] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ role: 'seller' }),
      Product.countDocuments(),
      Order.countDocuments(),
      Product.countDocuments({ isApproved: false }),
      Order.aggregate([{ $group: { _id: null, total: { $sum: '$finalAmount' } } }])
    ]);
    
    const recentOrders = await Order.find()
      .populate('buyer', 'name email')
      .sort('-createdAt')
      .limit(10)
      .lean();
    
    const recentUsers = await User.find()
      .select('name email role createdAt')
      .sort('-createdAt')
      .limit(10)
      .lean();
    
    res.json({ 
      success: true, 
      data: { 
        stats: { 
          totalUsers, 
          totalSellers, 
          totalProducts, 
          totalOrders, 
          pendingApprovals: pendingProducts,
          totalRevenue: totalRevenue[0]?.total || 0
        }, 
        recentOrders, 
        recentUsers 
      } 
    });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.get('/api/admin/products/pending', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
    const products = await Product.find({ isApproved: false })
      .populate('seller', 'name email sellerProfile.storeName')
      .lean();
    res.json({ success: true, data: { products } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.put('/api/admin/products/:id/approve', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
    const product = await Product.findByIdAndUpdate(req.params.id, { isApproved: true }, { new: true });
    res.json({ success: true, data: { product } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.get('/api/admin/users', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
    const users = await User.find().select('-password').sort('-createdAt').lean();
    res.json({ success: true, data: { users } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

// Start Server
const PORT = process.env.PORT || 10000;
connectDB().then(async (connected) => {
  if (connected) await seedDatabase();
  app.listen(PORT, () => console.log(`🚀 Ospoly Market Server running on port ${PORT}`));
});