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
  role: { type: String, enum: ['buyer', 'seller', 'admin'], default: 'buyer' },
  isVerified: { type: Boolean, default: false },
  isBanned: { type: Boolean, default: false },
  sellerProfile: { storeName: String, rating: { type: Number, default: 0 }, totalSales: { type: Number, default: 0 }, isApproved: Boolean },
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
  condition: { type: String, enum: ['new', 'used'], default: 'new' },
  images: [String],
  stock: { type: Number, default: 1 },
  brand: String, location: String,
  views: { type: Number, default: 0 },
  isApproved: { type: Boolean, default: true },
  isFeatured: { type: Boolean, default: false },
  isFlashDeal: { type: Boolean, default: false },
  rating: { type: Number, default: 0 },
  reviewCount: { type: Number, default: 0 },
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
  items: [{ product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' }, seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, title: String, image: String, price: Number, quantity: Number }],
  totalAmount: Number, shippingCost: { type: Number, default: 500 }, finalAmount: Number,
  status: { type: String, enum: ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'], default: 'pending' },
  paymentStatus: { type: String, enum: ['pending', 'paid', 'failed'], default: 'pending' },
  shippingAddress: { fullName: String, phone: String, street: String, city: String, state: String },
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
        sellerProfile: { storeName: 'Ospoly Official', isApproved: true }
      });
      console.log('✅ Admin created: admin@ospolymarket.com / Admin@123456');
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
        sellerProfile: { storeName: 'TechWorld Store', description: 'Your tech gadget hub', rating: 4.5, totalSales: 150, isApproved: true }
      });
      console.log('✅ Seller created: seller@ospolymarket.com / Seller@123456');
    }

    // Create Buyer
    let buyer = await User.findOne({ email: 'buyer@ospolymarket.com' });
    if (!buyer) {
      buyer = await User.create({
        name: 'John Student',
        email: 'buyer@ospolymarket.com',
        password: 'Buyer@123456',
        role: 'buyer',
        isVerified: true
      });
      console.log('✅ Buyer created: buyer@ospolymarket.com / Buyer@123456');
    }

    // Create Products
    const productCount = await Product.countDocuments();
    if (productCount === 0) {
      const products = [
        { seller: seller._id, title: 'Samsung Galaxy A54 5G - 128GB', description: 'Brand new Samsung Galaxy A54 5G with 128GB storage. Features 6.4" Super AMOLED display, 5000mAh battery, 50MP camera. Perfect for students!', price: 185000, originalPrice: 210000, category: 'phones-accessories', condition: 'new', stock: 15, brand: 'Samsung', location: 'Lagos', images: [], isApproved: true, isFeatured: true, rating: 4.5, reviewCount: 23 },
        { seller: seller._id, title: 'iPhone 13 Pro Max - Used Excellent', description: 'Used iPhone 13 Pro Max in excellent condition. Battery health 92%. Includes original box and charger. Great deal!', price: 450000, originalPrice: 520000, category: 'phones-accessories', condition: 'used', stock: 3, brand: 'Apple', location: 'Lagos', images: [], isApproved: true, rating: 4.8, reviewCount: 15 },
        { seller: seller._id, title: 'JBL Tune 510BT Wireless Headphones', description: 'New JBL Tune 510BT wireless headphones with 40-hour battery life. Lightweight and comfortable design. Perfect for studying!', price: 35000, originalPrice: 45000, category: 'electronics', condition: 'new', stock: 25, brand: 'JBL', location: 'Lagos', images: [], isApproved: true, isFlashDeal: true, rating: 4.3, reviewCount: 42 },
        { seller: seller._id, title: 'Student Study Desk - Compact', description: 'Sturdy study desk perfect for small spaces. Features 2 shelves, cable management hole. Easy to assemble. Great for dorm rooms!', price: 45000, originalPrice: 55000, category: 'furniture', condition: 'new', stock: 12, brand: 'HomeStyle', location: 'Ibadan', images: [], isApproved: true, isFeatured: true, rating: 4.0, reviewCount: 18 },
        { seller: seller._id, title: 'Ergonomic Office Chair - Used', description: 'Comfortable ergonomic chair with lumbar support. Used but in good condition. Height adjustable, 360-degree swivel. Perfect for long study sessions!', price: 38000, originalPrice: 65000, category: 'furniture', condition: 'used', stock: 5, brand: 'OfficePro', location: 'Ibadan', images: [], isApproved: true, isFlashDeal: true, rating: 4.2, reviewCount: 28 },
        { seller: seller._id, title: 'Unisex Hoodie - Premium Quality', description: 'High-quality unisex hoodie, 80% cotton. Soft inner lining, kangaroo pocket. Available in S, M, L, XL sizes. Multiple colors available!', price: 12000, originalPrice: 15000, category: 'fashion', condition: 'new', stock: 50, brand: 'CampusWear', location: 'Abuja', images: [], isApproved: true, isFeatured: true, rating: 4.6, reviewCount: 67 },
        { seller: seller._id, title: 'Samsung 32" LED Smart TV', description: 'New Samsung 32-inch LED Smart TV with built-in WiFi. Full HD resolution. Perfect for dorm rooms!', price: 125000, originalPrice: 145000, category: 'electronics', condition: 'new', stock: 8, brand: 'Samsung', location: 'Lagos', images: [], isApproved: true, rating: 4.4, reviewCount: 12 },
        { seller: seller._id, title: 'Leather Backpack - Laptop Compartments', description: 'Genuine leather backpack with padded laptop compartment (fits up to 17"), multiple pockets, USB charging port. Water resistant.', price: 18500, originalPrice: 22000, category: 'fashion', condition: 'new', stock: 20, brand: 'TravelPro', location: 'Abuja', images: [], isApproved: true, rating: 4.7, reviewCount: 54 },
        { seller: seller._id, title: 'Mini Refrigerator - 50L', description: 'Compact 50L mini refrigerator, perfect for dorm rooms. Adjustable thermostat, reversible door, quiet operation. Energy efficient!', price: 85000, originalPrice: 98000, category: 'kitchen-home', condition: 'new', stock: 10, brand: 'CoolTech', location: 'Ibadan', images: [], isApproved: true, isFlashDeal: true, rating: 4.1, reviewCount: 35 },
        { seller: seller._id, title: 'Portable Power Bank 20000mAh', description: 'High-capacity 20000mAh power bank with 2 USB outputs and Type-C input. Fast charging support. LED indicator. Compact design!', price: 8500, originalPrice: 12000, category: 'phones-accessories', condition: 'new', stock: 45, brand: 'PowerMax', location: 'Lagos', images: [], isApproved: true, rating: 4.3, reviewCount: 89 },
      ];
      await Product.insertMany(products);
      console.log('✅ 10 Sample products created');
    }

    console.log('✅ Database seeding complete!');
  } catch (error) {
    console.error('❌ Seeding error:', error.message);
  }
};

// Routes
app.get('/api/health', (req, res) => res.json({ success: true, message: 'Ospoly Market API Running', version: '1.0.0' }));

// Auth
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (await User.findOne({ email })) return res.status(400).json({ success: false, message: 'Email already exists' });
    const user = await User.create({ name, email, password, role: role || 'buyer' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
    user.refreshToken = refreshToken; await user.save();
    res.cookie('accessToken', token, { httpOnly: true, maxAge: 15 * 60 * 1000 });
    res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.status(201).json({ success: true, data: { user: { _id: user._id, name: user.name, email: user.email, role: user.role, sellerProfile: user.sellerProfile }, accessToken: token } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('Login attempt:', email);
    const user = await User.findOne({ email }).select('+password');
    console.log('User found:', !!user);
    if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    const isMatch = await user.comparePassword(password);
    console.log('Password match:', isMatch);
    if (!isMatch) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (user.isBanned) return res.status(403).json({ success: false, message: 'Account suspended' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
    user.refreshToken = refreshToken; user.lastLogin = new Date(); await user.save();
    res.cookie('accessToken', token, { httpOnly: true, maxAge: 15 * 60 * 1000 });
    res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    console.log('Login success:', user.name);
    res.json({ success: true, data: { user: { _id: user._id, name: user.name, email: user.email, role: user.role, sellerProfile: user.sellerProfile }, accessToken: token } });
  } catch (error) { console.error('Login error:', error); res.status(500).json({ success: false, message: error.message }); }
});

app.post('/api/auth/logout', auth, async (req, res) => { await User.findByIdAndUpdate(req.user._id, { refreshToken: '' }); res.clearCookie('accessToken'); res.clearCookie('refreshToken'); res.json({ success: true }); });
app.get('/api/auth/me', auth, (req, res) => res.json({ success: true, data: { user: { _id: req.user._id, name: req.user.name, email: req.user.email, role: req.user.role, avatar: req.user.avatar, sellerProfile: req.user.sellerProfile, isVerified: req.user.isVerified } } }));

// Products
app.get('/api/products', async (req, res) => {
  const { page = 1, limit = 20, category, condition, minPrice, maxPrice, search, sort = '-createdAt' } = req.query;
  const query = { isApproved: true };
  if (category) query.category = category;
  if (condition) query.condition = condition;
  if (minPrice || maxPrice) { query.price = {}; if (minPrice) query.price.$gte = Number(minPrice); if (maxPrice) query.price.$lte = Number(maxPrice); }
  if (search) query.title = { $regex: search, $options: 'i' };
  const products = await Product.find(query).populate('seller', 'name sellerProfile.storeName').sort(sort).skip((page - 1) * limit).limit(Number(limit)).lean();
  const total = await Product.countDocuments(query);
  res.json({ success: true, data: { products, pagination: { currentPage: Number(page), totalPages: Math.ceil(total / limit), totalProducts: total } } });
});

app.get('/api/products/flash-deals', async (req, res) => {
  const products = await Product.find({ isApproved: true, isFlashDeal: true }).populate('seller', 'name sellerProfile.storeName').limit(20).lean();
  res.json({ success: true, data: { products } });
});

app.get('/api/products/featured', async (req, res) => {
  const products = await Product.find({ isApproved: true, isFeatured: true }).populate('seller', 'name sellerProfile.storeName').limit(20).lean();
  res.json({ success: true, data: { products } });
});

app.get('/api/products/:id', async (req, res) => {
  const product = await Product.findById(req.params.id).populate('seller', 'name email sellerProfile.storeName').lean();
  if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
  await Product.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } });
  res.json({ success: true, data: { product } });
});

// Cart
app.get('/api/cart', auth, async (req, res) => {
  let cart = await Cart.findOne({ user: req.user._id }).populate({ path: 'items.product', select: 'title price images condition stock isApproved seller', populate: { path: 'seller', select: 'name' } }).lean();
  if (!cart) cart = { items: [] };
  const validItems = (cart.items || []).filter(i => i.product && i.product.isApproved && i.product.stock > 0);
  const itemCount = validItems.reduce((c, i) => c + i.quantity, 0);
  const subtotal = validItems.reduce((s, i) => s + (i.product.price * i.quantity), 0);
  res.json({ success: true, data: { cart: { _id: cart._id, items: validItems }, summary: { itemCount, subtotal, shipping: 500, total: subtotal + 500 } } });
});

app.post('/api/cart/add', auth, async (req, res) => {
  const { productId, quantity = 1 } = req.body;
  const product = await Product.findById(productId);
  if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
  let cart = await Cart.findOne({ user: req.user._id });
  if (!cart) cart = new Cart({ user: req.user._id, items: [] });
  const existing = cart.items.find(i => i.product.toString() === productId);
  if (existing) existing.quantity += quantity; else cart.items.push({ product: productId, quantity });
  await cart.save();
  await cart.populate({ path: 'items.product', select: 'title price images condition stock seller', populate: { path: 'seller', select: 'name' } });
  const itemCount = cart.items.reduce((c, i) => c + i.quantity, 0);
  const subtotal = cart.items.reduce((s, i) => s + (i.product.price * i.quantity), 0);
  res.json({ success: true, data: { cart, summary: { itemCount, subtotal, shipping: 500, total: subtotal + 500 } } });
});

app.put('/api/cart/update', auth, async (req, res) => {
  const { productId, quantity } = req.body;
  const cart = await Cart.findOne({ user: req.user._id });
  const item = cart?.items.find(i => i.product.toString() === productId);
  if (!item) return res.status(404).json({ success: false, message: 'Item not in cart' });
  item.quantity = quantity; await cart.save();
  await cart.populate({ path: 'items.product', select: 'title price images condition stock seller', populate: { path: 'seller', select: 'name' } });
  const itemCount = cart.items.reduce((c, i) => c + i.quantity, 0);
  const subtotal = cart.items.reduce((s, i) => s + (i.product.price * i.quantity), 0);
  res.json({ success: true, data: { cart, summary: { itemCount, subtotal, shipping: 500, total: subtotal + 500 } } });
});

app.delete('/api/cart/remove/:productId', auth, async (req, res) => {
  const cart = await Cart.findOne({ user: req.user._id });
  cart.items = cart.items.filter(i => i.product.toString() !== req.params.productId);
  await cart.save();
  await cart.populate({ path: 'items.product', select: 'title price images condition stock seller', populate: { path: 'seller', select: 'name' } });
  const itemCount = cart.items.reduce((c, i) => c + i.quantity, 0);
  const subtotal = cart.items.reduce((s, i) => s + (i.product.price * i.quantity), 0);
  res.json({ success: true, data: { cart, summary: { itemCount, subtotal, shipping: 500, total: subtotal + 500 } } });
});

app.delete('/api/cart/clear', auth, async (req, res) => { await Cart.findOneAndUpdate({ user: req.user._id }, { items: [] }); res.json({ success: true }); });

// Orders
app.post('/api/orders', auth, async (req, res) => {
  const { shippingAddress } = req.body;
  const cart = await Cart.findOne({ user: req.user._id }).populate({ path: 'items.product', select: 'title price images condition stock seller isApproved', populate: { path: 'seller', select: 'name' } }).lean();
  if (!cart || cart.items.length === 0) return res.status(400).json({ success: false, message: 'Cart is empty' });
  const validItems = cart.items.filter(i => i.product && i.product.isApproved && i.product.stock >= i.quantity);
  if (validItems.length === 0) return res.status(400).json({ success: false, message: 'No items available' });
  const orderItems = validItems.map(i => ({ product: i.product._id, seller: i.product.seller._id, title: i.product.title, image: i.product.images?.[0] || '', price: i.product.price, quantity: i.quantity }));
  const subtotal = validItems.reduce((s, i) => s + (i.product.price * i.quantity), 0);
  const order = await Order.create({ buyer: req.user._id, items: orderItems, totalAmount: subtotal, finalAmount: subtotal + 500, shippingAddress, statusHistory: [{ status: 'pending', note: 'Order placed' }] });
  await Cart.findOneAndUpdate({ user: req.user._id }, { items: [] });
  await order.populate('buyer', 'name email');
  res.status(201).json({ success: true, data: { order } });
});

app.get('/api/orders', auth, async (req, res) => {
  const orders = await Order.find({ buyer: req.user._id }).populate('items.product', 'title images').sort('-createdAt').lean();
  res.json({ success: true, data: { orders, pagination: { currentPage: 1, totalPages: 1, totalOrders: orders.length } } });
});

app.get('/api/orders/seller/stats', auth, async (req, res) => {
  const orders = await Order.find({ 'items.seller': req.user._id }).populate('buyer', 'name').sort('-createdAt').limit(10).lean();
  const stats = { totalOrders: orders.length, totalRevenue: orders.reduce((s, o) => s + o.finalAmount, 0), pendingOrders: orders.filter(o => ['pending', 'confirmed'].includes(o.status)).length };
  res.json({ success: true, data: { stats, recentOrders: orders } });
});

app.get('/api/orders/seller/orders', auth, async (req, res) => {
  const orders = await Order.find({ 'items.seller': req.user._id }).populate('buyer', 'name email phone').sort('-createdAt').lean();
  const filtered = orders.map(o => ({ ...o, items: o.items.filter(i => i.seller.toString() === req.user._id.toString()) }));
  res.json({ success: true, data: { orders: filtered } });
});

// Admin
app.get('/api/admin/dashboard', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
  const [totalUsers, totalSellers, totalProducts, totalOrders, pendingProducts] = await Promise.all([User.countDocuments(), User.countDocuments({ role: 'seller' }), Product.countDocuments(), Order.countDocuments(), Product.countDocuments({ isApproved: false })]);
  const recentOrders = await Order.find().populate('buyer', 'name email').sort('-createdAt').limit(5).lean();
  const recentUsers = await User.find().select('name email role').sort('-createdAt').limit(5).lean();
  res.json({ success: true, data: { stats: { totalUsers, totalSellers, totalProducts, totalOrders, pendingApprovals: pendingProducts }, recentOrders, recentUsers } });
});

// Start
const PORT = process.env.PORT || 10000;
connectDB().then(async (connected) => {
  if (connected) await seedDatabase();
  app.listen(PORT, () => console.log(`🚀 Ospoly Market Server running on port ${PORT}`));
});
