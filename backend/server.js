/**
 * Ospoly Market - Backend Server
 * Simplified single-file backend for easy deployment
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

// === MIDDLEWARE ===
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200, message: { success: false, message: 'Too many requests' } }));
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Static files
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
app.use('/uploads', express.static(uploadDir));

// === MONGODB CONNECTION ===
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/ospoly_market')
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err));

// === SCHEMAS ===
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true, select: false },
  role: { type: String, enum: ['buyer', 'seller', 'admin'], default: 'buyer' },
  avatar: String, phone: String,
  address: { street: String, city: String, state: String, zipCode: String },
  isVerified: { type: Boolean, default: false },
  isBanned: { type: Boolean, default: false },
  sellerProfile: { storeName: String, description: String, rating: { type: Number, default: 0 }, totalSales: { type: Number, default: 0 }, isApproved: Boolean },
  refreshToken: String, lastLogin: Date,
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
  flashDealEnd: Date,
  rating: { type: Number, default: 0 },
  reviewCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});
const Product = mongoose.model('Product', productSchema);

const cartSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{ product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' }, quantity: { type: Number, default: 1 }, addedAt: { type: Date, default: Date.now } }],
  updatedAt: { type: Date, default: Date.now }
});
const Cart = mongoose.model('Cart', cartSchema);

const orderSchema = new mongoose.Schema({
  buyer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{ product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' }, seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, title: String, image: String, price: Number, quantity: Number, condition: String }],
  totalAmount: Number, shippingCost: { type: Number, default: 500 }, finalAmount: Number,
  status: { type: String, enum: ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'], default: 'pending' },
  paymentStatus: { type: String, enum: ['pending', 'paid', 'failed'], default: 'pending' },
  paymentMethod: { type: String, default: 'paystack' },
  shippingAddress: { fullName: String, phone: String, street: String, city: String, state: String, zipCode: String },
  statusHistory: [{ status: String, timestamp: { type: Date, default: Date.now }, note: String }],
  createdAt: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema);

// === AUTH MIDDLEWARE ===
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies?.accessToken;
  if (!token) return res.status(401).json({ success: false, message: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    User.findById(decoded.id).then(user => {
      if (!user || user.isBanned) return res.status(401).json({ success: false, message: 'User not found' });
      req.user = user; next();
    });
  } catch (err) { res.status(401).json({ success: false, message: 'Invalid token' }); }
};

// === FILE UPLOAD ===
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: (req, file, cb) => cb(null, /jpeg|jpg|png|webp/.test(path.extname(file.originalname))) });

// === ROUTES ===

// Health Check
app.get('/api/health', (req, res) => res.json({ success: true, message: 'Ospoly Market API Running', version: '1.0.0' }));

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (await User.findOne({ email })) return res.status(400).json({ success: false, message: 'Email already exists' });
    const user = await User.create({ name, email, password, role: role || 'buyer' });
    if (role === 'seller') { user.sellerProfile = { storeName: name + "'s Store", description: 'New seller', isApproved: false }; await user.save(); }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
    user.refreshToken = refreshToken; await user.save();
    res.cookie('accessToken', token, { httpOnly: true, maxAge: 15 * 60 * 1000 });
    res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.status(201).json({ success: true, message: 'Registration successful', data: { user: { _id: user._id, name: user.name, email: user.email, role: user.role, sellerProfile: user.sellerProfile }, accessToken: token } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password');
    if (!user || !(await user.comparePassword(password))) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (user.isBanned) return res.status(403).json({ success: false, message: 'Account suspended' });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
    user.refreshToken = refreshToken; user.lastLogin = new Date(); await user.save();
    res.cookie('accessToken', token, { httpOnly: true, maxAge: 15 * 60 * 1000 });
    res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ success: true, message: 'Login successful', data: { user: { _id: user._id, name: user.name, email: user.email, role: user.role, sellerProfile: user.sellerProfile }, accessToken: token } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.post('/api/auth/logout', auth, async (req, res) => { await User.findByIdAndUpdate(req.user._id, { refreshToken: '' }); res.clearCookie('accessToken'); res.clearCookie('refreshToken'); res.json({ success: true, message: 'Logged out' }); });
app.get('/api/auth/me', auth, (req, res) => res.json({ success: true, data: { user: { _id: req.user._id, name: req.user.name, email: req.user.email, role: req.user.role, avatar: req.user.avatar, sellerProfile: req.user.sellerProfile, isVerified: req.user.isVerified } } }));
app.put('/api/auth/profile', auth, async (req, res) => { const user = await User.findByIdAndUpdate(req.user._id, { name: req.body.name, phone: req.body.phone, address: req.body.address }, { new: true }); res.json({ success: true, data: { user } }); });

// Products Routes
app.get('/api/products', async (req, res) => {
  try {
    const { page = 1, limit = 20, category, condition, minPrice, maxPrice, search, sort = '-createdAt' } = req.query;
    const query = { isApproved: true };
    if (category) query.category = category;
    if (condition) query.condition = condition;
    if (minPrice || maxPrice) { query.price = {}; if (minPrice) query.price.$gte = Number(minPrice); if (maxPrice) query.price.$lte = Number(maxPrice); }
    if (search) query.title = { $regex: search, $options: 'i' };
    const products = await Product.find(query).populate('seller', 'name sellerProfile.storeName').sort(sort).skip((page - 1) * limit).limit(Number(limit)).lean();
    const total = await Product.countDocuments(query);
    res.json({ success: true, data: { products, pagination: { currentPage: Number(page), totalPages: Math.ceil(total / limit), totalProducts: total } } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
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

app.get('/api/products/:id/related', async (req, res) => {
  const product = await Product.findById(req.params.id);
  if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
  const products = await Product.find({ _id: { $ne: product._id }, category: product.category, isApproved: true }).populate('seller', 'name sellerProfile.storeName').limit(6).lean();
  res.json({ success: true, data: { products } });
});

app.post('/api/products', auth, upload.array('images', 5), async (req, res) => {
  try {
    const { title, description, price, originalPrice, category, condition, stock, brand, location, isFlashDeal } = req.body;
    const images = req.files?.map(f => `/uploads/${f.filename}`) || [];
    const product = await Product.create({ seller: req.user._id, title, description, price: Number(price), originalPrice: originalPrice ? Number(originalPrice) : undefined, category, condition: condition || 'new', stock: stock ? Number(stock) : 1, brand, location, images, isApproved: req.user.role === 'admin', isFlashDeal: isFlashDeal === 'true' });
    await product.populate('seller', 'name sellerProfile.storeName');
    res.status(201).json({ success: true, message: 'Product created', data: { product } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.get('/api/products/seller/my-products', auth, async (req, res) => {
  const products = await Product.find({ seller: req.user._id }).sort('-createdAt').lean();
  res.json({ success: true, data: { products, pagination: { currentPage: 1, totalPages: 1, totalProducts: products.length } } });
});

app.delete('/api/products/:id', auth, async (req, res) => {
  const product = await Product.findById(req.params.id);
  if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
  if (product.seller.toString() !== req.user._id.toString() && req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Not authorized' });
  await Product.findByIdAndDelete(req.params.id);
  res.json({ success: true, message: 'Product deleted' });
});

// Cart Routes
app.get('/api/cart', auth, async (req, res) => {
  let cart = await Cart.findOne({ user: req.user._id }).populate({ path: 'items.product', select: 'title price images condition stock isApproved seller', populate: { path: 'seller', select: 'name' } }).lean();
  if (!cart) cart = { items: [] };
  const validItems = (cart.items || []).filter(i => i.product && i.product.isApproved && i.product.stock > 0);
  const itemCount = validItems.reduce((c, i) => c + i.quantity, 0);
  const subtotal = validItems.reduce((s, i) => s + (i.product.price * i.quantity), 0);
  res.json({ success: true, data: { cart: { _id: cart._id, items: validItems }, summary: { itemCount, subtotal, shipping: 500, total: subtotal + 500 } } });
});

app.post('/api/cart/add', auth, async (req, res) => {
  try {
    const { productId, quantity = 1 } = req.body;
    const product = await Product.findById(productId);
    if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
    if (!product.isApproved || product.stock < quantity) return res.status(400).json({ success: false, message: 'Product not available' });
    let cart = await Cart.findOne({ user: req.user._id });
    if (!cart) cart = new Cart({ user: req.user._id, items: [] });
    const existing = cart.items.find(i => i.product.toString() === productId);
    if (existing) existing.quantity += quantity; else cart.items.push({ product: productId, quantity });
    await cart.save();
    await cart.populate({ path: 'items.product', select: 'title price images condition stock seller', populate: { path: 'seller', select: 'name' } });
    const itemCount = cart.items.reduce((c, i) => c + i.quantity, 0);
    const subtotal = cart.items.reduce((s, i) => s + (i.product.price * i.quantity), 0);
    res.json({ success: true, message: 'Added to cart', data: { cart, summary: { itemCount, subtotal, shipping: 500, total: subtotal + 500 } } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
});

app.put('/api/cart/update', auth, async (req, res) => {
  const { productId, quantity } = req.body;
  const cart = await Cart.findOne({ user: req.user._id });
  if (!cart) return res.status(404).json({ success: false, message: 'Cart not found' });
  const item = cart.items.find(i => i.product.toString() === productId);
  if (!item) return res.status(404).json({ success: false, message: 'Item not in cart' });
  item.quantity = quantity; await cart.save();
  await cart.populate({ path: 'items.product', select: 'title price images condition stock seller', populate: { path: 'seller', select: 'name' } });
  const itemCount = cart.items.reduce((c, i) => c + i.quantity, 0);
  const subtotal = cart.items.reduce((s, i) => s + (i.product.price * i.quantity), 0);
  res.json({ success: true, data: { cart, summary: { itemCount, subtotal, shipping: 500, total: subtotal + 500 } } });
});

app.delete('/api/cart/remove/:productId', auth, async (req, res) => {
  const cart = await Cart.findOne({ user: req.user._id });
  if (!cart) return res.status(404).json({ success: false, message: 'Cart not found' });
  cart.items = cart.items.filter(i => i.product.toString() !== req.params.productId);
  await cart.save();
  await cart.populate({ path: 'items.product', select: 'title price images condition stock seller', populate: { path: 'seller', select: 'name' } });
  const itemCount = cart.items.reduce((c, i) => c + i.quantity, 0);
  const subtotal = cart.items.reduce((s, i) => s + (i.product.price * i.quantity), 0);
  res.json({ success: true, message: 'Removed from cart', data: { cart, summary: { itemCount, subtotal, shipping: 500, total: subtotal + 500 } } });
});

app.delete('/api/cart/clear', auth, async (req, res) => { await Cart.findOneAndUpdate({ user: req.user._id }, { items: [] }); res.json({ success: true, message: 'Cart cleared' }); });

// Order Routes
app.post('/api/orders', auth, async (req, res) => {
  try {
    const { shippingAddress, paymentMethod } = req.body;
    const cart = await Cart.findOne({ user: req.user._id }).populate({ path: 'items.product', select: 'title price images condition stock seller isApproved', populate: { path: 'seller', select: 'name' } }).lean();
    if (!cart || cart.items.length === 0) return res.status(400).json({ success: false, message: 'Cart is empty' });
    const validItems = cart.items.filter(i => i.product && i.product.isApproved && i.product.stock >= i.quantity);
    if (validItems.length === 0) return res.status(400).json({ success: false, message: 'No items available' });
    const orderItems = validItems.map(i => ({ product: i.product._id, seller: i.product.seller._id, title: i.product.title, image: i.product.images?.[0] || '', price: i.product.price, quantity: i.quantity, condition: i.product.condition }));
    const subtotal = validItems.reduce((s, i) => s + (i.product.price * i.quantity), 0);
    const order = await Order.create({ buyer: req.user._id, items: orderItems, totalAmount: subtotal, finalAmount: subtotal + 500, shippingAddress, paymentMethod: paymentMethod || 'paystack', statusHistory: [{ status: 'pending', note: 'Order placed' }] });
    await Cart.findOneAndUpdate({ user: req.user._id }, { items: [] });
    for (const item of validItems) { await Product.findByIdAndUpdate(item.product._id, { $inc: { stock: -item.quantity } }); }
    await order.populate('buyer', 'name email');
    res.status(201).json({ success: true, message: 'Order created', data: { order } });
  } catch (error) { res.status(500).json({ success: false, message: error.message }); }
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
  res.json({ success: true, data: { orders: filtered, pagination: { currentPage: 1, totalPages: 1, totalOrders: filtered.length } } });
});

app.put('/api/orders/:id/status', auth, async (req, res) => {
  const { status, note } = req.body;
  const order = await Order.findById(req.params.id);
  if (!order) return res.status(404).json({ success: false, message: 'Order not found' });
  const isSeller = order.items.some(i => i.seller.toString() === req.user._id.toString());
  if (!isSeller && req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Not authorized' });
  order.status = status;
  order.statusHistory.push({ status, note: note || `Updated to ${status}` });
  await order.save();
  res.json({ success: true, message: 'Order status updated', data: { order } });
});

// Admin Routes
app.get('/api/admin/dashboard', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
  const [totalUsers, totalSellers, totalProducts, totalOrders, pendingProducts] = await Promise.all([
    User.countDocuments(), User.countDocuments({ role: 'seller' }), Product.countDocuments(), Order.countDocuments(), Product.countDocuments({ isApproved: false })
  ]);
  const recentOrders = await Order.find().populate('buyer', 'name email').sort('-createdAt').limit(5).lean();
  const recentUsers = await User.find().select('name email role').sort('-createdAt').limit(5).lean();
  res.json({ success: true, data: { stats: { totalUsers, totalSellers, totalProducts, totalOrders, pendingApprovals: pendingProducts }, recentOrders, recentUsers } });
});

app.get('/api/admin/users', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
  const users = await User.find().select('-refreshToken').sort('-createdAt').lean();
  res.json({ success: true, data: { users } });
});

app.get('/api/admin/products/pending', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
  const products = await Product.find({ isApproved: false }).populate('seller', 'name email sellerProfile.storeName').sort('-createdAt').lean();
  res.json({ success: true, data: { products } });
});

app.put('/api/admin/products/:id/approve', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
  const { approved } = req.body;
  await Product.findByIdAndUpdate(req.params.id, { isApproved: approved });
  res.json({ success: true, message: approved ? 'Product approved' : 'Product rejected' });
});

app.get('/api/admin/orders', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
  const orders = await Order.find().populate('buyer', 'name email').sort('-createdAt').lean();
  res.json({ success: true, data: { orders } });
});

app.put('/api/admin/users/:id/ban', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
  const { ban } = req.body;
  await User.findByIdAndUpdate(req.params.id, { isBanned: ban });
  res.json({ success: true, message: ban ? 'User banned' : 'User unbanned' });
});

app.put('/api/admin/users/:id/approve-seller', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
  const { approved } = req.body;
  await User.findByIdAndUpdate(req.params.id, { 'sellerProfile.isApproved': approved, isVerified: approved });
  res.json({ success: true, message: approved ? 'Seller approved' : 'Seller rejected' });
});

// Rentals Routes
const rentalSchema = new mongoose.Schema({
  landlord: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  description: String,
  propertyType: String,
  price: Number,
  priceFrequency: String,
  location: { area: String, city: String, state: String },
  images: [String],
  amenities: [String],
  rooms: { bedrooms: Number, bathrooms: Number },
  isAvailable: { type: Boolean, default: true },
  isApproved: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});
const Rental = mongoose.model('Rental', rentalSchema);

app.get('/api/rentals', async (req, res) => {
  const rentals = await Rental.find({ isApproved: true, isAvailable: true }).populate('landlord', 'name email phone').sort('-createdAt').lean();
  res.json({ success: true, data: { rentals, pagination: { currentPage: 1, totalPages: 1, totalRentals: rentals.length } } });
});

app.get('/api/rentals/:id', async (req, res) => {
  const rental = await Rental.findById(req.params.id).populate('landlord', 'name email phone').lean();
  if (!rental) return res.status(404).json({ success: false, message: 'Rental not found' });
  await Rental.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } });
  res.json({ success: true, data: { rental } });
});

// Food Routes
app.get('/api/food/vendors', async (req, res) => {
  const vendors = [{ _id: '1', storeName: 'Campus Kitchen', cuisineType: ['local', 'continental'], rating: 4.5, deliveryTime: { min: 20, max: 40 }, deliveryFee: 300, isOpen: true }];
  res.json({ success: true, data: { vendors, pagination: { currentPage: 1, totalPages: 1, totalVendors: vendors.length } } });
});

// === START SEEDER ===
const seedDatabase = async () => {
  const adminExists = await User.findOne({ role: 'admin' });
  if (!adminExists) {
    await User.create({ name: process.env.ADMIN_NAME || 'Ospoly Admin', email: process.env.ADMIN_EMAIL || 'admin@ospolymarket.com', password: process.env.ADMIN_PASSWORD || 'Admin@123456', role: 'admin', isVerified: true, sellerProfile: { storeName: 'Ospoly Official', isApproved: true } });
    console.log('✅ Admin user created');
    const seller = await User.create({ name: 'TechWorld Store', email: 'seller@ospolymarket.com', password: 'Seller@123456', role: 'seller', isVerified: true, sellerProfile: { storeName: 'TechWorld Store', description: 'Your tech gadget hub', rating: 4.5, totalSales: 150, isApproved: true } });
    await Product.create([
      { seller: seller._id, title: 'Samsung Galaxy A54 5G - 128GB', description: 'Brand new Samsung Galaxy A54 5G with 128GB storage. Features 6.4" Super AMOLED display, 5000mAh battery, 50MP camera.', price: 185000, originalPrice: 210000, category: 'phones-accessories', condition: 'new', stock: 15, brand: 'Samsung', location: 'Lagos', images: [], isApproved: true, isFeatured: true, rating: 4.5, reviewCount: 23 },
      { seller: seller._id, title: 'iPhone 13 Pro Max - Used Excellent', description: 'Used iPhone 13 Pro Max in excellent condition. Battery health 92%. Includes original box and charger.', price: 450000, originalPrice: 520000, category: 'phones-accessories', condition: 'used', stock: 3, brand: 'Apple', location: 'Lagos', images: [], isApproved: true, rating: 4.8, reviewCount: 15 },
      { seller: seller._id, title: 'JBL Tune 510BT Wireless Headphones', description: 'New JBL Tune 510BT wireless headphones with 40-hour battery life.', price: 35000, originalPrice: 45000, category: 'electronics', condition: 'new', stock: 25, brand: 'JBL', location: 'Lagos', images: [], isApproved: true, isFlashDeal: true, rating: 4.3, reviewCount: 42 },
      { seller: seller._id, title: 'Student Study Desk', description: 'Sturdy study desk perfect for small spaces. Features 2 shelves, cable management.', price: 45000, originalPrice: 55000, category: 'furniture', condition: 'new', stock: 12, brand: 'HomeStyle', location: 'Ibadan', images: [], isApproved: true, isFeatured: true, rating: 4.0, reviewCount: 18 },
      { seller: seller._id, title: 'Ergonomic Office Chair - Used', description: 'Comfortable ergonomic chair with lumbar support. Perfect for long study sessions.', price: 38000, originalPrice: 65000, category: 'furniture', condition: 'used', stock: 5, brand: 'OfficePro', location: 'Ibadan', images: [], isApproved: true, isFlashDeal: true, rating: 4.2, reviewCount: 28 }
    ]);
    console.log('✅ Sample products created');
    console.log('📋 Login: admin@ospolymarket.com / Admin@123456');
  }
};

// === START SERVER ===
const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
  console.log(`🚀 Ospoly Market Server running on port ${PORT}`);
  console.log(`📚 API: http://localhost:${PORT}/api/health`);
  await seedDatabase();
});
