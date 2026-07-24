require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { v2: cloudinary } = require('cloudinary');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT || 10000);

// -----------------------------------------------------------------------------
// Security and app configuration
// -----------------------------------------------------------------------------
const allowedOrigins = (process.env.FRONTEND_URL || 'http://localhost:5173')
  .split(',')
  .map(origin => origin.trim().replace(/\/$/, ''))
  .filter(Boolean);

app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin.replace(/\/$/, ''))) return callback(null, true);
    return callback(new Error('Origin not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json({ limit: '1mb', verify: (req, res, buffer) => { req.rawBody = buffer; } }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 500,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests. Please try again shortly.' }
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { success: false, message: 'Too many login attempts. Please wait and try again.' }
});
app.use('/api', apiLimiter);

const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const normalizeMoney = value => {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(0, Math.round(number)) : 0;
};
const safeText = (value, max = 500) => String(value || '').trim().slice(0, max);
const normalizeEmail = value => String(value || '').trim().toLowerCase();
const escapeRegex = value => String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const parseJSON = (value, fallback) => {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'object') return value;
  try { return JSON.parse(value); } catch { return fallback; }
};

const listingQualityErrors = ({ title, description, price, originalPrice, stock, images = [] }) => {
  const errors = [];
  const cleanTitle = safeText(title, 180);
  const cleanDescription = safeText(description, 5000);
  const meaningful = text => new Set(text.toLowerCase().replace(/[^a-z0-9]/g, '')).size >= 4;
  if (cleanTitle.length < 5 || !meaningful(cleanTitle)) errors.push('Use a meaningful product title with at least 5 characters');
  if (cleanDescription.length < 20 || !meaningful(cleanDescription)) errors.push('Write a meaningful description with at least 20 characters');
  if (!Number.isFinite(Number(price)) || Number(price) < 1 || Number(price) > 1000000000) errors.push('Price must be between ₦1 and ₦1,000,000,000');
  if (originalPrice && (Number(originalPrice) <= Number(price) || Number(originalPrice) > Number(price) * 5)) errors.push('Original price must be above the selling price and no more than 5× the selling price');
  if (!Number.isInteger(Number(stock)) || Number(stock) < 0 || Number(stock) > 99999) errors.push('Stock must be a whole number between 0 and 99,999');
  if (!images.length) errors.push('At least one product image is required');
  return errors;
};

// -----------------------------------------------------------------------------
// Database
// -----------------------------------------------------------------------------
const connectDB = async () => {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is not configured');
  await mongoose.connect(process.env.MONGO_URI, {
    serverSelectionTimeoutMS: 10000,
    socketTimeoutMS: 45000
  });
  console.log('✅ MongoDB connected');
};

const addressSchema = new mongoose.Schema({
  street: { type: String, trim: true },
  city: { type: String, trim: true },
  state: { type: String, trim: true },
  country: { type: String, default: 'Nigeria', trim: true }
}, { _id: false });

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
  password: { type: String, required: true, select: false },
  role: { type: String, enum: ['buyer', 'seller', 'admin', 'moderator'], default: 'buyer', index: true },
  phone: { type: String, trim: true },
  address: addressSchema,
  avatar: String,
  isVerified: { type: Boolean, default: false },
  isBanned: { type: Boolean, default: false },
  walletBalance: { type: Number, default: 0, min: 0 },
  pendingBalance: { type: Number, default: 0, min: 0 },
  referralCode: { type: String, unique: true, sparse: true, uppercase: true, trim: true },
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  totalWithdrawn: { type: Number, default: 0, min: 0 },
  sellerDebt: { type: Number, default: 0, min: 0 },
  sellerProfile: {
    storeName: { type: String, trim: true, maxlength: 120 },
    description: { type: String, trim: true, maxlength: 1000 },
    logo: String,
    banner: String,
    returnPolicy: { type: String, trim: true, maxlength: 1500 },
    pickupAddress: { type: String, trim: true, maxlength: 300 },
    rating: { type: Number, default: 0 },
    totalSales: { type: Number, default: 0 },
    isApproved: { type: Boolean, default: false },
    identityVerified: { type: Boolean, default: false },
    chatEnabled: { type: Boolean, default: true },
    bankAccount: {
      bankName: String,
      bankCode: String,
      accountNumber: String,
      accountName: String,
      recipientCode: String,
      isVerified: { type: Boolean, default: false }
    }
  },
  refreshToken: { type: String, select: false },
  lastLogin: Date
}, { timestamps: true });

userSchema.pre('save', async function hashPassword(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});
userSchema.methods.comparePassword = function comparePassword(candidate) {
  return bcrypt.compare(candidate, this.password);
};

const shippingSchema = new mongoose.Schema({
  localFee: { type: Number, default: 1000, min: 0 },
  nationwideFee: { type: Number, default: 2500, min: 0 },
  freeShipping: { type: Boolean, default: false },
  pickupAvailable: { type: Boolean, default: true },
  processingDays: { type: Number, default: 2, min: 0, max: 30 }
}, { _id: false });

const productSchema = new mongoose.Schema({
  seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String, required: true, trim: true, maxlength: 180 },
  description: { type: String, required: true, trim: true, maxlength: 5000 },
  price: { type: Number, required: true, min: 1 },
  originalPrice: { type: Number, min: 0 },
  category: { type: String, required: true, trim: true, index: true },
  condition: { type: String, enum: ['new', 'used', 'refurbished'], default: 'new' },
  images: [{ type: String }],
  imagePublicIds: [{ type: String, select: false }],
  stock: { type: Number, default: 1, min: 0 },
  brand: { type: String, trim: true, maxlength: 100 },
  location: { type: String, trim: true, maxlength: 100, index: true },
  tags: [{ type: String, trim: true }],
  specifications: [{ name: { type: String, trim: true, maxlength: 80 }, value: { type: String, trim: true, maxlength: 300 } }],
  warranty: { type: String, trim: true, maxlength: 500 },
  returnPolicy: { type: String, trim: true, maxlength: 1000 },
  pickupLocation: { type: String, trim: true, maxlength: 250 },
  shipping: { type: shippingSchema, default: () => ({}) },
  chatEnabled: { type: Boolean, default: true },
  views: { type: Number, default: 0 },
  isApproved: { type: Boolean, default: false, index: true },
  isRejected: { type: Boolean, default: false, index: true },
  approvalNote: String,
  isFeatured: { type: Boolean, default: false },
  isFlashDeal: { type: Boolean, default: false },
  rating: { type: Number, default: 0, min: 0, max: 5 },
  reviewCount: { type: Number, default: 0, min: 0 }
}, { timestamps: true });
productSchema.index({ title: 'text', description: 'text', brand: 'text', tags: 'text' });

const cartSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  items: [{
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    quantity: { type: Number, default: 1, min: 1, max: 99 }
  }]
}, { timestamps: true });

const orderItemSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
  seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  title: String,
  image: String,
  price: Number,
  quantity: Number,
  status: { type: String, enum: ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'], default: 'pending' }
}, { _id: false });

const orderSchema = new mongoose.Schema({
  buyer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  items: [orderItemSchema],
  totalAmount: { type: Number, required: true },
  shippingCost: { type: Number, default: 0 },
  finalAmount: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'], default: 'pending', index: true },
  paymentMethod: { type: String, enum: ['pay_on_delivery', 'flutterwave', 'paystack'], default: 'pay_on_delivery' },
  paymentStatus: { type: String, enum: ['pending', 'initialized', 'paid', 'failed', 'refunded'], default: 'pending', index: true },
  paymentReference: { type: String, sparse: true, unique: true },
  paymentTransactionId: String,
  paymentChannel: String,
  paidAt: Date,
  gatewayFee: { type: Number, default: 0 },
  platformCommission: { type: Number, default: 0 },
  sellerAllocations: [{
    seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    itemSubtotal: Number,
    shippingAmount: Number,
    commission: Number,
    gatewayFee: Number,
    netAmount: Number,
    status: { type: String, enum: ['pending', 'available', 'refunded'], default: 'pending' },
    releasedAt: Date
  }],
  deliveredAt: Date,
  buyerConfirmedDeliveryAt: Date,
  stockRestored: { type: Boolean, default: false },
  shippingAddress: {
    fullName: String,
    phone: String,
    street: String,
    city: String,
    state: String,
    country: { type: String, default: 'Nigeria' }
  },
  statusHistory: [{ status: String, timestamp: { type: Date, default: Date.now }, note: String, changedBy: mongoose.Schema.Types.ObjectId }],
  report: {
    reason: String,
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'resolved'] },
    createdAt: Date,
    resolvedAt: Date,
    adminNote: String,
    amountRefunded: Number,
    refundReference: String
  }
}, { timestamps: true });

const reviewSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true, index: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  order: { type: mongoose.Schema.Types.ObjectId, ref: 'Order' },
  rating: { type: Number, required: true, min: 1, max: 5 },
  title: { type: String, maxlength: 120 },
  comment: { type: String, required: true, maxlength: 2000 },
  aspectRatings: { quality: Number, delivery: Number, communication: Number },
  isVerified: { type: Boolean, default: false },
  isApproved: { type: Boolean, default: true }
}, { timestamps: true });
reviewSchema.index({ product: 1, user: 1 }, { unique: true });

const chatSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }],
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
  type: { type: String, enum: ['buyer_to_seller', 'support'], default: 'buyer_to_seller' },
  isOpen: { type: Boolean, default: true },
  messages: [{
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: { type: String, maxlength: 2000 },
    readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now }
  }]
}, { timestamps: true });
chatSchema.index({ participants: 1, updatedAt: -1 });

const supportTicketSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  subject: { type: String, maxlength: 200 },
  message: { type: String, required: true, maxlength: 4000 },
  priority: { type: String, enum: ['low', 'normal', 'high', 'urgent'], default: 'normal' },
  status: { type: String, enum: ['open', 'in_progress', 'resolved', 'closed'], default: 'open' },
  replies: [{ from: mongoose.Schema.Types.ObjectId, message: String, createdAt: { type: Date, default: Date.now } }]
}, { timestamps: true });

const withdrawalSchema = new mongoose.Schema({
  seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  amount: { type: Number, required: true, min: 100 },
  bankAccount: { bankName: String, bankCode: String, accountNumber: String, accountName: String },
  notes: String,
  reference: { type: String, required: true, unique: true },
  status: { type: String, enum: ['requested', 'approved', 'processing', 'paid', 'rejected', 'failed', 'reversed'], default: 'requested' },
  amountTransferred: Number,
  transferReference: { type: String, sparse: true, unique: true },
  transferDate: Date,
  proofUrl: String,
  adminNote: String,
  balanceRestored: { type: Boolean, default: false },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewedAt: Date,
  paidAt: Date
}, { timestamps: true });

const walletTransactionSchema = new mongoose.Schema({
  seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  order: { type: mongoose.Schema.Types.ObjectId, ref: 'Order' },
  withdrawal: { type: mongoose.Schema.Types.ObjectId, ref: 'Withdrawal' },
  type: { type: String, enum: ['sale_pending', 'sale_released', 'withdrawal_reserved', 'withdrawal_paid', 'withdrawal_reversed', 'refund'] },
  amount: { type: Number, required: true },
  reference: { type: String, required: true, unique: true },
  balanceAfter: Number,
  status: { type: String, default: 'completed' }
}, { timestamps: true });

const followSchema = new mongoose.Schema({
  follower: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true });
followSchema.index({ follower: 1, seller: 1 }, { unique: true });

const notificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type: { type: String, default: 'general' },
  title: { type: String, maxlength: 160 },
  message: { type: String, maxlength: 1000 },
  link: String,
  read: { type: Boolean, default: false }
}, { timestamps: true });

const productReportSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true, index: true },
  reporter: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  reason: { type: String, required: true, maxlength: 2000 },
  category: { type: String, enum: ['counterfeit', 'prohibited', 'misleading', 'scam', 'duplicate', 'other'], default: 'other' },
  status: { type: String, enum: ['pending', 'reviewed', 'dismissed', 'actioned'], default: 'pending' },
  adminNote: String
}, { timestamps: true });
productReportSchema.index({ product: 1, reporter: 1, status: 1 });

const paymentSchema = new mongoose.Schema({
  order: { type: mongoose.Schema.Types.ObjectId, ref: 'Order', required: true, unique: true },
  buyer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  provider: { type: String, enum: ['flutterwave'], default: 'flutterwave' },
  reference: { type: String, required: true, unique: true },
  transactionId: String,
  amount: { type: Number, required: true },
  currency: { type: String, default: 'NGN' },
  status: { type: String, enum: ['initialized', 'successful', 'failed'], default: 'initialized' },
  gatewayFee: { type: Number, default: 0 },
  channel: String,
  rawVerifiedAt: Date
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);
const Cart = mongoose.model('Cart', cartSchema);
const Order = mongoose.model('Order', orderSchema);
const Review = mongoose.model('Review', reviewSchema);
const Chat = mongoose.model('Chat', chatSchema);
const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const WalletTransaction = mongoose.model('WalletTransaction', walletTransactionSchema);
const Follow = mongoose.model('Follow', followSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const ProductReport = mongoose.model('ProductReport', productReportSchema);
const Payment = mongoose.model('Payment', paymentSchema);

// -----------------------------------------------------------------------------
// Authentication helpers
// -----------------------------------------------------------------------------
const publicUser = user => ({
  _id: user._id,
  name: user.name,
  email: user.email,
  role: user.role,
  phone: user.phone,
  address: user.address,
  avatar: user.avatar,
  isVerified: user.isVerified,
  walletBalance: user.walletBalance || 0,
  pendingBalance: user.pendingBalance || 0,
  totalWithdrawn: user.totalWithdrawn || 0,
  referralCode: user.referralCode,
  sellerProfile: user.sellerProfile,
  verificationLevel: user.role === 'seller' || user.role === 'admin'
    ? (user.sellerProfile?.isApproved ? (user.sellerProfile?.bankAccount?.isVerified ? ((user.sellerProfile?.totalSales || 0) >= 10 && (user.sellerProfile?.rating || 0) >= 4 ? 'trusted' : 'bank_verified') : 'identity_verified') : 'unverified')
    : undefined
});

const createNotification = (user, title, message, link = '', type = 'general') => Notification.create({ user, title, message, link, type }).catch(() => null);
const makeReferralCode = (name = 'CAMPUS') => `${safeText(name, 12).replace(/[^a-z0-9]/gi, '').toUpperCase() || 'CAMPUS'}${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

const issueToken = user => jwt.sign(
  { id: user._id.toString(), role: user.role },
  process.env.JWT_SECRET,
  { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
);

const auth = asyncHandler(async (req, res, next) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.cookies?.accessToken;
  if (!token) return res.status(401).json({ success: false, message: 'Please sign in to continue' });
  let decoded;
  try { decoded = jwt.verify(token, process.env.JWT_SECRET); }
  catch { return res.status(401).json({ success: false, message: 'Your session has expired. Please sign in again.' }); }
  const user = await User.findById(decoded.id);
  if (!user || user.isBanned) return res.status(401).json({ success: false, message: 'Account unavailable' });
  req.user = user;
  next();
});

const allowRoles = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ success: false, message: 'You do not have permission to perform this action' });
  next();
};

// -----------------------------------------------------------------------------
// Image uploads (Cloudinary)
// -----------------------------------------------------------------------------
const hasCloudinary = Boolean(process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET);
if (hasCloudinary) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true
  });
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 6 },
  fileFilter(req, file, cb) {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    if (!allowed.includes(file.mimetype)) return cb(new Error('Only JPG, PNG and WebP images are allowed'));
    cb(null, true);
  }
});

const uploadImage = async (file, ownerId) => {
  if (!hasCloudinary) throw Object.assign(new Error('Product image storage is not configured. Add Cloudinary variables on Render.'), { statusCode: 503 });
  const dataUri = `data:${file.mimetype};base64,${file.buffer.toString('base64')}`;
  return cloudinary.uploader.upload(dataUri, {
    folder: `campus-market/products/${ownerId}`,
    resource_type: 'image',
    transformation: [
      { width: 1600, height: 1600, crop: 'limit' },
      { quality: 'auto', fetch_format: 'auto' }
    ]
  });
};

const uploadMany = async (files, ownerId) => {
  if (!files?.length) return [];
  return Promise.all(files.map(file => uploadImage(file, ownerId)));
};

// -----------------------------------------------------------------------------
// Shared cart and shipping helpers
// -----------------------------------------------------------------------------
const populateCart = cart => cart.populate({
  path: 'items.product',
  select: 'title price originalPrice images condition stock isApproved seller location shipping',
  populate: { path: 'seller', select: 'name sellerProfile.storeName' }
});

const calculateShipping = (items, destinationState = '') => {
  const sellerFees = new Map();
  const state = safeText(destinationState, 100).toLowerCase();
  for (const item of items) {
    const product = item.product;
    if (!product || product.shipping?.freeShipping) continue;
    const sellerId = String(product.seller?._id || product.seller || 'unknown');
    const local = state && safeText(product.location, 100).toLowerCase().includes(state);
    const fee = normalizeMoney(local ? product.shipping?.localFee : product.shipping?.nationwideFee) || (local ? 1000 : 2500);
    sellerFees.set(sellerId, Math.max(sellerFees.get(sellerId) || 0, fee));
  }
  return [...sellerFees.values()].reduce((sum, fee) => sum + fee, 0);
};

const cartPayload = (cart, destinationState = '') => {
  const validItems = (cart?.items || []).filter(item => item.product && item.product.isApproved && item.product.stock > 0);
  const itemCount = validItems.reduce((sum, item) => sum + item.quantity, 0);
  const subtotal = validItems.reduce((sum, item) => sum + (item.product.price * item.quantity), 0);
  const shipping = validItems.length ? calculateShipping(validItems, destinationState) : 0;
  return {
    cart: { _id: cart?._id, items: validItems },
    summary: { itemCount, subtotal, shipping, total: subtotal + shipping, shippingIsEstimate: !destinationState }
  };
};

// -----------------------------------------------------------------------------
// Flutterwave payment, seller allocation and earning-release helpers
// -----------------------------------------------------------------------------
const PLATFORM_COMMISSION_RATE = Number(process.env.PLATFORM_COMMISSION_RATE || 7);
const MIN_WITHDRAWAL = Number(process.env.MIN_WITHDRAWAL || 5000);

const flutterwaveRequest = async (path, options = {}) => {
  if (!process.env.FLW_SECRET_KEY) throw Object.assign(new Error('Flutterwave is not configured'), { statusCode: 503 });
  if (flutterwaveMode === 'live-locked') throw Object.assign(new Error('Live Flutterwave key is locked until FLW_LIVE_ENABLED=true'), { statusCode: 503 });
  const response = await fetch(`https://api.flutterwave.com/v3${path}`, {
    ...options,
    headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`, 'Content-Type': 'application/json', ...(options.headers || {}) }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.status === 'error') throw Object.assign(new Error(data.message || 'Flutterwave request failed'), { statusCode: 502 });
  return data;
};

const extractFlutterwaveFee = data => {
  if (Number.isFinite(Number(data.app_fee))) return Math.max(0, Math.round(Number(data.app_fee)));
  if (Array.isArray(data.fees)) return Math.max(0, Math.round(data.fees.reduce((sum, item) => sum + Number(item.amount || item.value || 0), 0)));
  return 0;
};

const buildSellerAllocations = (order, gatewayFee = 0) => {
  const groups = new Map();
  order.items.forEach(item => {
    const id = String(item.seller);
    const current = groups.get(id) || { seller: item.seller, itemSubtotal: 0 };
    current.itemSubtotal += normalizeMoney(item.price) * Number(item.quantity || 1);
    groups.set(id, current);
  });
  const entries = [...groups.values()];
  let assignedShipping = 0;
  let assignedFee = 0;
  return entries.map((entry, index) => {
    const last = index === entries.length - 1;
    const ratio = order.totalAmount > 0 ? entry.itemSubtotal / order.totalAmount : 0;
    const shippingAmount = last ? order.shippingCost - assignedShipping : Math.round(order.shippingCost * ratio);
    const feeShare = last ? gatewayFee - assignedFee : Math.round(gatewayFee * ratio);
    assignedShipping += shippingAmount;
    assignedFee += feeShare;
    const commission = Math.round(entry.itemSubtotal * PLATFORM_COMMISSION_RATE / 100);
    const netAmount = Math.max(0, entry.itemSubtotal + shippingAmount - commission - feeShare);
    return { seller: entry.seller, itemSubtotal: entry.itemSubtotal, shippingAmount, commission, gatewayFee: feeShare, netAmount, status: 'pending' };
  });
};

const creditPendingSellerAllocations = async order => {
  for (const allocation of order.sellerAllocations || []) {
    const ledgerRef = `sale_pending_${order._id}_${allocation.seller}`;
    const result = await WalletTransaction.updateOne(
      { reference: ledgerRef },
      { $setOnInsert: { seller: allocation.seller, order: order._id, type: 'sale_pending', amount: allocation.netAmount, reference: ledgerRef, status: 'completed' } },
      { upsert: true }
    );
    if (result.upsertedCount) {
      const seller = await User.findByIdAndUpdate(allocation.seller, { $inc: { pendingBalance: allocation.netAmount } }, { new: true });
      await WalletTransaction.updateOne({ reference: ledgerRef }, { $set: { balanceAfter: seller?.pendingBalance || 0 } });
      createNotification(allocation.seller, 'New paid order', `₦${allocation.netAmount.toLocaleString()} was added to pending earnings after commission and payment fees.`, '/seller', 'payment');
    }
  }
};

const finalizeVerifiedFlutterwavePayment = async (reference, verifiedData) => {
  const order = await Order.findOne({ paymentReference: reference });
  if (!order) throw Object.assign(new Error('Order for this payment was not found'), { statusCode: 404 });
  if (order.paymentStatus === 'paid') {
    await creditPendingSellerAllocations(order);
    return order;
  }
  const status = String(verifiedData.status || '').toLowerCase();
  const amount = Number(verifiedData.amount ?? verifiedData.charged_amount);
  const currency = String(verifiedData.currency || '').toUpperCase();
  const txRef = String(verifiedData.tx_ref || verifiedData.reference || reference);
  if (!['successful', 'succeeded'].includes(status) || amount !== Number(order.finalAmount) || currency !== 'NGN' || txRef !== reference) {
    throw Object.assign(new Error('Payment verification did not match the order'), { statusCode: 400 });
  }
  const gatewayFee = extractFlutterwaveFee(verifiedData);
  const allocations = buildSellerAllocations(order, gatewayFee);
  const platformCommission = allocations.reduce((sum, item) => sum + item.commission, 0);
  const updated = await Order.findOneAndUpdate(
    { _id: order._id, paymentStatus: { $ne: 'paid' } },
    { $set: { paymentStatus: 'paid', paymentMethod: 'flutterwave', paymentTransactionId: String(verifiedData.id || ''), paymentChannel: verifiedData.payment_type || verifiedData.payment_method?.type || '', paidAt: new Date(), gatewayFee, platformCommission, sellerAllocations: allocations } },
    { new: true }
  );
  if (!updated) {
    const fresh = await Order.findById(order._id);
    if (fresh?.paymentStatus === 'paid') await creditPendingSellerAllocations(fresh);
    return fresh;
  }
  await Payment.findOneAndUpdate({ order: order._id }, { $set: { status: 'successful', transactionId: String(verifiedData.id || ''), gatewayFee, channel: verifiedData.payment_type || '', rawVerifiedAt: new Date() } }, { upsert: true, new: true });
  await creditPendingSellerAllocations(updated);
  createNotification(order.buyer, 'Payment verified', `Payment for order #${String(order._id).slice(-8).toUpperCase()} was verified successfully.`, '/orders', 'payment');
  return updated;
};

const releaseOrderEarnings = async (order, reason = 'Buyer confirmed delivery') => {
  if (!order || order.paymentStatus !== 'paid' || order.report?.status === 'pending') return order;
  let changed = false;
  for (const allocation of order.sellerAllocations || []) {
    if (allocation.status !== 'pending') continue;
    const ledgerRef = `sale_release_${order._id}_${allocation.seller}`;
    const result = await WalletTransaction.updateOne(
      { reference: ledgerRef },
      { $setOnInsert: { seller: allocation.seller, order: order._id, type: 'sale_released', amount: allocation.netAmount, reference: ledgerRef, status: 'completed' } },
      { upsert: true }
    );
    if (result.upsertedCount) {
      const seller = await User.findOneAndUpdate({ _id: allocation.seller, pendingBalance: { $gte: allocation.netAmount } }, { $inc: { pendingBalance: -allocation.netAmount, walletBalance: allocation.netAmount, 'sellerProfile.totalSales': 1 } }, { new: true });
      if (!seller) { await WalletTransaction.deleteOne({ reference: ledgerRef }); continue; }
      await WalletTransaction.updateOne({ reference: ledgerRef }, { $set: { balanceAfter: seller.walletBalance || 0 } });
      createNotification(allocation.seller, 'Earnings available', `₦${allocation.netAmount.toLocaleString()} is now available for withdrawal.`, '/seller', 'wallet');
    }
    allocation.status = 'available';
    allocation.releasedAt = new Date();
    changed = true;
  }
  if (changed) {
    order.statusHistory.push({ status: 'delivered', note: `Seller earnings released: ${reason}` });
    await order.save();
  }
  return order;
};

const releaseEligibleEarnings = async () => {
  const threshold = new Date(Date.now() - 48 * 60 * 60 * 1000);
  const orders = await Order.find({ paymentStatus: 'paid', deliveredAt: { $lte: threshold }, 'sellerAllocations.status': 'pending', $or: [{ 'report.status': { $exists: false } }, { 'report.status': { $ne: 'pending' } }] }).limit(50);
  for (const order of orders) await releaseOrderEarnings(order, '48 hours passed after delivery without a dispute');
};

// -----------------------------------------------------------------------------
// Health and authentication
// -----------------------------------------------------------------------------
const hasFlutterwave = Boolean(process.env.FLW_SECRET_KEY);
const flutterwaveMode = !hasFlutterwave ? 'not-configured' : process.env.FLW_SECRET_KEY.includes('_TEST') || process.env.FLW_SECRET_KEY.includes('TEST-') ? 'test' : process.env.FLW_LIVE_ENABLED === 'true' ? 'live' : 'live-locked';

app.get('/api/health', (req, res) => res.json({
  success: true,
  message: 'Campus Market API is running',
  version: '7.1.0',
  imageStorageConfigured: hasCloudinary,
  paymentProvider: 'flutterwave',
  paymentMode: flutterwaveMode
}));

app.post('/api/auth/register', authLimiter, asyncHandler(async (req, res) => {
  const name = safeText(req.body.name, 100);
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || '');
  const role = req.body.role === 'seller' ? 'seller' : 'buyer'; // Never allow public admin registration.
  const phone = safeText(req.body.phone, 30);
  const storeName = safeText(req.body.storeName, 120);
  const submittedReferral = safeText(req.body.referralCode, 30).toUpperCase();

  if (name.length < 2) return res.status(400).json({ success: false, message: 'Enter your full name' });
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ success: false, message: 'Enter a valid email address' });
  if (password.length < 8) return res.status(400).json({ success: false, message: 'Password must be at least 8 characters' });
  if (role === 'seller' && storeName.length < 2) return res.status(400).json({ success: false, message: 'Store name is required for sellers' });
  if (await User.exists({ email })) return res.status(409).json({ success: false, message: 'An account already exists with this email' });

  const referrer = submittedReferral ? await User.findOne({ referralCode: submittedReferral }) : null;
  let referralCode = makeReferralCode(name);
  while (await User.exists({ referralCode })) referralCode = makeReferralCode(name);
  const user = await User.create({
    name,
    email,
    password,
    phone,
    role,
    referralCode,
    referredBy: referrer?._id,
    sellerProfile: role === 'seller' ? { storeName, isApproved: false, chatEnabled: true } : undefined
  });
  if (referrer) createNotification(referrer._id, 'New referral joined', `${name} joined Campus Market using your referral code. Rewards unlock after their first verified paid order.`, '/profile', 'referral');
  const token = issueToken(user);
  res.cookie('accessToken', token, { httpOnly: true, secure: isProduction, sameSite: isProduction ? 'none' : 'lax', maxAge: 24 * 60 * 60 * 1000 });
  res.status(201).json({ success: true, data: { user: publicUser(user), accessToken: token } });
}));

app.post('/api/auth/login', authLimiter, asyncHandler(async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || '');
  const user = await User.findOne({ email }).select('+password');
  if (!user || !(await user.comparePassword(password))) return res.status(401).json({ success: false, message: 'Invalid email or password' });
  if (user.isBanned) return res.status(403).json({ success: false, message: 'This account is suspended' });
  user.lastLogin = new Date();
  if (!user.referralCode) {
    let code = makeReferralCode(user.name);
    while (await User.exists({ referralCode: code })) code = makeReferralCode(user.name);
    user.referralCode = code;
  }
  await user.save();
  const token = issueToken(user);
  res.cookie('accessToken', token, { httpOnly: true, secure: isProduction, sameSite: isProduction ? 'none' : 'lax', maxAge: 24 * 60 * 60 * 1000 });
  res.json({ success: true, data: { user: publicUser(user), accessToken: token } });
}));

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('accessToken', { secure: isProduction, sameSite: isProduction ? 'none' : 'lax' });
  res.json({ success: true });
});

app.get('/api/auth/me', auth, (req, res) => res.json({ success: true, data: { user: publicUser(req.user) } }));

app.put('/api/auth/profile', auth, asyncHandler(async (req, res) => {
  const updates = {
    name: safeText(req.body.name || req.user.name, 100),
    phone: safeText(req.body.phone, 30),
    address: {
      street: safeText(req.body.street ?? req.user.address?.street, 200),
      city: safeText(req.body.city ?? req.user.address?.city, 100),
      state: safeText(req.body.state ?? req.user.address?.state, 100),
      country: safeText(req.body.country ?? req.user.address?.country ?? 'Nigeria', 100)
    }
  };
  if (req.user.role === 'seller' && req.body.storeName !== undefined) {
    updates['sellerProfile.storeName'] = safeText(req.body.storeName, 120);
    if (req.body.storeDescription !== undefined) updates['sellerProfile.description'] = safeText(req.body.storeDescription, 1000);
    if (req.body.returnPolicy !== undefined) updates['sellerProfile.returnPolicy'] = safeText(req.body.returnPolicy, 1500);
    if (req.body.pickupAddress !== undefined) updates['sellerProfile.pickupAddress'] = safeText(req.body.pickupAddress, 300);
  }
  const user = await User.findByIdAndUpdate(req.user._id, { $set: updates }, { new: true, runValidators: true });
  res.json({ success: true, data: { user: publicUser(user) } });
}));

app.put('/api/auth/password', auth, authLimiter, asyncHandler(async (req, res) => {
  const currentPassword = String(req.body.currentPassword || '');
  const newPassword = String(req.body.newPassword || '');
  if (newPassword.length < 10) return res.status(400).json({ success: false, message: 'New password must be at least 10 characters' });
  if (!/[A-Z]/.test(newPassword) || !/[a-z]/.test(newPassword) || !/\d/.test(newPassword)) return res.status(400).json({ success: false, message: 'Use uppercase, lowercase and a number in the new password' });
  const user = await User.findById(req.user._id).select('+password');
  if (!user || !(await user.comparePassword(currentPassword))) return res.status(400).json({ success: false, message: 'Current password is incorrect' });
  user.password = newPassword;
  await user.save();
  res.json({ success: true, message: 'Password changed successfully' });
}));

// -----------------------------------------------------------------------------
// Public stores, following, notifications and referrals
// -----------------------------------------------------------------------------
app.get('/api/stores/:sellerId', asyncHandler(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.sellerId)) return res.status(404).json({ success: false, message: 'Store not found' });
  const seller = await User.findOne({ _id: req.params.sellerId, role: { $in: ['seller', 'admin'] }, 'sellerProfile.isApproved': true }).select('name avatar createdAt address.state sellerProfile.storeName sellerProfile.description sellerProfile.logo sellerProfile.banner sellerProfile.returnPolicy sellerProfile.pickupAddress sellerProfile.rating sellerProfile.totalSales sellerProfile.isApproved sellerProfile.bankAccount.isVerified sellerProfile.chatEnabled').lean();
  if (!seller) return res.status(404).json({ success: false, message: 'Store not found or not approved' });
  const [products, followers, delivered, reviewStats] = await Promise.all([
    Product.find({ seller: seller._id, isApproved: true }).populate('seller', 'name sellerProfile.storeName sellerProfile.rating').sort('-createdAt').limit(100).lean(),
    Follow.countDocuments({ seller: seller._id }),
    Order.aggregate([{ $unwind: '$items' }, { $match: { 'items.seller': seller._id, 'items.status': 'delivered' } }, { $group: { _id: null, quantity: { $sum: '$items.quantity' } } }]),
    Review.aggregate([{ $lookup: { from: 'products', localField: 'product', foreignField: '_id', as: 'productDoc' } }, { $unwind: '$productDoc' }, { $match: { 'productDoc.seller': seller._id, isApproved: true, isVerified: true } }, { $group: { _id: null, average: { $avg: '$rating' }, count: { $sum: 1 } } }])
  ]);
  const verificationLevel = seller.sellerProfile?.bankAccount?.isVerified ? ((delivered[0]?.quantity || 0) >= 10 && (reviewStats[0]?.average || 0) >= 4 ? 'trusted' : 'bank_verified') : 'identity_verified';
  if (seller.sellerProfile?.bankAccount) delete seller.sellerProfile.bankAccount;
  res.json({ success: true, data: { seller: { ...seller, verificationLevel }, products, metrics: { followers, deliveredSales: delivered[0]?.quantity || 0, rating: reviewStats[0]?.average || seller.sellerProfile?.rating || 0, reviews: reviewStats[0]?.count || 0, products: products.length } } });
}));

app.get('/api/stores/:sellerId/follow-status', auth, asyncHandler(async (req, res) => {
  const following = Boolean(await Follow.exists({ follower: req.user._id, seller: req.params.sellerId }));
  res.json({ success: true, data: { following } });
}));

app.post('/api/stores/:sellerId/follow', auth, asyncHandler(async (req, res) => {
  if (String(req.params.sellerId) === String(req.user._id)) return res.status(400).json({ success: false, message: 'You cannot follow your own store' });
  const seller = await User.findOne({ _id: req.params.sellerId, role: { $in: ['seller', 'admin'] }, 'sellerProfile.isApproved': true });
  if (!seller) return res.status(404).json({ success: false, message: 'Store not found' });
  await Follow.updateOne({ follower: req.user._id, seller: seller._id }, { $setOnInsert: { follower: req.user._id, seller: seller._id } }, { upsert: true });
  createNotification(seller._id, 'New store follower', `${req.user.name} followed your store.`, `/stores/${seller._id}`, 'follow');
  res.json({ success: true, message: 'Store followed' });
}));

app.delete('/api/stores/:sellerId/follow', auth, asyncHandler(async (req, res) => {
  await Follow.deleteOne({ follower: req.user._id, seller: req.params.sellerId });
  res.json({ success: true, message: 'Store unfollowed' });
}));

app.get('/api/notifications', auth, asyncHandler(async (req, res) => {
  const notifications = await Notification.find({ user: req.user._id }).sort('-createdAt').limit(100).lean();
  res.json({ success: true, data: { notifications, unreadCount: notifications.filter(item => !item.read).length } });
}));
app.put('/api/notifications/:id/read', auth, asyncHandler(async (req, res) => {
  await Notification.updateOne({ _id: req.params.id, user: req.user._id }, { $set: { read: true } });
  res.json({ success: true });
}));
app.put('/api/notifications/read-all', auth, asyncHandler(async (req, res) => {
  await Notification.updateMany({ user: req.user._id, read: false }, { $set: { read: true } });
  res.json({ success: true });
}));

app.get('/api/referrals/me', auth, asyncHandler(async (req, res) => {
  const referrals = await User.find({ referredBy: req.user._id }).select('name role createdAt').sort('-createdAt').lean();
  res.json({ success: true, data: { referralCode: req.user.referralCode, referrals, verifiedRewards: 0, note: 'Rewards activate only after a referred user completes a verified paid order.' } });
}));

// -----------------------------------------------------------------------------
// Products and images
// -----------------------------------------------------------------------------
app.get('/api/products/flash-deals', asyncHandler(async (req, res) => {
  const products = await Product.find({ isApproved: true, isFlashDeal: true, stock: { $gt: 0 } })
    .populate('seller', 'name sellerProfile.storeName sellerProfile.rating')
    .sort('-createdAt').limit(20).lean();
  res.json({ success: true, data: { products } });
}));

app.get('/api/products/featured', asyncHandler(async (req, res) => {
  const products = await Product.find({ isApproved: true, isFeatured: true, stock: { $gt: 0 } })
    .populate('seller', 'name sellerProfile.storeName sellerProfile.rating')
    .sort('-createdAt').limit(20).lean();
  res.json({ success: true, data: { products } });
}));

app.get('/api/products/seller/my-products', auth, allowRoles('seller', 'admin'), asyncHandler(async (req, res) => {
  const sellerId = req.user.role === 'admin' && req.query.seller ? req.query.seller : req.user._id;
  const products = await Product.find({ seller: sellerId }).sort('-createdAt').lean();
  res.json({ success: true, data: { products } });
}));

app.get('/api/products', asyncHandler(async (req, res) => {
  const page = Math.max(1, Number(req.query.page) || 1);
  const limit = Math.min(60, Math.max(1, Number(req.query.limit) || 20));
  const query = { isApproved: true };
  if (req.query.category) query.category = safeText(req.query.category, 80);
  if (req.query.condition) query.condition = safeText(req.query.condition, 30);
  if (req.query.seller && mongoose.isValidObjectId(req.query.seller)) query.seller = req.query.seller;
  if (req.query.location) query.location = { $regex: escapeRegex(req.query.location), $options: 'i' };
  if (req.query.minPrice || req.query.maxPrice) {
    query.price = {};
    if (req.query.minPrice) query.price.$gte = normalizeMoney(req.query.minPrice);
    if (req.query.maxPrice) query.price.$lte = normalizeMoney(req.query.maxPrice);
  }
  if (req.query.search) {
    const term = escapeRegex(safeText(req.query.search, 100));
    query.$or = [
      { title: { $regex: term, $options: 'i' } },
      { description: { $regex: term, $options: 'i' } },
      { brand: { $regex: term, $options: 'i' } },
      { location: { $regex: term, $options: 'i' } }
    ];
  }
  const allowedSort = { newest: '-createdAt', 'price-low': 'price', 'price-high': '-price', rating: '-rating', popular: '-views' };
  const sort = allowedSort[req.query.sort] || '-createdAt';
  const [products, total] = await Promise.all([
    Product.find(query).populate('seller', 'name sellerProfile.storeName sellerProfile.rating').sort(sort).skip((page - 1) * limit).limit(limit).lean(),
    Product.countDocuments(query)
  ]);
  res.json({ success: true, data: { products, pagination: { currentPage: page, totalPages: Math.ceil(total / limit), totalProducts: total } } });
}));

app.get('/api/products/:id', asyncHandler(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ success: false, message: 'Product not found' });
  const product = await Product.findOne({ _id: req.params.id, isApproved: true })
    .populate('seller', 'name email sellerProfile.storeName sellerProfile.rating sellerProfile.totalSales sellerProfile.chatEnabled sellerProfile.bankAccount.isVerified')
    .lean();
  if (!product) return res.status(404).json({ success: false, message: 'Product not found or awaiting approval' });
  Product.updateOne({ _id: product._id }, { $inc: { views: 1 } }).catch(() => {});
  const [reviews, similarProducts, sellerProducts, followerCount, deliveredSales] = await Promise.all([
    Review.find({ product: product._id, isApproved: true }).populate('user', 'name avatar').sort('-createdAt').limit(30).lean(),
    Product.find({ _id: { $ne: product._id }, category: product.category, isApproved: true, stock: { $gt: 0 } }).populate('seller', 'name sellerProfile.storeName sellerProfile.rating').sort('-rating -createdAt').limit(6).lean(),
    Product.find({ _id: { $ne: product._id }, seller: product.seller._id, isApproved: true, stock: { $gt: 0 } }).populate('seller', 'name sellerProfile.storeName sellerProfile.rating').sort('-createdAt').limit(4).lean(),
    Follow.countDocuments({ seller: product.seller._id }),
    Order.aggregate([{ $unwind: '$items' }, { $match: { 'items.seller': product.seller._id, 'items.status': 'delivered' } }, { $group: { _id: null, quantity: { $sum: '$items.quantity' } } }])
  ]);
  const sellerMetrics = { followers: followerCount, deliveredSales: deliveredSales[0]?.quantity || 0, verificationLevel: product.seller?.sellerProfile?.bankAccount?.isVerified ? ((deliveredSales[0]?.quantity || 0) >= 10 && (product.seller?.sellerProfile?.rating || 0) >= 4 ? 'trusted' : 'bank_verified') : 'identity_verified' };
  if (product.seller?.sellerProfile?.bankAccount) delete product.seller.sellerProfile.bankAccount;
  res.json({ success: true, data: { product, reviews, similarProducts, sellerProducts, sellerMetrics } });
}));

app.post('/api/products', auth, allowRoles('seller', 'admin'), upload.array('images', 6), asyncHandler(async (req, res) => {
  if (req.user.role === 'seller' && !req.user.sellerProfile?.isApproved) return res.status(403).json({ success: false, message: 'Your seller account must be approved before listing products' });
  if (!req.files?.length) return res.status(400).json({ success: false, message: 'Upload at least one product image' });

  const title = safeText(req.body.title, 180);
  const description = safeText(req.body.description, 5000);
  const price = normalizeMoney(req.body.price);
  const stock = Math.floor(Number(req.body.stock));
  const qualityErrors = listingQualityErrors({ title, description, price, originalPrice: req.body.originalPrice, stock, images: req.files || [] });
  if (qualityErrors.length) return res.status(400).json({ success: false, message: qualityErrors.join('. ') });

  const uploaded = await uploadMany(req.files, req.user._id.toString());
  const product = await Product.create({
    seller: req.user._id,
    title,
    description,
    price,
    originalPrice: normalizeMoney(req.body.originalPrice) || undefined,
    stock,
    category: safeText(req.body.category, 80),
    condition: ['new', 'used', 'refurbished'].includes(req.body.condition) ? req.body.condition : 'new',
    brand: safeText(req.body.brand, 100),
    location: safeText(req.body.location, 100),
    tags: safeText(req.body.tags, 300).split(',').map(tag => tag.trim()).filter(Boolean).slice(0, 12),
    specifications: parseJSON(req.body.specifications, []).filter(item => item?.name && item?.value).slice(0, 20).map(item => ({ name: safeText(item.name, 80), value: safeText(item.value, 300) })),
    warranty: safeText(req.body.warranty, 500),
    returnPolicy: safeText(req.body.returnPolicy, 1000),
    pickupLocation: safeText(req.body.pickupLocation, 250),
    chatEnabled: String(req.body.chatEnabled) !== 'false',
    shipping: {
      localFee: normalizeMoney(req.body.localDeliveryFee) || 1000,
      nationwideFee: normalizeMoney(req.body.nationwideDeliveryFee) || 2500,
      freeShipping: String(req.body.freeShipping) === 'true',
      pickupAvailable: String(req.body.pickupAvailable) !== 'false',
      processingDays: Math.min(30, Math.max(0, Number(req.body.processingDays) || 2))
    },
    images: uploaded.map(image => image.secure_url),
    imagePublicIds: uploaded.map(image => image.public_id),
    isApproved: req.user.role === 'admin'
  });
  res.status(201).json({ success: true, message: product.isApproved ? 'Product published' : 'Product submitted for admin approval', data: { product } });
}));

app.put('/api/products/:id', auth, allowRoles('seller', 'admin'), upload.array('images', 6), asyncHandler(async (req, res) => {
  const product = await Product.findById(req.params.id).select('+imagePublicIds');
  if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
  if (req.user.role !== 'admin' && product.seller.toString() !== req.user._id.toString()) return res.status(403).json({ success: false, message: 'You cannot edit this product' });

  const oldImages = [...product.images];
  const oldPublicIds = [...(product.imagePublicIds || [])];
  const existingImages = parseJSON(req.body.existingImages, oldImages).filter(url => oldImages.includes(url)).slice(0, 6);
  const existingPublicIds = existingImages.map(url => oldPublicIds[oldImages.indexOf(url)] || '');
  const maxNew = Math.max(0, 6 - existingImages.length);
  const files = (req.files || []).slice(0, maxNew);
  const uploaded = await uploadMany(files, req.user._id.toString());
  const removedIndexes = oldImages.map((url, index) => existingImages.includes(url) ? -1 : index).filter(index => index >= 0);
  if (hasCloudinary) await Promise.all(removedIndexes.map(index => oldPublicIds[index] ? cloudinary.uploader.destroy(oldPublicIds[index]).catch(() => null) : null));

  product.title = safeText(req.body.title ?? product.title, 180);
  product.description = safeText(req.body.description ?? product.description, 5000);
  product.price = req.body.price === undefined ? product.price : normalizeMoney(req.body.price);
  product.originalPrice = req.body.originalPrice === undefined ? product.originalPrice : normalizeMoney(req.body.originalPrice) || undefined;
  product.stock = req.body.stock === undefined ? product.stock : Math.max(0, Math.floor(Number(req.body.stock) || 0));
  product.category = safeText(req.body.category ?? product.category, 80);
  product.condition = ['new', 'used', 'refurbished'].includes(req.body.condition) ? req.body.condition : product.condition;
  product.brand = safeText(req.body.brand ?? product.brand, 100);
  product.location = safeText(req.body.location ?? product.location, 100);
  if (req.body.tags !== undefined) product.tags = safeText(req.body.tags, 300).split(',').map(tag => tag.trim()).filter(Boolean).slice(0, 12);
  if (req.body.specifications !== undefined) product.specifications = parseJSON(req.body.specifications, []).filter(item => item?.name && item?.value).slice(0, 20).map(item => ({ name: safeText(item.name, 80), value: safeText(item.value, 300) }));
  if (req.body.warranty !== undefined) product.warranty = safeText(req.body.warranty, 500);
  if (req.body.returnPolicy !== undefined) product.returnPolicy = safeText(req.body.returnPolicy, 1000);
  if (req.body.pickupLocation !== undefined) product.pickupLocation = safeText(req.body.pickupLocation, 250);
  product.chatEnabled = req.body.chatEnabled === undefined ? product.chatEnabled : String(req.body.chatEnabled) !== 'false';
  if (req.body.localDeliveryFee !== undefined) product.shipping.localFee = normalizeMoney(req.body.localDeliveryFee);
  if (req.body.nationwideDeliveryFee !== undefined) product.shipping.nationwideFee = normalizeMoney(req.body.nationwideDeliveryFee);
  if (req.body.freeShipping !== undefined) product.shipping.freeShipping = String(req.body.freeShipping) === 'true';
  if (req.body.pickupAvailable !== undefined) product.shipping.pickupAvailable = String(req.body.pickupAvailable) !== 'false';
  if (req.body.processingDays !== undefined) product.shipping.processingDays = Math.min(30, Math.max(0, Number(req.body.processingDays) || 0));
  product.images = [...existingImages, ...uploaded.map(image => image.secure_url)];
  product.imagePublicIds = [...existingPublicIds, ...uploaded.map(image => image.public_id)];
  const qualityErrors = listingQualityErrors(product);
  if (qualityErrors.length) return res.status(400).json({ success: false, message: qualityErrors.join('. ') });
  if (req.user.role !== 'admin') {
    product.isApproved = false;
    product.isRejected = false;
    product.approvalNote = '';
  }
  await product.save();
  res.json({ success: true, message: req.user.role === 'admin' ? 'Product updated' : 'Product updated and returned for approval', data: { product } });
}));

app.delete('/api/products/:id', auth, allowRoles('seller', 'admin'), asyncHandler(async (req, res) => {
  const product = await Product.findById(req.params.id).select('+imagePublicIds');
  if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
  if (req.user.role !== 'admin' && product.seller.toString() !== req.user._id.toString()) return res.status(403).json({ success: false, message: 'You cannot delete this product' });
  if (hasCloudinary) await Promise.all((product.imagePublicIds || []).map(id => cloudinary.uploader.destroy(id).catch(() => null)));
  await product.deleteOne();
  await Cart.updateMany({}, { $pull: { items: { product: product._id } } });
  res.json({ success: true, message: 'Product deleted' });
}));

app.post('/api/products/:id/reviews', auth, asyncHandler(async (req, res) => {
  const product = await Product.findOne({ _id: req.params.id, isApproved: true });
  if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
  const deliveredOrder = await Order.findOne({ buyer: req.user._id, status: 'delivered', 'items.product': product._id });
  if (!deliveredOrder) return res.status(403).json({ success: false, message: 'Only buyers with a delivered order can review this product' });
  const review = await Review.findOneAndUpdate(
    { product: product._id, user: req.user._id },
    {
      $set: {
        rating: Math.min(5, Math.max(1, Number(req.body.rating) || 1)),
        title: safeText(req.body.title, 120),
        comment: safeText(req.body.comment, 2000),
        aspectRatings: req.body.aspectRatings,
        order: deliveredOrder?._id,
        isVerified: Boolean(deliveredOrder)
      }
    },
    { upsert: true, new: true, runValidators: true }
  );
  const aggregate = await Review.aggregate([{ $match: { product: product._id, isApproved: true } }, { $group: { _id: null, rating: { $avg: '$rating' }, count: { $sum: 1 } } }]);
  await Product.updateOne({ _id: product._id }, { rating: aggregate[0]?.rating || 0, reviewCount: aggregate[0]?.count || 0 });
  const sellerRating = await Review.aggregate([{ $match: { isApproved: true, isVerified: true } }, { $lookup: { from: 'products', localField: 'product', foreignField: '_id', as: 'p' } }, { $unwind: '$p' }, { $match: { 'p.seller': product.seller } }, { $group: { _id: null, average: { $avg: '$rating' } } }]);
  await User.updateOne({ _id: product.seller }, { $set: { 'sellerProfile.rating': sellerRating[0]?.average || 0 } });
  res.status(201).json({ success: true, data: { review } });
}));

app.post('/api/products/:id/report', auth, asyncHandler(async (req, res) => {
  const product = await Product.findOne({ _id: req.params.id, isApproved: true });
  if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
  if (product.seller.toString() === req.user._id.toString()) return res.status(400).json({ success: false, message: 'You cannot report your own listing' });
  const reason = safeText(req.body.reason, 2000);
  const category = ['counterfeit', 'prohibited', 'misleading', 'scam', 'duplicate', 'other'].includes(req.body.category) ? req.body.category : 'other';
  if (reason.length < 10) return res.status(400).json({ success: false, message: 'Explain the problem in at least 10 characters' });
  const report = await ProductReport.create({ product: product._id, reporter: req.user._id, seller: product.seller, reason, category });
  res.status(201).json({ success: true, message: 'Listing reported for moderator review', data: { report } });
}));

// -----------------------------------------------------------------------------
// Cart and location-aware delivery estimates
// -----------------------------------------------------------------------------
app.get('/api/cart', auth, asyncHandler(async (req, res) => {
  let cart = await Cart.findOne({ user: req.user._id });
  if (!cart) cart = await Cart.create({ user: req.user._id, items: [] });
  await populateCart(cart);
  res.json({ success: true, data: cartPayload(cart, req.query.state || req.user.address?.state) });
}));

app.post('/api/cart/add', auth, asyncHandler(async (req, res) => {
  if (!mongoose.isValidObjectId(req.body.productId)) return res.status(400).json({ success: false, message: 'Invalid product' });
  const product = await Product.findOne({ _id: req.body.productId, isApproved: true });
  if (!product || product.stock < 1) return res.status(404).json({ success: false, message: 'Product is unavailable' });
  const quantity = Math.min(99, Math.max(1, Math.floor(Number(req.body.quantity) || 1)));
  let cart = await Cart.findOne({ user: req.user._id });
  if (!cart) cart = new Cart({ user: req.user._id, items: [] });
  const existing = cart.items.find(item => item.product.toString() === product._id.toString());
  const nextQuantity = (existing?.quantity || 0) + quantity;
  if (nextQuantity > product.stock) return res.status(400).json({ success: false, message: `Only ${product.stock} item(s) are available` });
  if (existing) existing.quantity = nextQuantity;
  else cart.items.push({ product: product._id, quantity });
  await cart.save();
  await populateCart(cart);
  res.json({ success: true, data: cartPayload(cart, req.user.address?.state) });
}));

app.put('/api/cart/update', auth, asyncHandler(async (req, res) => {
  const quantity = Math.floor(Number(req.body.quantity));
  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 99) return res.status(400).json({ success: false, message: 'Quantity must be between 1 and 99' });
  const product = await Product.findOne({ _id: req.body.productId, isApproved: true });
  if (!product || product.stock < quantity) return res.status(400).json({ success: false, message: `Only ${product?.stock || 0} item(s) are available` });
  const cart = await Cart.findOne({ user: req.user._id });
  const item = cart?.items.find(entry => entry.product.toString() === req.body.productId);
  if (!item) return res.status(404).json({ success: false, message: 'Item is not in your cart' });
  item.quantity = quantity;
  await cart.save();
  await populateCart(cart);
  res.json({ success: true, data: cartPayload(cart, req.user.address?.state) });
}));

app.delete('/api/cart/remove/:productId', auth, asyncHandler(async (req, res) => {
  const cart = await Cart.findOne({ user: req.user._id });
  if (!cart) return res.json({ success: true, data: { cart: { items: [] }, summary: { itemCount: 0, subtotal: 0, shipping: 0, total: 0 } } });
  cart.items = cart.items.filter(item => item.product.toString() !== req.params.productId);
  await cart.save();
  await populateCart(cart);
  res.json({ success: true, data: cartPayload(cart, req.user.address?.state) });
}));

app.delete('/api/cart/clear', auth, asyncHandler(async (req, res) => {
  await Cart.findOneAndUpdate({ user: req.user._id }, { $set: { items: [] } });
  res.json({ success: true });
}));

app.post('/api/orders/shipping-quote', auth, asyncHandler(async (req, res) => {
  const cart = await Cart.findOne({ user: req.user._id });
  if (!cart) return res.json({ success: true, data: { shipping: 0 } });
  await populateCart(cart);
  const data = cartPayload(cart, req.body.state);
  res.json({ success: true, data: { shipping: data.summary.shipping, total: data.summary.total } });
}));

// -----------------------------------------------------------------------------
// Orders, reports and interim pay-on-delivery
// -----------------------------------------------------------------------------
app.post('/api/orders', auth, asyncHandler(async (req, res) => {
  const address = req.body.shippingAddress || {};
  const requestedPaymentMethod = req.body.paymentMethod === 'flutterwave' ? 'flutterwave' : 'pay_on_delivery';
  if (![address.fullName, address.phone, address.street, address.city, address.state].every(value => safeText(value, 200))) {
    return res.status(400).json({ success: false, message: 'Complete all delivery address fields' });
  }
  const cart = await Cart.findOne({ user: req.user._id });
  if (!cart || !cart.items.length) return res.status(400).json({ success: false, message: 'Your cart is empty' });
  await populateCart(cart);
  const items = cart.items.filter(item => item.product && item.product.isApproved && item.product.stock >= item.quantity);
  if (items.length !== cart.items.length) return res.status(409).json({ success: false, message: 'Some cart items are unavailable or do not have enough stock. Refresh your cart.' });

  const subtotal = items.reduce((sum, item) => sum + item.product.price * item.quantity, 0);
  const shippingCost = calculateShipping(items, address.state);
  const orderItems = items.map(item => ({
    product: item.product._id,
    seller: item.product.seller._id || item.product.seller,
    title: item.product.title,
    image: item.product.images?.[0] || '',
    price: item.product.price,
    quantity: item.quantity,
    status: 'pending'
  }));
  const order = await Order.create({
    buyer: req.user._id,
    items: orderItems,
    totalAmount: subtotal,
    shippingCost,
    finalAmount: subtotal + shippingCost,
    paymentMethod: requestedPaymentMethod,
    paymentStatus: 'pending',
    shippingAddress: {
      fullName: safeText(address.fullName, 100), phone: safeText(address.phone, 30), street: safeText(address.street, 200),
      city: safeText(address.city, 100), state: safeText(address.state, 100), country: safeText(address.country || 'Nigeria', 100)
    },
    statusHistory: [{ status: 'pending', note: requestedPaymentMethod === 'flutterwave' ? 'Order created – awaiting verified Flutterwave payment' : 'Order placed – payment on delivery', changedBy: req.user._id }]
  });
  await Promise.all(items.map(item => Product.updateOne({ _id: item.product._id, stock: { $gte: item.quantity } }, { $inc: { stock: -item.quantity } })));
  cart.items = [];
  await cart.save();
  await order.populate('buyer', 'name email phone');
  orderItems.forEach(item => createNotification(item.seller, 'New order received', `${address.fullName} placed an order containing your product.`, '/seller', 'order'));
  res.status(201).json({ success: true, message: requestedPaymentMethod === 'flutterwave' ? 'Order created. Continue to secure Flutterwave checkout.' : 'Order placed. Pay the seller only on confirmed delivery.', data: { order } });
}));

app.get('/api/orders', auth, asyncHandler(async (req, res) => {
  await releaseEligibleEarnings();
  const orders = await Order.find({ buyer: req.user._id }).populate('items.product', 'title images').sort('-createdAt').lean();
  res.json({ success: true, data: { orders, pagination: { currentPage: 1, totalPages: 1, totalOrders: orders.length } } });
}));

app.get('/api/orders/seller/stats', auth, allowRoles('seller', 'admin'), asyncHandler(async (req, res) => {
  const orders = await Order.find({ 'items.seller': req.user._id }).lean();
  let revenue = 0;
  let itemOrders = 0;
  for (const order of orders) {
    const mine = order.items.filter(item => item.seller.toString() === req.user._id.toString());
    if (mine.length) itemOrders += 1;
    if (order.status === 'delivered') revenue += mine.reduce((sum, item) => sum + item.price * item.quantity, 0);
  }
  res.json({ success: true, data: { stats: { totalOrders: itemOrders, totalRevenue: revenue, pendingOrders: orders.filter(order => !['delivered', 'cancelled'].includes(order.status)).length }, recentOrders: orders.slice(0, 10) } });
}));

app.get('/api/orders/seller/orders', auth, allowRoles('seller', 'admin'), asyncHandler(async (req, res) => {
  const orders = await Order.find({ 'items.seller': req.user._id }).populate('buyer', 'name email phone').sort('-createdAt').lean();
  const filtered = orders.map(order => {
    const items = order.items.filter(item => item.seller.toString() === req.user._id.toString());
    const stages = ['pending', 'confirmed', 'processing', 'shipped', 'delivered'];
    const sellerStatus = items.some(item => item.status === 'cancelled') ? 'cancelled' : stages[Math.min(...items.map(item => Math.max(0, stages.indexOf(item.status || 'pending'))))];
    return { ...order, status: sellerStatus, items, sellerAmount: items.reduce((sum, item) => sum + item.price * item.quantity, 0) };
  });
  res.json({ success: true, data: { orders: filtered } });
}));

app.put('/api/orders/:id/status', auth, allowRoles('seller', 'admin'), asyncHandler(async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order) return res.status(404).json({ success: false, message: 'Order not found' });
  if (order.paymentMethod === 'flutterwave' && order.paymentStatus !== 'paid') return res.status(400).json({ success: false, message: 'Seller cannot process an order until Flutterwave payment is verified' });
  const sellerOwnsItems = order.items.some(item => item.seller.toString() === req.user._id.toString());
  if (req.user.role !== 'admin' && !sellerOwnsItems) return res.status(403).json({ success: false, message: 'This is not your order' });
  const transitions = { pending: 'confirmed', confirmed: 'processing', processing: 'shipped', shipped: 'delivered' };
  const stages = ['pending', 'confirmed', 'processing', 'shipped', 'delivered'];
  const nextStatus = safeText(req.body.status, 30);
  if (!['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'].includes(nextStatus)) return res.status(400).json({ success: false, message: 'Invalid order status' });

  if (req.user.role === 'admin') {
    order.items.forEach(item => { item.status = nextStatus; });
  } else {
    const mine = order.items.filter(item => item.seller.toString() === req.user._id.toString());
    const currentIndex = Math.min(...mine.map(item => Math.max(0, stages.indexOf(item.status || 'pending'))));
    const currentStatus = stages[currentIndex];
    if (transitions[currentStatus] !== nextStatus) return res.status(400).json({ success: false, message: `Your items can only move from ${currentStatus} to ${transitions[currentStatus] || 'no further status'}` });
    mine.forEach(item => { item.status = nextStatus; });
  }

  const activeStatuses = order.items.filter(item => item.status !== 'cancelled').map(item => Math.max(0, stages.indexOf(item.status || 'pending')));
  order.status = activeStatuses.length ? stages[Math.min(...activeStatuses)] : 'cancelled';
  if (order.status === 'delivered' && !order.deliveredAt) order.deliveredAt = new Date();
  order.statusHistory.push({ status: nextStatus, note: safeText(req.body.note, 300) || `Seller items moved to ${nextStatus}`, changedBy: req.user._id });
  await order.save();
  createNotification(order.buyer, `Order ${order.status}`, `Order #${String(order._id).slice(-8).toUpperCase()} moved to ${order.status}.`, '/orders', 'order');
  if (order.status === 'delivered') releaseEligibleEarnings().catch(() => {});
  res.json({ success: true, data: { order, sellerStatus: nextStatus } });
}));

app.put('/api/orders/:id/confirm-delivery', auth, asyncHandler(async (req, res) => {
  const order = await Order.findOne({ _id: req.params.id, buyer: req.user._id });
  if (!order) return res.status(404).json({ success: false, message: 'Order not found' });
  if (order.status !== 'delivered') return res.status(400).json({ success: false, message: 'The order must be marked delivered first' });
  if (order.paymentStatus !== 'paid') return res.status(400).json({ success: false, message: 'Only verified online-payment earnings can be released through the wallet' });
  if (order.report?.status === 'pending') return res.status(409).json({ success: false, message: 'Earnings cannot be released while a dispute is pending' });
  order.buyerConfirmedDeliveryAt = new Date();
  await releaseOrderEarnings(order, 'Buyer confirmed delivery');
  res.json({ success: true, message: 'Delivery confirmed and seller earnings released', data: { order } });
}));

app.put('/api/orders/:id/cancel', auth, asyncHandler(async (req, res) => {
  const order = await Order.findOne({ _id: req.params.id, buyer: req.user._id });
  if (!order) return res.status(404).json({ success: false, message: 'Order not found' });
  if (order.paymentStatus === 'paid' || order.status !== 'pending') return res.status(400).json({ success: false, message: 'Only an unpaid pending order can be cancelled here' });
  if (!order.stockRestored) {
    await Promise.all(order.items.map(item => Product.updateOne({ _id: item.product }, { $inc: { stock: item.quantity } })));
    order.stockRestored = true;
  }
  order.status = 'cancelled';
  order.items.forEach(item => { item.status = 'cancelled'; });
  order.statusHistory.push({ status: 'cancelled', note: 'Buyer cancelled unpaid order', changedBy: req.user._id });
  await order.save();
  res.json({ success: true, message: 'Unpaid order cancelled and stock restored', data: { order } });
}));

app.post('/api/orders/:id/report', auth, asyncHandler(async (req, res) => {
  const order = await Order.findOne({ _id: req.params.id, buyer: req.user._id });
  if (!order) return res.status(404).json({ success: false, message: 'Order not found' });
  const reason = safeText(req.body.reason, 2000);
  if (reason.length < 10) return res.status(400).json({ success: false, message: 'Please explain the issue in at least 10 characters' });
  order.report = { reason, status: 'pending', createdAt: new Date() };
  await order.save();
  res.status(201).json({ success: true, message: 'Report submitted for admin review' });
}));

// Flutterwave hosted checkout. Live keys remain locked until compliance approval.
app.post('/api/payments/flutterwave/initialize', auth, asyncHandler(async (req, res) => {
  if (!hasFlutterwave) return res.status(503).json({ success: false, message: 'Flutterwave Test Mode is not configured yet' });
  const order = await Order.findOne({ _id: req.body.orderId, buyer: req.user._id });
  if (!order) return res.status(404).json({ success: false, message: 'Order not found' });
  if (order.paymentStatus === 'paid') return res.status(409).json({ success: false, message: 'This order is already paid' });
  const reference = `cm_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
  const frontendUrl = process.env.PUBLIC_FRONTEND_URL || allowedOrigins.find(origin => origin.startsWith('https://')) || 'http://localhost:5173';
  const payload = {
    tx_ref: reference,
    amount: String(order.finalAmount),
    currency: 'NGN',
    redirect_url: `${frontendUrl}/payment/callback`,
    payment_options: 'card,banktransfer,ussd,account',
    customer: { email: req.user.email, name: req.user.name, phonenumber: req.user.phone || '' },
    meta: { order_id: String(order._id), buyer_id: String(req.user._id) },
    customizations: { title: 'Campus Market', description: `Payment for order #${String(order._id).slice(-8).toUpperCase()}`, logo: `${frontendUrl}/logo.svg` },
    configurations: { session_duration: 20, max_retry_attempt: 3 }
  };
  const response = await flutterwaveRequest('/payments', { method: 'POST', body: JSON.stringify(payload) });
  if (!response.data?.link) return res.status(502).json({ success: false, message: 'Flutterwave did not return a checkout link' });
  order.paymentMethod = 'flutterwave';
  order.paymentStatus = 'initialized';
  order.paymentReference = reference;
  await order.save();
  await Payment.findOneAndUpdate({ order: order._id }, { $set: { buyer: req.user._id, provider: 'flutterwave', reference, amount: order.finalAmount, currency: 'NGN', status: 'initialized' } }, { upsert: true, new: true, runValidators: true });
  res.json({ success: true, data: { checkoutUrl: response.data.link, reference, mode: flutterwaveMode } });
}));

app.get('/api/payments/flutterwave/verify', auth, asyncHandler(async (req, res) => {
  const transactionId = safeText(req.query.transaction_id, 100);
  const reference = safeText(req.query.tx_ref, 120);
  if (!transactionId || !reference) return res.status(400).json({ success: false, message: 'Payment reference and transaction ID are required' });
  const order = await Order.findOne({ paymentReference: reference, buyer: req.user._id });
  if (!order) return res.status(404).json({ success: false, message: 'Payment order not found' });
  const response = await flutterwaveRequest(`/transactions/${encodeURIComponent(transactionId)}/verify`);
  const verifiedOrder = await finalizeVerifiedFlutterwavePayment(reference, response.data || {});
  res.json({ success: true, message: 'Payment verified', data: { order: verifiedOrder } });
}));

app.post('/api/payments/flutterwave/webhook', asyncHandler(async (req, res) => {
  const secretHash = process.env.FLW_SECRET_HASH;
  if (!secretHash) return res.status(503).json({ success: false, message: 'Webhook secret is not configured' });
  const signature = req.headers['flutterwave-signature'] || req.headers['verif-hash'];
  const raw = req.rawBody || Buffer.from(JSON.stringify(req.body));
  const expectedHex = crypto.createHmac('sha256', secretHash).update(raw).digest('hex');
  const expectedBase64 = crypto.createHmac('sha256', secretHash).update(raw).digest('base64');
  if (!signature || ![secretHash, expectedHex, expectedBase64].includes(String(signature))) return res.status(401).end();
  const event = req.body;
  const data = event.data || {};
  const reference = String(data.tx_ref || data.reference || '');
  const transactionId = data.id;
  res.status(200).json({ received: true });
  if ((event.event === 'charge.completed' || event.type === 'charge.completed') && transactionId && reference) {
    flutterwaveRequest(`/transactions/${encodeURIComponent(transactionId)}/verify`)
      .then(response => finalizeVerifiedFlutterwavePayment(reference, response.data || {}))
      .catch(error => console.error('Flutterwave webhook verification failed:', error.message));
  }
}));

// Legacy routes stay disabled so no old simulated payment can succeed.
app.get('/api/payments/verify/:reference', auth, (req, res) => res.status(410).json({ success: false, message: 'Use Flutterwave checkout for new payments', data: { verified: false } }));
app.post('/api/payments/confirm', auth, (req, res) => res.status(410).json({ success: false, message: 'Legacy payment confirmation is disabled' }));

// -----------------------------------------------------------------------------
// Chats and support
// -----------------------------------------------------------------------------
app.get('/api/chat/chats', auth, asyncHandler(async (req, res) => {
  const query = (req.user.role === 'admin' || req.user.role === 'moderator') ? {} : { participants: req.user._id };
  const chats = await Chat.find(query).populate('participants', 'name role sellerProfile.storeName').populate('product', 'title images chatEnabled').sort('-updatedAt').lean();
  res.json({ success: true, data: { chats } });
}));

app.post('/api/chat/send', auth, asyncHandler(async (req, res) => {
  const recipientId = req.body.recipientId;
  const message = safeText(req.body.message, 2000);
  if (!mongoose.isValidObjectId(recipientId) || message.length < 1) return res.status(400).json({ success: false, message: 'Recipient and message are required' });
  const recipient = await User.findById(recipientId);
  if (!recipient) return res.status(404).json({ success: false, message: 'Recipient not found' });
  let product;
  if (req.body.productId && mongoose.isValidObjectId(req.body.productId)) {
    product = await Product.findById(req.body.productId);
    if (product) {
      const sellerId = product.seller.toString();
      const senderOrRecipientIsSeller = sellerId === String(recipientId) || sellerId === req.user._id.toString();
      if (!product.chatEnabled || !senderOrRecipientIsSeller) return res.status(403).json({ success: false, message: 'Chat is unavailable for this product' });
    }
  }
  let chat = await Chat.findOne({ participants: { $all: [req.user._id, recipient._id], $size: 2 }, product: product?._id || null, type: req.body.type === 'support' ? 'support' : 'buyer_to_seller' });
  if (!chat) chat = new Chat({ participants: [req.user._id, recipient._id], product: product?._id, type: req.body.type === 'support' ? 'support' : 'buyer_to_seller', messages: [] });
  chat.messages.push({ sender: req.user._id, message, readBy: [req.user._id] });
  await chat.save();
  createNotification(recipient._id, `New message from ${req.user.name}`, product ? `Re: ${product.title}` : message.slice(0, 100), '/messages', 'message');
  res.status(201).json({ success: true, data: { chatId: chat._id } });
}));

app.post('/api/support/tickets', auth, asyncHandler(async (req, res) => {
  const message = safeText(req.body.message, 4000);
  if (message.length < 2) return res.status(400).json({ success: false, message: 'Support message is required' });
  const ticket = await SupportTicket.create({
    user: req.user._id,
    subject: safeText(req.body.subject || 'Support request', 200),
    message,
    priority: ['low', 'normal', 'high', 'urgent'].includes(req.body.priority) ? req.body.priority : 'normal'
  });
  res.status(201).json({ success: true, message: 'Support request sent only to admins and moderators', data: { ticket } });
}));

app.get('/api/support/tickets/my', auth, asyncHandler(async (req, res) => {
  const tickets = await SupportTicket.find({ user: req.user._id }).populate('replies.from', 'name role').sort('-updatedAt').limit(30).lean();
  res.json({ success: true, data: { tickets } });
}));

app.post('/api/support/tickets/:id/reply', auth, asyncHandler(async (req, res) => {
  const message = safeText(req.body.message, 2000);
  if (!message) return res.status(400).json({ success: false, message: 'Message is required' });
  const ticket = await SupportTicket.findOne({ _id: req.params.id, user: req.user._id });
  if (!ticket) return res.status(404).json({ success: false, message: 'Support ticket not found' });
  if (ticket.status === 'closed') return res.status(400).json({ success: false, message: 'This support conversation is closed' });
  ticket.replies.push({ from: req.user._id, message });
  if (ticket.status === 'resolved') ticket.status = 'open';
  await ticket.save();
  res.status(201).json({ success: true, data: { ticket } });
}));

// -----------------------------------------------------------------------------
// Seller wallet and manual withdrawal requests
// -----------------------------------------------------------------------------
app.get('/api/seller/wallet', auth, allowRoles('seller', 'admin'), asyncHandler(async (req, res) => {
  await releaseEligibleEarnings();
  const freshUser = await User.findById(req.user._id);
  const transactions = await WalletTransaction.find({ seller: req.user._id }).sort('-createdAt').limit(100).lean();
  const withdrawals = await Withdrawal.find({ seller: req.user._id }).sort('-createdAt').limit(50).lean();
  res.json({ success: true, data: { availableBalance: freshUser?.walletBalance || 0, pendingBalance: freshUser?.pendingBalance || 0, totalWithdrawn: freshUser?.totalWithdrawn || 0, bankAccount: freshUser?.sellerProfile?.bankAccount || null, minimumWithdrawal: MIN_WITHDRAWAL, transactions, withdrawals } });
}));

app.put('/api/seller/bank-account', auth, allowRoles('seller'), asyncHandler(async (req, res) => {
  const accountNumber = safeText(req.body.accountNumber, 20).replace(/\D/g, '');
  const bankName = safeText(req.body.bankName, 120);
  const bankCode = safeText(req.body.bankCode, 30);
  const accountName = safeText(req.body.accountName, 160);
  if (accountNumber.length !== 10 || !bankName || !accountName) return res.status(400).json({ success: false, message: 'Enter a valid Nigerian bank account, bank name and account name' });
  await User.updateOne({ _id: req.user._id }, { $set: { 'sellerProfile.bankAccount': { bankName, bankCode, accountNumber, accountName, isVerified: false } } });
  res.json({ success: true, message: 'Bank account saved and awaiting admin verification' });
}));

app.post('/api/seller/withdraw', auth, allowRoles('seller'), asyncHandler(async (req, res) => {
  const amount = normalizeMoney(req.body.amount);
  if (amount < MIN_WITHDRAWAL) return res.status(400).json({ success: false, message: `Minimum withdrawal is ₦${MIN_WITHDRAWAL.toLocaleString()}` });
  if (!req.user.sellerProfile?.bankAccount?.isVerified) return res.status(400).json({ success: false, message: 'Add and verify a bank account before withdrawing' });
  const updated = await User.findOneAndUpdate({ _id: req.user._id, walletBalance: { $gte: amount } }, { $inc: { walletBalance: -amount } }, { new: true });
  if (!updated) return res.status(400).json({ success: false, message: 'Insufficient available balance' });
  const reference = `wdr_${crypto.randomUUID().replace(/-/g, '').slice(0, 24)}`;
  const bank = req.user.sellerProfile.bankAccount;
  const withdrawal = await Withdrawal.create({ seller: req.user._id, amount, bankAccount: { bankName: bank.bankName, bankCode: bank.bankCode, accountNumber: bank.accountNumber, accountName: bank.accountName }, notes: safeText(req.body.notes, 500), reference });
  await WalletTransaction.create({ seller: req.user._id, withdrawal: withdrawal._id, type: 'withdrawal_reserved', amount: -amount, reference, balanceAfter: updated.walletBalance });
  res.status(201).json({ success: true, message: 'Withdrawal request submitted for admin review', data: { withdrawal } });
}));

// -----------------------------------------------------------------------------
// Admin and moderator operations
// -----------------------------------------------------------------------------
app.get('/api/admin/dashboard', auth, allowRoles('admin', 'moderator'), asyncHandler(async (req, res) => {
  const [totalUsers, totalSellers, totalProducts, totalOrders, pendingProducts, pendingSellers, openReports, openTickets, pendingWithdrawals] = await Promise.all([
    User.countDocuments(), User.countDocuments({ role: 'seller' }), Product.countDocuments(), Order.countDocuments(),
    Product.countDocuments({ isApproved: false, isRejected: { $ne: true } }), User.countDocuments({ role: 'seller', 'sellerProfile.isApproved': false }),
    Order.countDocuments({ 'report.status': 'pending' }), SupportTicket.countDocuments({ status: { $in: ['open', 'in_progress'] } }),
    Withdrawal.countDocuments({ status: 'requested' })
  ]);
  const [paidRevenue, commissions, sellerLiabilities] = await Promise.all([
    Order.aggregate([{ $match: { paymentStatus: 'paid' } }, { $group: { _id: null, total: { $sum: '$finalAmount' } } }]),
    Order.aggregate([{ $match: { paymentStatus: 'paid' } }, { $group: { _id: null, total: { $sum: '$platformCommission' }, gatewayFees: { $sum: '$gatewayFee' } } }]),
    User.aggregate([{ $match: { role: 'seller' } }, { $group: { _id: null, pending: { $sum: '$pendingBalance' }, available: { $sum: '$walletBalance' } } }])
  ]);
  res.json({ success: true, data: { stats: { totalUsers, totalSellers, totalProducts, totalOrders, totalRevenue: paidRevenue[0]?.total || 0, platformCommission: commissions[0]?.total || 0, gatewayFees: commissions[0]?.gatewayFees || 0, sellerPendingLiability: sellerLiabilities[0]?.pending || 0, sellerAvailableLiability: sellerLiabilities[0]?.available || 0, pendingApprovals: pendingProducts + pendingSellers + openReports + openTickets + pendingWithdrawals } } });
}));

app.get('/api/admin/moderators', auth, allowRoles('admin'), asyncHandler(async (req, res) => {
  const moderators = await User.find({ role: 'moderator' }).select('name email phone isBanned createdAt').sort('-createdAt').lean();
  res.json({ success: true, data: { moderators } });
}));

app.post('/api/admin/moderators', auth, allowRoles('admin'), asyncHandler(async (req, res) => {
  const name = safeText(req.body.name, 100);
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || '');
  if (name.length < 2 || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ success: false, message: 'Valid moderator name and email are required' });
  if (password.length < 10) return res.status(400).json({ success: false, message: 'Temporary password must have at least 10 characters' });
  if (await User.exists({ email })) return res.status(409).json({ success: false, message: 'An account already uses this email' });
  const moderator = await User.create({ name, email, password, role: 'moderator', isVerified: true });
  res.status(201).json({ success: true, message: 'Moderator account created. Ask them to change the temporary password after signing in.', data: { moderator: publicUser(moderator) } });
}));

app.delete('/api/admin/moderators/:id', auth, allowRoles('admin'), asyncHandler(async (req, res) => {
  const moderator = await User.findOneAndUpdate({ _id: req.params.id, role: 'moderator' }, { $set: { role: 'buyer' } }, { new: true });
  if (!moderator) return res.status(404).json({ success: false, message: 'Moderator not found' });
  res.json({ success: true, message: 'Moderator access removed' });
}));

app.get('/api/admin/pending-products', auth, allowRoles('admin', 'moderator'), asyncHandler(async (req, res) => {
  const products = await Product.find({ isApproved: false, isRejected: { $ne: true } }).populate('seller', 'name email sellerProfile.storeName').sort('createdAt').lean();
  res.json({ success: true, data: { products } });
}));

app.put('/api/admin/products/:id/approve', auth, allowRoles('admin', 'moderator'), asyncHandler(async (req, res) => {
  const existing = await Product.findById(req.params.id);
  if (!existing) return res.status(404).json({ success: false, message: 'Product not found' });
  const errors = listingQualityErrors(existing);
  if (errors.length) return res.status(400).json({ success: false, message: `Cannot approve: ${errors.join('. ')}` });
  const product = await Product.findByIdAndUpdate(req.params.id, { $set: { isApproved: true, isRejected: false, approvalNote: '' } }, { new: true });
  createNotification(product.seller, 'Product approved', `${product.title} is now visible to buyers.`, `/products/${product._id}`, 'approval');
  const followers = await Follow.find({ seller: product.seller }).select('follower').lean();
  followers.forEach(item => createNotification(item.follower, 'New product from a store you follow', product.title, `/products/${product._id}`, 'store_product'));
  res.json({ success: true, data: { product } });
}));

app.put('/api/admin/products/:id/reject', auth, allowRoles('admin', 'moderator'), asyncHandler(async (req, res) => {
  const product = await Product.findByIdAndUpdate(req.params.id, { $set: { isApproved: false, isRejected: true, approvalNote: safeText(req.body.reason || 'Listing rejected. Edit it and submit again.', 500) } }, { new: true });
  if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
  res.json({ success: true, data: { product } });
}));

app.get('/api/admin/pending-sellers', auth, allowRoles('admin', 'moderator'), asyncHandler(async (req, res) => {
  const sellers = await User.find({ role: 'seller', 'sellerProfile.isApproved': { $ne: true } }).select('name email phone createdAt sellerProfile.storeName sellerProfile.description sellerProfile.isApproved').sort('createdAt').lean();
  res.json({ success: true, data: { sellers } });
}));

app.put('/api/admin/sellers/:id/approve', auth, allowRoles('admin'), asyncHandler(async (req, res) => {
  const seller = await User.findOneAndUpdate({ _id: req.params.id, role: 'seller' }, { $set: { 'sellerProfile.isApproved': true, 'sellerProfile.identityVerified': true } }, { new: true });
  if (!seller) return res.status(404).json({ success: false, message: 'Seller not found' });
  createNotification(seller._id, 'Seller account approved', 'You can now add products and operate your Campus Market store.', '/seller', 'approval');
  res.json({ success: true, data: { seller: publicUser(seller) } });
}));

app.get('/api/admin/pending-bank-accounts', auth, allowRoles('admin'), asyncHandler(async (req, res) => {
  const sellers = await User.find({ role: 'seller', 'sellerProfile.bankAccount.accountNumber': { $exists: true }, 'sellerProfile.bankAccount.isVerified': { $ne: true } }).select('name email phone sellerProfile.storeName sellerProfile.bankAccount createdAt').sort('updatedAt').lean();
  res.json({ success: true, data: { sellers } });
}));

app.put('/api/admin/sellers/:id/verify-bank', auth, allowRoles('admin'), asyncHandler(async (req, res) => {
  const seller = await User.findOne({ _id: req.params.id, role: 'seller' });
  if (!seller?.sellerProfile?.bankAccount?.accountNumber) return res.status(404).json({ success: false, message: 'Seller bank account not found' });
  seller.sellerProfile.bankAccount.isVerified = true;
  await seller.save();
  createNotification(seller._id, 'Bank account verified', 'Your payout bank account was approved for manual withdrawals.', '/seller', 'bank');
  res.json({ success: true, message: 'Bank account verified' });
}));

app.get('/api/admin/product-reports', auth, allowRoles('admin', 'moderator'), asyncHandler(async (req, res) => {
  const reports = await ProductReport.find().populate('product', 'title images price isApproved').populate('reporter', 'name email').populate('seller', 'name sellerProfile.storeName').sort('-createdAt').lean();
  res.json({ success: true, data: { reports } });
}));

app.put('/api/admin/product-reports/:id', auth, allowRoles('admin', 'moderator'), asyncHandler(async (req, res) => {
  const status = ['reviewed', 'dismissed', 'actioned'].includes(req.body.status) ? req.body.status : 'reviewed';
  const report = await ProductReport.findByIdAndUpdate(req.params.id, { $set: { status, adminNote: safeText(req.body.note, 500) } }, { new: true });
  if (!report) return res.status(404).json({ success: false, message: 'Listing report not found' });
  if (status === 'actioned' && req.body.hideProduct === true) await Product.updateOne({ _id: report.product }, { $set: { isApproved: false, isRejected: true, approvalNote: 'Hidden after a marketplace safety report' } });
  res.json({ success: true, data: { report } });
}));

app.get('/api/admin/reports', auth, allowRoles('admin', 'moderator'), asyncHandler(async (req, res) => {
  const orders = await Order.find({ 'report.status': { $exists: true } }).populate('buyer', 'name email phone').sort('-report.createdAt').lean();
  const reports = orders.map(order => ({ _id: order._id, orderId: order._id.toString(), buyer: order.buyer, amount: order.finalAmount, ...order.report }));
  res.json({ success: true, data: { reports } });
}));

app.put('/api/admin/orders/:id/:action', auth, allowRoles('admin'), asyncHandler(async (req, res) => {
  if (!['approve-refund', 'reject-refund'].includes(req.params.action)) return res.status(400).json({ success: false, message: 'Invalid action' });
  const order = await Order.findById(req.params.id);
  if (!order?.report?.status) return res.status(404).json({ success: false, message: 'Report not found' });
  if (req.params.action === 'approve-refund') {
    const amountRefunded = normalizeMoney(req.body.amountRefunded);
    const refundReference = safeText(req.body.refundReference, 120);
    if (order.paymentStatus === 'paid' && (amountRefunded !== order.finalAmount || refundReference.length < 5)) return res.status(400).json({ success: false, message: `Process the refund first, then enter the exact amount ₦${order.finalAmount.toLocaleString()} and its Flutterwave/bank refund reference` });
    for (const allocation of order.sellerAllocations || []) {
      if (allocation.status === 'refunded') continue;
      const ledgerRef = `refund_${order._id}_${allocation.seller}`;
      if (!(await WalletTransaction.exists({ reference: ledgerRef }))) {
        const seller = await User.findById(allocation.seller);
        if (seller) {
          if (allocation.status === 'pending') {
            const debit = Math.min(seller.pendingBalance || 0, allocation.netAmount);
            seller.pendingBalance = Math.max(0, (seller.pendingBalance || 0) - debit);
            seller.sellerDebt = (seller.sellerDebt || 0) + Math.max(0, allocation.netAmount - debit);
          } else {
            const debit = Math.min(seller.walletBalance || 0, allocation.netAmount);
            seller.walletBalance = Math.max(0, (seller.walletBalance || 0) - debit);
            seller.sellerDebt = (seller.sellerDebt || 0) + Math.max(0, allocation.netAmount - debit);
          }
          await seller.save();
          await WalletTransaction.create({ seller: allocation.seller, order: order._id, type: 'refund', amount: -allocation.netAmount, reference: ledgerRef, balanceAfter: seller.walletBalance || 0 });
          createNotification(allocation.seller, 'Order refunded', `A refund affected ₦${allocation.netAmount.toLocaleString()} of your earnings. Check your wallet ledger.`, '/seller', 'refund');
        }
      }
      allocation.status = 'refunded';
    }
    order.report.status = 'approved';
    order.report.amountRefunded = amountRefunded;
    order.report.refundReference = refundReference;
    if (order.paymentStatus === 'paid') order.paymentStatus = 'refunded';
  } else order.report.status = 'rejected';
  order.report.resolvedAt = new Date();
  order.report.adminNote = safeText(req.body.note, 500);
  await order.save();
  res.json({ success: true, data: { order } });
}));

app.get('/api/admin/support-tickets', auth, allowRoles('admin', 'moderator'), asyncHandler(async (req, res) => {
  const tickets = await SupportTicket.find().populate('user', 'name email role').populate('replies.from', 'name role').sort('-updatedAt').lean();
  res.json({ success: true, data: { tickets } });
}));

app.post('/api/admin/support-tickets/:id/reply', auth, allowRoles('admin', 'moderator'), asyncHandler(async (req, res) => {
  const message = safeText(req.body.message, 2000);
  if (!message) return res.status(400).json({ success: false, message: 'Reply is required' });
  const ticket = await SupportTicket.findById(req.params.id);
  if (!ticket) return res.status(404).json({ success: false, message: 'Support ticket not found' });
  ticket.replies.push({ from: req.user._id, message });
  ticket.status = req.body.resolve === true ? 'resolved' : 'in_progress';
  await ticket.save();
  await ticket.populate([{ path: 'user', select: 'name email role' }, { path: 'replies.from', select: 'name role' }]);
  res.status(201).json({ success: true, data: { ticket } });
}));

app.put('/api/admin/support-tickets/:id/status', auth, allowRoles('admin', 'moderator'), asyncHandler(async (req, res) => {
  const status = safeText(req.body.status, 30);
  if (!['open', 'in_progress', 'resolved', 'closed'].includes(status)) return res.status(400).json({ success: false, message: 'Invalid ticket status' });
  const ticket = await SupportTicket.findByIdAndUpdate(req.params.id, { $set: { status } }, { new: true });
  if (!ticket) return res.status(404).json({ success: false, message: 'Support ticket not found' });
  res.json({ success: true, data: { ticket } });
}));

app.get('/api/admin/withdrawals', auth, allowRoles('admin'), asyncHandler(async (req, res) => {
  const withdrawals = await Withdrawal.find().populate('seller', 'name email phone sellerProfile.storeName').sort('-createdAt').lean();
  res.json({ success: true, data: { withdrawals } });
}));

app.put('/api/admin/withdrawals/:id', auth, allowRoles('admin'), asyncHandler(async (req, res) => {
  const withdrawal = await Withdrawal.findById(req.params.id);
  if (!withdrawal) return res.status(404).json({ success: false, message: 'Withdrawal not found' });
  const action = safeText(req.body.action, 30);
  if (withdrawal.status === 'paid') return res.status(409).json({ success: false, message: 'Withdrawal is already paid' });
  if (action === 'approve') withdrawal.status = 'approved';
  else if (action === 'processing') withdrawal.status = 'processing';
  else if (action === 'paid') {
    const amountTransferred = normalizeMoney(req.body.amountTransferred);
    const transferReference = safeText(req.body.transferReference, 120);
    if (amountTransferred !== withdrawal.amount) return res.status(400).json({ success: false, message: `Amount transferred must equal ₦${withdrawal.amount.toLocaleString()}` });
    if (transferReference.length < 5) return res.status(400).json({ success: false, message: 'Enter the bank transfer reference or session ID' });
    if (await Withdrawal.exists({ _id: { $ne: withdrawal._id }, transferReference })) return res.status(409).json({ success: false, message: 'That transfer reference was already used' });
    withdrawal.status = 'paid';
    withdrawal.amountTransferred = amountTransferred;
    withdrawal.transferReference = transferReference;
    withdrawal.transferDate = req.body.transferDate ? new Date(req.body.transferDate) : new Date();
    withdrawal.proofUrl = safeText(req.body.proofUrl, 500);
    withdrawal.adminNote = safeText(req.body.note, 500);
    withdrawal.paidAt = new Date();
    await User.updateOne({ _id: withdrawal.seller }, { $inc: { totalWithdrawn: withdrawal.amount } });
    await WalletTransaction.updateOne({ reference: `withdrawal_paid_${withdrawal.reference}` }, { $setOnInsert: { seller: withdrawal.seller, withdrawal: withdrawal._id, type: 'withdrawal_paid', amount: withdrawal.amount, reference: `withdrawal_paid_${withdrawal.reference}`, status: 'completed' } }, { upsert: true });
    createNotification(withdrawal.seller, 'Withdrawal paid', `₦${withdrawal.amount.toLocaleString()} was marked paid. Reference: ${transferReference}`, '/seller', 'withdrawal');
  } else if (['reject', 'failed'].includes(action)) {
    withdrawal.status = action === 'reject' ? 'rejected' : 'failed';
    withdrawal.adminNote = safeText(req.body.note, 500);
    if (!withdrawal.balanceRestored) {
      const seller = await User.findByIdAndUpdate(withdrawal.seller, { $inc: { walletBalance: withdrawal.amount } }, { new: true });
      withdrawal.balanceRestored = true;
      await WalletTransaction.updateOne({ reference: `withdrawal_reversed_${withdrawal.reference}` }, { $setOnInsert: { seller: withdrawal.seller, withdrawal: withdrawal._id, type: 'withdrawal_reversed', amount: withdrawal.amount, reference: `withdrawal_reversed_${withdrawal.reference}`, balanceAfter: seller?.walletBalance || 0 } }, { upsert: true });
    }
    createNotification(withdrawal.seller, 'Withdrawal not completed', `Your withdrawal was ${withdrawal.status}. The reserved amount was returned to available balance.`, '/seller', 'withdrawal');
  } else return res.status(400).json({ success: false, message: 'Invalid withdrawal action' });
  withdrawal.reviewedBy = req.user._id;
  withdrawal.reviewedAt = new Date();
  await withdrawal.save();
  res.json({ success: true, data: { withdrawal } });
}));

// -----------------------------------------------------------------------------
// 404 and error handling
// -----------------------------------------------------------------------------
app.use('/api', (req, res) => res.status(404).json({ success: false, message: `API route not found: ${req.method} ${req.originalUrl}` }));

app.use((error, req, res, next) => {
  console.error(error);
  if (error instanceof multer.MulterError) {
    const message = error.code === 'LIMIT_FILE_SIZE' ? 'Each image must be 5MB or smaller' : error.code === 'LIMIT_FILE_COUNT' ? 'You can upload a maximum of 6 images' : error.message;
    return res.status(400).json({ success: false, message });
  }
  if (error?.name === 'ValidationError') return res.status(400).json({ success: false, message: Object.values(error.errors).map(item => item.message).join(', ') });
  if (error?.code === 11000) return res.status(409).json({ success: false, message: 'That record already exists' });
  res.status(error.statusCode || 500).json({ success: false, message: error.statusCode ? error.message : 'An unexpected server error occurred' });
});

connectDB()
  .then(() => app.listen(PORT, () => console.log(`🚀 Campus Market API v7.1 running on port ${PORT}`)))
  .catch(error => {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  });
