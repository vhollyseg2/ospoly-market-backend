import { useState, useEffect, createContext, useContext } from 'react'
import { Routes, Route, Link, useNavigate, Navigate } from 'react-router-dom'

// ============ CONTEXT ============
const AuthContext = createContext()
const CartContext = createContext()

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  
  useEffect(() => { checkAuth() }, [])
  
  const checkAuth = async () => {
    try {
      const token = localStorage.getItem('accessToken')
      if (!token) { setLoading(false); return }
      const res = await fetch('/api/auth/me', { headers: { Authorization: `Bearer ${token}` } })
      const data = await res.json()
      if (data.success) setUser(data.data.user)
      else localStorage.removeItem('accessToken')
    } catch {}
    setLoading(false)
  }
  
  const login = async (email, password) => {
    const res = await fetch('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) })
    const data = await res.json()
    if (data.success) { localStorage.setItem('accessToken', data.data.accessToken); setUser(data.data.user); return { success: true } }
    return { success: false, message: data.message }
  }
  
  const register = async (userData) => {
    const res = await fetch('/api/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(userData) })
    const data = await res.json()
    if (data.success) { localStorage.setItem('accessToken', data.data.accessToken); setUser(data.data.user); return { success: true } }
    return { success: false, message: data.message }
  }
  
  const logout = () => { localStorage.removeItem('accessToken'); setUser(null) }
  
  return <AuthContext.Provider value={{ user, loading, login, register, logout }}>{children}</AuthContext.Provider>
}

const CartProvider = ({ children }) => {
  const [items, setItems] = useState([])
  const [summary, setSummary] = useState({ itemCount: 0, subtotal: 0, shipping: 500, total: 500 })
  
  const fetchCart = async () => {
    const token = localStorage.getItem('accessToken')
    if (!token) return
    try {
      const res = await fetch('/api/cart', { headers: { Authorization: `Bearer ${token}` } })
      const data = await res.json()
      if (data.success) { setItems(data.data.cart.items || []); setSummary(data.data.summary) }
    } catch {}
  }
  
  const addToCart = async (productId) => {
    const token = localStorage.getItem('accessToken')
    if (!token) return { success: false }
    try {
      const res = await fetch('/api/cart/add', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ productId }) })
      const data = await res.json()
      if (data.success) { setItems(data.data.cart.items); setSummary(data.data.summary); return { success: true } }
      return { success: false, message: data.message }
    } catch { return { success: false } }
  }
  
  const removeFromCart = async (productId) => {
    const token = localStorage.getItem('accessToken')
    const res = await fetch(`/api/cart/remove/${productId}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } })
    const data = await res.json()
    if (data.success) { setItems(data.data.cart.items); setSummary(data.data.summary) }
  }
  
  const updateQuantity = async (productId, quantity) => {
    const token = localStorage.getItem('accessToken')
    const res = await fetch('/api/cart/update', { method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ productId, quantity }) })
    const data = await res.json()
    if (data.success) { setItems(data.data.cart.items); setSummary(data.data.summary) }
  }
  
  useEffect(() => { fetchCart() }, [])
  
  return <CartContext.Provider value={{ items, summary, addToCart, removeFromCart, updateQuantity, fetchCart }}>{children}</CartContext.Provider>
}

const useAuth = () => useContext(AuthContext)
const useCart = () => useContext(CartContext)

// ============ HEADER ============
const Header = () => {
  const { user, logout, isAuthenticated } = useAuth()
  const { summary } = useCart()
  const navigate = useNavigate()
  const [menuOpen, setMenuOpen] = useState(false)
  
  return (
    <header className="sticky top-0 z-50 bg-white shadow-sm">
      <div className="bg-gradient-to-r from-orange-500 to-orange-600 text-white text-center py-2 text-sm font-medium">
        🎓 Welcome to Ospoly Market! Free delivery on orders above ₦50,000
      </div>
      <div className="max-w-7xl mx-auto px-4 py-3">
        <div className="flex items-center justify-between gap-4">
          <Link to="/" className="flex items-center gap-2">
            <div className="w-10 h-10 bg-gradient-to-br from-orange-500 to-orange-600 rounded-xl flex items-center justify-center">
              <span className="text-white font-bold text-lg">OM</span>
            </div>
            <div className="hidden sm:block">
              <span className="font-bold text-xl text-gray-900">Ospoly</span>
              <span className="font-bold text-xl text-orange-500">Market</span>
            </div>
          </Link>
          <div className="flex-1 max-w-xl">
            <div className="relative">
              <input type="text" placeholder="Search products..." className="w-full pl-4 pr-12 py-2.5 rounded-full border border-gray-300 focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20" onKeyDown={(e) => e.key === 'Enter' && navigate(`/products?search=${e.target.value}`)} />
              <button className="absolute right-1 top-1/2 -translate-y-1/2 p-2 rounded-full bg-orange-500 text-white hover:bg-orange-600">🔍</button>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Link to="/cart" className="relative p-2 hover:bg-gray-100 rounded-full">
              🛒 {summary.itemCount > 0 && <span className="absolute -top-1 -right-1 w-5 h-5 bg-orange-500 text-white text-xs font-bold rounded-full flex items-center justify-center">{summary.itemCount}</span>}
            </Link>
            {isAuthenticated ? (
              <div className="relative group">
                <button className="w-9 h-9 bg-orange-500 rounded-full flex items-center justify-center text-white font-bold">{user?.name?.charAt(0)}</button>
                <div className="absolute right-0 top-full mt-2 w-48 bg-white rounded-xl shadow-lg border border-gray-100 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-50">
                  <div className="p-3 border-b border-gray-100">
                    <p className="font-medium">{user?.name}</p>
                    <p className="text-xs text-gray-500 capitalize">{user?.role}</p>
                  </div>
                  {(user?.role === 'seller' || user?.role === 'admin') && <Link to="/seller" className="block px-4 py-2 hover:bg-gray-50">📊 Seller Dashboard</Link>}
                  {user?.role === 'admin' && <Link to="/admin" className="block px-4 py-2 hover:bg-gray-50 text-orange-600">⚙️ Admin Panel</Link>}
                  <button onClick={logout} className="w-full text-left px-4 py-2 hover:bg-red-50 text-red-500">🚪 Logout</button>
                </div>
              </div>
            ) : (
              <Link to="/login" className="hidden sm:block px-4 py-2 rounded-full border-2 border-orange-500 text-orange-500 hover:bg-orange-500 hover:text-white font-medium">Login</Link>
            )}
          </div>
        </div>
        <div className="flex gap-4 mt-3 overflow-x-auto scrollbar-hide text-sm">
          <Link to="/products" className="text-gray-600 hover:text-orange-500 whitespace-nowrap">All Products</Link>
          <Link to="/products?category=phones-accessories" className="text-gray-600 hover:text-orange-500 whitespace-nowrap">📱 Phones</Link>
          <Link to="/products?category=electronics" className="text-gray-600 hover:text-orange-500 whitespace-nowrap">💻 Electronics</Link>
          <Link to="/products?category=furniture" className="text-gray-600 hover:text-orange-500 whitespace-nowrap">🪑 Furniture</Link>
          <Link to="/products?category=fashion" className="text-gray-600 hover:text-orange-500 whitespace-nowrap">👕 Fashion</Link>
          <Link to="/rentals" className="text-gray-600 hover:text-orange-500 whitespace-nowrap">🏠 Rentals</Link>
          <Link to="/food" className="text-gray-600 hover:text-orange-500 whitespace-nowrap">🍔 Food</Link>
        </div>
      </div>
    </header>
  )
}

// ============ HOME PAGE ============
const HomePage = () => {
  const [products, setProducts] = useState([])
  const [featured, setFeatured] = useState([])
  const [flashDeals, setFlashDeals] = useState([])
  const navigate = useNavigate()
  
  useEffect(() => {
    fetch('/api/products/featured').then(r => r.json()).then(d => d.success && setFeatured(d.data.products))
    fetch('/api/products/flash-deals').then(r => r.json()).then(d => d.success && setFlashDeals(d.data.products))
    fetch('/api/products?limit=10').then(r => r.json()).then(d => d.success && setProducts(d.data.products))
  }, [])
  
  const ProductCard = ({ p }) => (
    <div className="card group cursor-pointer" onClick={() => navigate(`/products/${p._id}`)}>
      <div className="aspect-square bg-gray-100 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-gray-200 to-gray-300 flex items-center justify-center text-4xl">📦</div>
        {p.isFlashDeal && <span className="absolute top-2 left-2 badge bg-red-500 text-white">🔥 Flash</span>}
        {p.discount > 0 && <span className="absolute top-2 right-2 badge bg-red-500 text-white">-{p.discount}%</span>}
        <span className={`absolute bottom-2 left-2 badge ${p.condition === 'new' ? 'badge-new' : 'badge-used'}`}>{p.condition}</span>
      </div>
      <div className="p-3">
        <h3 className="font-medium text-gray-900 line-clamp-2 mb-1">{p.title}</h3>
        <p className="text-xs text-gray-500 mb-2">{p.seller?.sellerProfile?.storeName || p.seller?.name}</p>
        <div className="flex items-center gap-2">
          <span className="text-lg font-bold text-gray-900">₦{p.price?.toLocaleString()}</span>
          {p.originalPrice && p.originalPrice > p.price && <span className="text-sm text-gray-400 line-through">₦{p.originalPrice?.toLocaleString()}</span>}
        </div>
      </div>
    </div>
  )
  
  return (
    <div>
      <section className="bg-gradient-to-r from-orange-600 via-orange-500 to-orange-400 py-16">
        <div className="max-w-7xl mx-auto px-4">
          <div className="grid md:grid-cols-2 gap-8 items-center">
            <div className="text-white space-y-4">
              <div className="inline-block px-3 py-1 bg-white/20 rounded-full text-sm">🎉 Welcome to Campus Marketplace</div>
              <h1 className="text-4xl md:text-5xl font-bold">Shop Smart,<br /><span className="text-yellow-300">Sell Faster</span></h1>
              <p className="text-lg text-white/90">Buy and sell new/used items, find apartments, order food - all in one place for students.</p>
              <div className="flex gap-3">
                <Link to="/products" className="btn bg-white text-orange-600 hover:bg-gray-100 font-semibold px-6 py-3">Start Shopping</Link>
                <Link to="/register" className="btn border-2 border-white text-white hover:bg-white hover:text-orange-600 font-semibold px-6 py-3">Become a Seller</Link>
              </div>
            </div>
          </div>
        </div>
      </section>
      
      <section className="max-w-7xl mx-auto px-4 py-8">
        <h2 className="text-xl font-bold mb-6">🛍️ Shop by Category</h2>
        <div className="grid grid-cols-3 md:grid-cols-6 gap-4">
          {[['📱','Phones'],['💻','Electronics'],['🪑','Furniture'],['🍳','Kitchen'],['👕','Fashion'],['📚','Books']].map(([icon, name]) => (
            <Link key={name} to={`/products?category=${name.toLowerCase()}`} className="card p-4 text-center hover:border-orange-300 hover:ring-2 hover:ring-orange-500/20">
              <span className="text-3xl mb-2 block">{icon}</span>
              <span className="text-sm font-medium">{name}</span>
            </Link>
          ))}
        </div>
      </section>
      
      {flashDeals.length > 0 && (
        <section className="bg-gradient-to-r from-red-500 to-orange-500 py-8">
          <div className="max-w-7xl mx-auto px-4">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <span className="bg-yellow-400 text-black px-3 py-1.5 rounded-lg font-bold">🔥 FLASH DEALS</span>
              </div>
              <Link to="/products?flash=true" className="text-white font-medium hover:underline">View All →</Link>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-4">
              {flashDeals.map(p => <ProductCard key={p._id} p={p} />)}
            </div>
          </div>
        </section>
      )}
      
      <section className="max-w-7xl mx-auto px-4 py-8">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold">⭐ Featured Products</h2>
          <Link to="/products" className="text-orange-500 font-medium hover:underline">View All →</Link>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-4">
          {products.map(p => <ProductCard key={p._id} p={p} />)}
        </div>
      </section>
      
      <section className="bg-gray-50 py-12">
        <div className="max-w-7xl mx-auto px-4">
          <div className="grid md:grid-cols-3 gap-8">
            <Link to="/rentals" className="card p-6 hover:border-orange-300">
              <span className="text-4xl mb-4 block">🏠</span>
              <h3 className="text-lg font-semibold mb-2">Apartment Rentals</h3>
              <p className="text-gray-500 text-sm">Find comfortable and affordable accommodation near campus.</p>
            </Link>
            <Link to="/food" className="card p-6 hover:border-orange-300">
              <span className="text-4xl mb-4 block">🍔</span>
              <h3 className="text-lg font-semibold mb-2">Food Delivery</h3>
              <p className="text-gray-500 text-sm">Order delicious food from campus vendors.</p>
            </Link>
            <div className="card p-6">
              <span className="text-4xl mb-4 block">🛡️</span>
              <h3 className="text-lg font-semibold mb-2">Safe & Secure</h3>
              <p className="text-gray-500 text-sm">Your transactions are protected. Verified sellers and secure payments.</p>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}

// ============ PRODUCTS PAGE ============
const ProductsPage = () => {
  const [products, setProducts] = useState([])
  const [loading, setLoading] = useState(true)
  const params = new URLSearchParams(window.location.search)
  const category = params.get('category') || ''
  const search = params.get('search') || ''
  
  useEffect(() => {
    setLoading(true)
    let url = '/api/products?limit=20'
    if (category) url += `&category=${category}`
    if (search) url += `&search=${search}`
    fetch(url).then(r => r.json()).then(d => { if (d.success) setProducts(d.data.products); setLoading(false) })
  }, [category, search])
  
  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 py-6">
        <div className="flex items-center gap-2 text-sm text-gray-500 mb-6">
          <span>Home</span><span>/</span><span className="font-medium">Products</span>
        </div>
        <h1 className="text-2xl font-bold mb-6">{search ? `Search: "${search}"` : category ? category.replace('-', ' ').replace(/\b\w/g, l => l.toUpperCase()) : 'All Products'}</h1>
        {loading ? <div className="grid grid-cols-2 md:grid-cols-4 gap-4">{[1,2,3,4,5,6,7,8].map(i => <div key={i} className="card h-64 animate-pulse bg-gray-200" />)}</div> : products.length > 0 ? (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-4">
            {products.map(p => (
              <div key={p._id} className="card group cursor-pointer" onClick={() => window.location.href = `/products/${p._id}`}>
                <div className="aspect-square bg-gray-100 relative">
                  <div className="absolute inset-0 bg-gradient-to-br from-gray-200 to-gray-300 flex items-center justify-center text-4xl">📦</div>
                  {p.condition === 'new' ? <span className="absolute top-2 left-2 badge badge-new">New</span> : <span className="absolute top-2 left-2 badge badge-used">Used</span>}
                </div>
                <div className="p-3">
                  <h3 className="font-medium text-gray-900 line-clamp-2 mb-1">{p.title}</h3>
                  <p className="text-xs text-gray-500 mb-2">{p.seller?.sellerProfile?.storeName || p.seller?.name}</p>
                  <span className="text-lg font-bold text-gray-900">₦{p.price?.toLocaleString()}</span>
                </div>
              </div>
            ))}
          </div>
        ) : <div className="text-center py-16 text-gray-500">No products found</div>}
      </div>
    </div>
  )
}

// ============ PRODUCT DETAIL ============
const ProductDetailPage = () => {
  const [product, setProduct] = useState(null)
  const [quantity, setQuantity] = useState(1)
  const { addToCart } = useCart()
  const params = new URLSearchParams(window.location.search)
  const id = window.location.pathname.split('/').pop()
  
  useEffect(() => { fetch(`/api/products/${id}`).then(r => r.json()).then(d => d.success && setProduct(d.data.product)) }, [id])
  
  if (!product) return <div className="min-h-screen flex items-center justify-center"><div className="w-12 h-12 border-4 border-orange-500 border-t-transparent rounded-full animate-spin"></div></div>
  
  const discount = product.originalPrice && product.originalPrice > product.price ? Math.round(((product.originalPrice - product.price) / product.originalPrice) * 100) : 0
  
  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 py-6">
        <div className="flex items-center gap-2 text-sm text-gray-500 mb-6">
          <Link to="/">Home</Link><span>/</span><Link to="/products">Products</Link><span>/</span><span className="font-medium truncate">{product.title}</span>
        </div>
        <div className="grid lg:grid-cols-2 gap-8">
          <div className="aspect-square bg-white rounded-xl border border-gray-200 flex items-center justify-center text-8xl">📦</div>
          <div className="space-y-6">
            <div>
              <span className={`badge mb-2 ${product.condition === 'new' ? 'badge-new' : 'badge-used'}`}>{product.condition === 'new' ? 'Brand New' : 'Used'}</span>
              <h1 className="text-2xl font-bold">{product.title}</h1>
              <div className="flex items-center gap-2 mt-2">
                <span className="text-yellow-500">⭐ {product.rating || 0}</span>
                <span className="text-gray-400">({product.reviewCount || 0} reviews)</span>
              </div>
            </div>
            <div className="bg-gray-50 rounded-xl p-4">
              <span className="text-3xl font-bold">₦{product.price?.toLocaleString()}</span>
              {product.originalPrice && <span className="text-lg text-gray-400 line-through ml-2">₦{product.originalPrice?.toLocaleString()}</span>}
              {discount > 0 && <span className="ml-2 text-green-600 font-medium">Save {discount}%</span>}
            </div>
            <div className="flex items-center gap-2">
              {product.stock > 0 ? <span className="text-green-600 font-medium">✓ In Stock ({product.stock} available)</span> : <span className="text-red-500 font-medium">Out of Stock</span>}
            </div>
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <span className="text-sm">Quantity:</span>
                <div className="flex items-center border border-gray-300 rounded-lg">
                  <button onClick={() => setQuantity(q => Math.max(1, q - 1))} className="w-10 h-10 hover:bg-gray-100">-</button>
                  <span className="w-12 text-center font-medium">{quantity}</span>
                  <button onClick={() => setQuantity(q => Math.min(product.stock, q + 1))} className="w-10 h-10 hover:bg-gray-100">+</button>
                </div>
              </div>
              <div className="flex gap-3">
                <button onClick={() => addToCart(product._id).then(r => r.success && (window.location.href = '/cart'))} className="flex-1 btn btn-secondary py-3">🛒 Add to Cart</button>
                <button onClick={() => addToCart(product._id).then(r => r.success && (window.location.href = '/checkout'))} className="flex-1 btn btn-primary py-3">Buy Now</button>
              </div>
            </div>
            <div className="border rounded-xl p-4">
              <p className="font-medium mb-2">Sold by: {product.seller?.sellerProfile?.storeName || product.seller?.name}</p>
              {product.location && <p className="text-sm text-gray-500">📍 {product.location}</p>}
            </div>
            <div className="border rounded-xl p-4">
              <h3 className="font-medium mb-2">Description</h3>
              <p className="text-gray-600 whitespace-pre-line">{product.description}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ============ CART PAGE ============
const CartPage = () => {
  const { user } = useAuth()
  const { items, summary, removeFromCart, updateQuantity } = useCart()
  
  if (!user) return <div className="min-h-screen flex items-center justify-center"><div className="text-center"><h2 className="text-xl font-semibold mb-4">Please login to view cart</h2><Link to="/login" className="btn btn-primary">Login</Link></div></div>
  if (items.length === 0) return <div className="min-h-screen flex items-center justify-center"><div className="text-center"><div className="text-6xl mb-4">🛒</div><h2 className="text-xl font-semibold mb-4">Your cart is empty</h2><Link to="/products" className="btn btn-primary">Browse Products</Link></div></div>
  
  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 py-6">
        <h1 className="text-2xl font-bold mb-6">Shopping Cart ({summary.itemCount} items)</h1>
        <div className="grid lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-4">
            {items.map(item => (
              <div key={item.product?._id} className="card p-4 flex gap-4">
                <div className="w-24 h-24 bg-gray-100 rounded-lg flex items-center justify-center text-2xl">📦</div>
                <div className="flex-1">
                  <h3 className="font-medium">{item.product?.title}</h3>
                  <p className="text-sm text-gray-500">Seller: {item.product?.seller?.name}</p>
                  <p className="text-lg font-bold mt-2">₦{item.product?.price?.toLocaleString()}</p>
                </div>
                <div className="flex flex-col items-end gap-2">
                  <button onClick={() => removeFromCart(item.product?._id)} className="text-red-500">🗑️</button>
                  <div className="flex items-center border rounded-lg">
                    <button onClick={() => updateQuantity(item.product?._id, item.quantity - 1)} className="w-8 h-8 hover:bg-gray-100">-</button>
                    <span className="w-10 text-center">{item.quantity}</span>
                    <button onClick={() => updateQuantity(item.product?._id, item.quantity + 1)} className="w-8 h-8 hover:bg-gray-100">+</button>
                  </div>
                </div>
              </div>
            ))}
          </div>
          <div className="lg:col-span-1">
            <div className="card p-6 sticky top-24">
              <h2 className="text-lg font-semibold mb-4">Order Summary</h2>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between"><span>Subtotal</span><span className="font-medium">₦{summary.subtotal?.toLocaleString()}</span></div>
                <div className="flex justify-between"><span>Shipping</span><span className="font-medium">₦{summary.shipping?.toLocaleString()}</span></div>
                <div className="flex justify-between text-lg font-bold border-t pt-2"><span>Total</span><span className="text-orange-500">₦{summary.total?.toLocaleString()}</span></div>
              </div>
              <Link to="/checkout" className="btn btn-primary w-full mt-4 py-3">Proceed to Checkout →</Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ============ CHECKOUT PAGE ============
const CheckoutPage = () => {
  const { user } = useAuth()
  const { items, summary, fetchCart } = useCart()
  const [address, setAddress] = useState({ fullName: user?.name || '', phone: '', street: '', city: '', state: '' })
  const [loading, setLoading] = useState(false)
  
  if (!user) return <Navigate to="/login" />
  if (items.length === 0) return <div className="min-h-screen flex items-center justify-center"><div className="text-center"><h2>Your cart is empty</h2><Link to="/products" className="btn btn-primary mt-4">Shop Now</Link></div></div>
  
  const handlePlaceOrder = async () => {
    if (!address.fullName || !address.phone || !address.street || !address.city || !address.state) { alert('Please fill all fields'); return }
    setLoading(true)
    const token = localStorage.getItem('accessToken')
    const res = await fetch('/api/orders', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ shippingAddress: address }) })
    const data = await res.json()
    setLoading(false)
    if (data.success) { fetchCart(); alert('Order placed successfully!'); window.location.href = '/' }
    else alert(data.message || 'Order failed')
  }
  
  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-4xl mx-auto px-4 py-6">
        <h1 className="text-2xl font-bold mb-6">Checkout</h1>
        <div className="grid lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-4">
            <div className="card p-6">
              <h2 className="font-semibold mb-4">📍 Shipping Address</h2>
              <div className="grid md:grid-cols-2 gap-4">
                <div className="md:col-span-2"><label className="text-sm text-gray-600">Full Name</label><input className="input" value={address.fullName} onChange={e => setAddress({...address, fullName: e.target.value})} /></div>
                <div className="md:col-span-2"><label className="text-sm text-gray-600">Phone</label><input className="input" value={address.phone} onChange={e => setAddress({...address, phone: e.target.value})} /></div>
                <div className="md:col-span-2"><label className="text-sm text-gray-600">Street Address</label><input className="input" value={address.street} onChange={e => setAddress({...address, street: e.target.value})} /></div>
                <div><label className="text-sm text-gray-600">City</label><input className="input" value={address.city} onChange={e => setAddress({...address, city: e.target.value})} /></div>
                <div><label className="text-sm text-gray-600">State</label><input className="input" value={address.state} onChange={e => setAddress({...address, state: e.target.value})} /></div>
              </div>
            </div>
          </div>
          <div className="lg:col-span-1">
            <div className="card p-6 sticky top-24">
              <h2 className="font-semibold mb-4">Order Summary</h2>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between"><span>{items.length} items</span><span>₦{summary.subtotal?.toLocaleString()}</span></div>
                <div className="flex justify-between"><span>Shipping</span><span>₦{summary.shipping?.toLocaleString()}</span></div>
                <div className="flex justify-between text-lg font-bold border-t pt-2"><span>Total</span><span className="text-orange-500">₦{summary.total?.toLocaleString()}</span></div>
              </div>
              <button onClick={handlePlaceOrder} disabled={loading} className="btn btn-primary w-full mt-4 py-3">{loading ? 'Processing...' : 'Place Order'}</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ============ LOGIN PAGE ============
const LoginPage = () => {
  const { login, user } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  
  if (user) return <Navigate to="/" />
  
  const handleLogin = async (e) => { e.preventDefault(); const result = await login(email, password); if (result.success) navigate('/'); else alert(result.message) }
  
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center gap-2 mb-6">
            <div className="w-12 h-12 bg-gradient-to-br from-orange-500 to-orange-600 rounded-xl flex items-center justify-center"><span className="text-white font-bold text-xl">OM</span></div>
          </Link>
          <h1 className="text-2xl font-bold">Welcome Back!</h1>
          <p className="text-gray-500 mt-2">Sign in to continue</p>
        </div>
        <div className="card p-6">
          <form onSubmit={handleLogin} className="space-y-4">
            <div><label className="label">Email</label><input type="email" value={email} onChange={e => setEmail(e.target.value)} className="input" placeholder="you@example.com" required /></div>
            <div><label className="label">Password</label><input type="password" value={password} onChange={e => setPassword(e.target.value)} className="input" placeholder="••••••••" required /></div>
            <button type="submit" className="btn btn-primary w-full py-3">Sign In</button>
          </form>
          <div className="mt-6 p-4 bg-gray-50 rounded-lg text-xs">
            <p className="font-medium mb-2">Demo:</p>
            <p>Admin: admin@ospolymarket.com</p>
            <p>Password: Admin@123456</p>
          </div>
          <p className="text-center text-sm text-gray-500 mt-6">Don't have an account? <Link to="/register" className="text-orange-500 font-medium">Create one</Link></p>
        </div>
      </div>
    </div>
  )
}

// ============ REGISTER PAGE ============
const RegisterPage = () => {
  const { register, user } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ name: '', email: '', password: '', role: 'buyer' })
  
  if (user) return <Navigate to="/" />
  
  const handleRegister = async (e) => { e.preventDefault(); const result = await register(form); if (result.success) navigate('/'); else alert(result.message) }
  
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-2xl font-bold">Create Account</h1>
          <p className="text-gray-500 mt-2">Join Ospoly Market</p>
        </div>
        <div className="card p-6">
          <form onSubmit={handleRegister} className="space-y-4">
            <div className="grid grid-cols-2 gap-3 mb-4">
              <button type="button" onClick={() => setForm({...form, role: 'buyer'})} className={`p-4 rounded-xl border-2 ${form.role === 'buyer' ? 'border-orange-500 bg-orange-50' : 'border-gray-200'}`}>🛒 Buy</button>
              <button type="button" onClick={() => setForm({...form, role: 'seller'})} className={`p-4 rounded-xl border-2 ${form.role === 'seller' ? 'border-orange-500 bg-orange-50' : 'border-gray-200'}`}>🏪 Sell</button>
            </div>
            <div><label className="label">Full Name</label><input value={form.name} onChange={e => setForm({...form, name: e.target.value})} className="input" placeholder="John Doe" required /></div>
            <div><label className="label">Email</label><input type="email" value={form.email} onChange={e => setForm({...form, email: e.target.value})} className="input" required /></div>
            <div><label className="label">Password</label><input type="password" value={form.password} onChange={e => setForm({...form, password: e.target.value})} className="input" placeholder="Min 8 chars" required /></div>
            <button type="submit" className="btn btn-primary w-full py-3">Create Account</button>
          </form>
          <p className="text-center text-sm text-gray-500 mt-6">Already have an account? <Link to="/login" className="text-orange-500 font-medium">Sign in</Link></p>
        </div>
      </div>
    </div>
  )
}

// ============ SELLER DASHBOARD ============
const SellerDashboard = () => {
  const { user } = useAuth()
  const [stats, setStats] = useState(null)
  const [products, setProducts] = useState([])
  
  if (!user || (user.role !== 'seller' && user.role !== 'admin')) return <Navigate to="/" />
  
  useEffect(() => {
    fetch('/api/orders/seller/stats', { headers: { Authorization: `Bearer ${localStorage.getItem('accessToken')}` } }).then(r => r.json()).then(d => d.success && setStats(d.data))
    fetch('/api/products/seller/my-products', { headers: { Authorization: `Bearer ${localStorage.getItem('accessToken')}` } }).then(r => r.json()).then(d => d.success && setProducts(d.data.products || []))
  }, [])
  
  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 py-6">
        <h1 className="text-2xl font-bold mb-6">📊 Seller Dashboard</h1>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <div className="card p-6"><p className="text-gray-500">Total Sales</p><p className="text-2xl font-bold">{stats?.stats?.totalOrders || 0}</p></div>
          <div className="card p-6"><p className="text-gray-500">Revenue</p><p className="text-2xl font-bold">₦{(stats?.stats?.totalRevenue || 0).toLocaleString()}</p></div>
          <div className="card p-6"><p className="text-gray-500">Pending</p><p className="text-2xl font-bold text-yellow-600">{stats?.stats?.pendingOrders || 0}</p></div>
          <div className="card p-6"><p className="text-gray-500">Products</p><p className="text-2xl font-bold">{products.length}</p></div>
        </div>
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4"><h2 className="font-semibold">My Products</h2><Link to="/seller/add-product" className="btn btn-primary">+ Add Product</Link></div>
          {products.length > 0 ? (
            <table className="w-full"><thead><tr className="text-left text-sm text-gray-500 border-b"><th className="pb-3">Product</th><th className="pb-3">Price</th><th className="pb-3">Stock</th><th className="pb-3">Status</th></tr></thead>
            <tbody>{products.map(p => (<tr key={p._id} className="border-b"><td className="py-3">{p.title}</td><td className="py-3">₦{p.price?.toLocaleString()}</td><td className="py-3">{p.stock}</td><td className="py-3"><span className={`badge ${p.isApproved ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'}`}>{p.isApproved ? 'Approved' : 'Pending'}</span></td></tr>))}</tbody></table>
          ) : <p className="text-gray-500 text-center py-8">No products yet. Add your first product!</p>}
        </div>
      </div>
    </div>
  )
}

// ============ ADMIN DASHBOARD ============
const AdminDashboard = () => {
  const { user } = useAuth()
  const [stats, setStats] = useState(null)
  
  if (!user || user.role !== 'admin') return <Navigate to="/" />
  
  useEffect(() => { fetch('/api/admin/dashboard', { headers: { Authorization: `Bearer ${localStorage.getItem('accessToken')}` } }).then(r => r.json()).then(d => d.success && setStats(d.data)) }, [])
  
  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 py-6">
        <h1 className="text-2xl font-bold mb-6">⚙️ Admin Panel</h1>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <div className="card p-6"><p className="text-gray-500">Total Users</p><p className="text-2xl font-bold">{stats?.stats?.totalUsers || 0}</p></div>
          <div className="card p-6"><p className="text-gray-500">Sellers</p><p className="text-2xl font-bold">{stats?.stats?.totalSellers || 0}</p></div>
          <div className="card p-6"><p className="text-gray-500">Products</p><p className="text-2xl font-bold">{stats?.stats?.totalProducts || 0}</p></div>
          <div className="card p-6"><p className="text-gray-500">Pending</p><p className="text-2xl font-bold text-orange-600">{stats?.stats?.pendingApprovals || 0}</p></div>
        </div>
        <div className="grid lg:grid-cols-2 gap-6">
          <div className="card p-6"><h3 className="font-semibold mb-4">Recent Users</h3>
            {stats?.recentUsers?.map(u => <div key={u._id} className="flex items-center justify-between py-2 border-b"><div><p className="font-medium">{u.name}</p><p className="text-sm text-gray-500">{u.email}</p></div><span className="text-xs px-2 py-1 bg-gray-100 rounded capitalize">{u.role}</span></div>)}
          </div>
          <div className="card p-6"><h3 className="font-semibold mb-4">Recent Orders</h3>
            {stats?.recentOrders?.map(o => <div key={o._id} className="flex items-center justify-between py-2 border-b"><div><p className="font-medium">#{o._id?.slice(-6)}</p><p className="text-sm text-gray-500">{o.buyer?.name}</p></div><span className="font-bold">₦{o.finalAmount?.toLocaleString()}</span></div>)}
          </div>
        </div>
      </div>
    </div>
  )
}

// ============ RENTALS & FOOD PAGES ============
const RentalsPage = () => (
  <div className="min-h-screen bg-gray-50">
    <section className="bg-gradient-to-r from-orange-600 to-orange-500 py-12 text-center text-white">
      <h1 className="text-3xl font-bold mb-4">🏠 Find Your Perfect Home</h1>
      <p className="text-white/90 mb-6">Apartments, rooms, and rentals near campus</p>
    </section>
    <div className="max-w-7xl mx-auto px-4 py-8">
      <h2 className="text-xl font-bold mb-6">Available Rentals</h2>
      <div className="grid md:grid-cols-3 gap-6">
        {[1,2,3].map(i => (
          <div key={i} className="card overflow-hidden">
            <div className="aspect-video bg-gray-200 flex items-center justify-center text-4xl">🏠</div>
            <div className="p-4">
              <p className="text-2xl font-bold mb-1">₦45,000<span className="text-sm font-normal text-gray-500">/mo</span></p>
              <h3 className="font-semibold mb-2">Student Apartment {i}</h3>
              <p className="text-sm text-gray-500 mb-2">📍 Campus Area, Owerri</p>
              <p className="text-sm">🛏️ 1 Bed • 🛁 1 Bath</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  </div>
)

const FoodPage = () => (
  <div className="min-h-screen bg-gray-50">
    <section className="bg-gradient-to-r from-green-600 to-green-500 py-12 text-center text-white">
      <h1 className="text-3xl font-bold mb-4">🍔 Food Delivery</h1>
      <p className="text-white/90 mb-6">Delicious food from campus vendors, delivered to your doorstep</p>
    </section>
    <div className="max-w-7xl mx-auto px-4 py-8">
      <h2 className="text-xl font-bold mb-6">Popular Vendors</h2>
      <div className="grid md:grid-cols-3 gap-6">
        {[1,2,3].map(i => (
          <div key={i} className="card overflow-hidden">
            <div className="h-24 bg-gradient-to-r from-green-400 to-green-500 flex items-center justify-center text-4xl">🍳</div>
            <div className="p-4">
              <h3 className="font-semibold">Campus Kitchen {i}</h3>
              <p className="text-sm text-gray-500">⭐ 4.5 • 20-35 min • ₦300 delivery</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  </div>
)

// ============ APP ============
function App() {
  return (
    <AuthProvider>
      <CartProvider>
        <div className="min-h-screen flex flex-col">
          <Header />
          <main className="flex-1 pb-16 md:pb-0">
            <Routes>
              <Route path="/" element={<HomePage />} />
              <Route path="/products" element={<ProductsPage />} />
              <Route path="/products/:id" element={<ProductDetailPage />} />
              <Route path="/cart" element={<CartPage />} />
              <Route path="/checkout" element={<CheckoutPage />} />
              <Route path="/login" element={<LoginPage />} />
              <Route path="/register" element={<RegisterPage />} />
              <Route path="/seller" element={<SellerDashboard />} />
              <Route path="/admin" element={<AdminDashboard />} />
              <Route path="/rentals" element={<RentalsPage />} />
              <Route path="/food" element={<FoodPage />} />
              <Route path="*" element={<div className="min-h-screen flex items-center justify-center"><h1 className="text-4xl font-bold text-gray-300">404 - Page Not Found</h1></div>} />
            </Routes>
          </main>
          <footer className="bg-gray-900 text-gray-300 py-8 text-center">
            <p>© {new Date().getFullYear()} Ospoly Market. All rights reserved.</p>
          </footer>
        </div>
      </CartProvider>
    </AuthProvider>
  )
}

export default App
