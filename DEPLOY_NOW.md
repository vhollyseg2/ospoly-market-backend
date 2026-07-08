# 🚀 DEPLOY OSPOLY MARKET - QUICK START

## STEP 1: Create GitHub Repos
1. Go to https://github.com
2. Sign in or create account
3. Create 2 repos:
   - `ospoly-market-backend` (public)
   - `ospoly-market-frontend` (public)

## STEP 2: Push Backend
```bash
cd /home/user/backend
git init
git add .
git commit -m "Ospoly Market Backend"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/ospoly-market-backend.git
git push -u origin main
```

## STEP 3: Push Frontend
```bash
cd /home/user/frontend
git init
git add .
git commit -m "Ospoly Market Frontend"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/ospoly-market-frontend.git
git push -u origin main
```

## STEP 4: Deploy Backend on Render
1. Go to https://render.com
2. Sign up with GitHub
3. New → Web Service → Connect ospoly-market-backend
4. Settings:
   - Name: ospoly-market-api
   - Build: npm install
   - Start: node server.js
5. Add Environment Variables:
   - PORT = 10000
   - NODE_ENV = production
   - MONGO_URI = your_mongodb_url
   - JWT_SECRET = any_secure_string
   - JWT_REFRESH_SECRET = any_secure_string
   - FRONTEND_URL = https://your-frontend.vercel.app
6. Deploy!

## STEP 5: Deploy Frontend on Vercel
1. Go to https://vercel.com
2. Sign up with GitHub
3. Import ospoly-market-frontend
4. Add Environment Variable:
   - VITE_API_URL = https://your-render-api.onrender.com/api
5. Deploy!

## 🎉 DONE!
