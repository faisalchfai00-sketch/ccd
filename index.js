// index.js - Complete Backend for Suspect Tracker
// Deploy on Vercel - With Domain Lock & Token Blacklisting

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
const fetch = require('node-fetch');
require('dotenv').config();

// ==================== FIREBASE ADMIN INIT ====================
let firebaseInitialized = false;
let db = null;

// Token blacklist cache
const tokenBlacklist = new Set();

try {
  console.log('🔥 Starting Firebase Admin initialization...');

  if (!admin.apps.length) {
    let privateKey = process.env.FIREBASE_PRIVATE_KEY;
    if (privateKey) {
      privateKey = privateKey.replace(/\\n/g, '\n');
    }

    const credential = {
      projectId: process.env.FIREBASE_PROJECT_ID,
      privateKey: privateKey,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    };

    admin.initializeApp({
      credential: admin.credential.cert(credential),
    });

    db = admin.firestore();
    firebaseInitialized = true;
    console.log('✅ Firebase Admin initialized successfully');
  }
} catch (error) {
  console.error('❌ Firebase Admin init error:', error);
}

// ==================== EXPRESS SETUP ====================
const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_change_me';

// Middleware
app.use(express.json());
app.use(cookieParser());

// ==================== CORS WITH DOMAIN LOCK ====================
const allowedOrigins = [
  'https://suspect-tracker.free.nf',
  'http://suspect-tracker.free.nf',
  'https://www.suspect-tracker.free.nf',
  'http://localhost:5500',
  'http://localhost:5000',
  'http://127.0.0.1:5500'
];

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps or curl)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      console.log(`❌ CORS Blocked request from: ${origin}`);
      return callback(new Error('Access denied. This API can only be accessed from https://suspect-tracker.free.nf'), false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

// Domain check middleware
app.use((req, res, next) => {
  const referer = req.headers.referer || req.headers.origin;
  
  if (referer && !referer.includes('suspect-tracker.free.nf') && 
      !referer.includes('localhost') && !referer.includes('127.0.0.1')) {
    console.log(`❌ Domain Blocked request with referer: ${referer}`);
    return res.status(403).json({ 
      error: 'Access Denied', 
      message: 'This API can only be accessed from https://suspect-tracker.free.nf' 
    });
  }
  
  next();
});

// Log all requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - Origin: ${req.headers.origin || 'unknown'}`);
  next();
});

// ==================== AUTH MIDDLEWARE ====================
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  if (tokenBlacklist.has(token)) {
    console.log('Token is blacklisted, rejecting request');
    return res.status(403).json({ error: 'Token has been revoked. Please login again.' });
  }

  jwt.verify(token, JWT_SECRET, async (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    
    try {
      const userDoc = await db.collection('users').doc(user.uid).get();
      if (userDoc.exists && userDoc.data().status === 'blocked') {
        tokenBlacklist.add(token);
        return res.status(403).json({ error: 'User account has been blocked' });
      }
    } catch (dbError) {
      console.error('Error checking user status:', dbError);
    }
    
    req.user = user;
    next();
  });
};

const authenticateAdmin = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Admin token required' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    if (decoded.email !== process.env.ADMIN_EMAIL) {
      return res.status(403).json({ error: 'Not authorized as admin' });
    }
    
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid admin token' });
  }
};

// ==================== ROUTES ====================

// Health check
app.get('/', (req, res) => {
  res.json({ 
    status: '🟢 Suspect Tracker API Running',
    firebase: firebaseInitialized ? '✅ connected' : '❌ not connected',
    timestamp: new Date().toISOString()
  });
});

// ==================== 1. LOGIN ====================
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    let userRecord;
    try {
      userRecord = await admin.auth().getUserByEmail(email);
    } catch (authError) {
      return res.status(401).json({ error: 'User not found' });
    }

    const apiKey = process.env.FIREBASE_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: 'Firebase API key missing' });
    }

    const verifyResponse = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, returnSecureToken: true })
      }
    );

    if (!verifyResponse.ok) {
      const verifyData = await verifyResponse.json();
      return res.status(401).json({ error: verifyData.error?.message || 'Invalid password' });
    }

    const userDoc = await db.collection('users').doc(userRecord.uid).get();
    if (userDoc.exists && userDoc.data().status === 'blocked') {
      return res.status(403).json({ error: 'Your account has been suspended.' });
    }

    const token = jwt.sign(
      { uid: userRecord.uid, email: userRecord.email, verified: true, iat: Date.now() },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    for (const blacklistedToken of tokenBlacklist) {
      try {
        const decoded = jwt.decode(blacklistedToken);
        if (decoded && decoded.uid === userRecord.uid) {
          tokenBlacklist.delete(blacklistedToken);
        }
      } catch(e) {}
    }

    let userData = {};
    try {
      const userDocData = await db.collection('users').doc(userRecord.uid).get();
      if (userDocData.exists) {
        userData = userDocData.data();
      } else {
        const defaultData = {
          settings: {
            refNo: '1/DO CCD',
            centerDo: 'PAKPATTAN',
            toDate: '01/01/2026',
            dateAfterTrack: '01/09/2025',
            fir: 'FIR-1112/24',
            us: '395/412',
            ps: 'Saddar Arifwala',
            io: 'ASI Muhammad Naeem',
            ioNo: '0300-9793362',
            divisionRo: 'SAHIWAL',
            divRef: '3097',
            divDate: '30/11/2025'
          },
          status: 'active'
        };
        await db.collection('users').doc(userRecord.uid).set(defaultData);
        userData = defaultData;
      }
    } catch (firestoreError) {
      userData = { settings: {} };
    }

    res.json({
      token,
      user: {
        uid: userRecord.uid,
        email: userRecord.email,
        settings: userData.settings || {}
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== 2. GET USER DATA ====================
app.get('/api/user-data', authenticateToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    const userDoc = await db.collection('users').doc(uid).get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User data not found' });
    }

    res.json(userDoc.data());
  } catch (error) {
    console.error('Get user data error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== 3. SAVE USER SETTINGS ====================
app.post('/api/save-settings', authenticateToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    const settings = req.body;

    if (!settings) {
      return res.status(400).json({ error: 'Settings required' });
    }

    await db.collection('users').doc(uid).set({ settings: settings }, { merge: true });
    res.json({ success: true, message: 'Settings saved successfully' });
  } catch (error) {
    console.error('Save settings error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== 4. SAVE OUTPUT (HISTORY) ====================
app.post('/api/save-output', authenticateToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    const { category, subCategory, numbers, outputData, refNo } = req.body;

    if (!category || !outputData) {
      return res.status(400).json({ error: 'Category and outputData required' });
    }

    const historyEntry = {
      userId: uid,
      category,
      subCategory: subCategory || category,
      numbers: numbers || [],
      outputData,
      refNo: refNo || '',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      outputHtml: outputData.html || '',
      outputText: outputData.text || ''
    };

    const docRef = await db.collection('history').add(historyEntry);
    res.json({ success: true, id: docRef.id, message: 'Output saved to history' });
  } catch (error) {
    console.error('Save output error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== 5. GET HISTORY ====================
app.get('/api/history', authenticateToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    const { category, limit = 50 } = req.query;

    let query = db.collection('history')
      .where('userId', '==', uid)
      .orderBy('createdAt', 'desc')
      .limit(parseInt(limit));

    if (category && category !== '') {
      query = query.where('category', '==', category);
    }

    const snapshot = await query.get();
    const history = [];
    snapshot.forEach(doc => {
      const data = doc.data();
      history.push({
        id: doc.id,
        ...data,
        createdAt: data.createdAt?.toDate ? data.createdAt.toDate() : null
      });
    });

    res.json(history);
  } catch (error) {
    console.error('Get history error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== 6. GET STATS ====================
app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    const statsDoc = await db.collection('stats').doc(uid).get();

    if (!statsDoc.exists) {
      return res.json({ cdrs: 0, imei: 0, total: 0 });
    }

    const stats = statsDoc.data();
    res.json({
      cdrs: stats.cdrs || 0,
      imei: stats.imei || 0,
      total: stats.total || 0
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== 7. DELETE HISTORY ENTRY ====================
app.delete('/api/history/:id', authenticateToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    const historyId = req.params.id;

    const historyRef = db.collection('history').doc(historyId);
    const historyDoc = await historyRef.get();

    if (!historyDoc.exists) {
      return res.status(404).json({ error: 'History entry not found' });
    }

    const historyData = historyDoc.data();
    if (historyData.userId !== uid) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    await historyRef.delete();
    res.json({ success: true, message: 'History entry deleted' });
  } catch (error) {
    console.error('Delete history error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== 8. VERIFY TOKEN ====================
app.post('/api/verify-token', authenticateToken, (req, res) => {
  res.json({ valid: true, user: { uid: req.user.uid, email: req.user.email } });
});

// ==================== 9. ADMIN: CREATE USER ====================
app.post('/api/admin/create-user', authenticateAdmin, async (req, res) => {
  try {
    const { email, password, adminSecret } = req.body;
    
    if (adminSecret !== process.env.ADMIN_SECRET_KEY) {
      console.log('Admin create user: unauthorized - invalid secret');
      return res.status(403).json({ error: 'Unauthorized: Invalid admin secret key' });
    }

    console.log('Creating new user:', email);

    const userRecord = await admin.auth().createUser({ email, password });

    await db.collection('users').doc(userRecord.uid).set({
      status: 'active',
      settings: {
        refNo: '1/DO CCD',
        centerDo: 'PAKPATTAN',
        toDate: '01/01/2026',
        dateAfterTrack: '01/09/2025',
        fir: 'FIR-1112/24',
        us: '395/412',
        ps: 'Saddar Arifwala',
        io: 'ASI Muhammad Naeem',
        ioNo: '0300-9793362',
        divisionRo: 'SAHIWAL',
        divRef: '3097',
        divDate: '30/11/2025',
        refDate: '30/11/2025'
      }
    });

    res.json({ success: true, uid: userRecord.uid, message: 'User created successfully' });
  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== 10. ADMIN: DELETE USER ====================
app.post('/api/admin/delete-user', authenticateAdmin, async (req, res) => {
  try {
    const { email, adminSecret } = req.body;
    
    if (adminSecret !== process.env.ADMIN_SECRET_KEY) {
      return res.status(403).json({ error: 'Unauthorized: Invalid admin secret key' });
    }

    console.log('Deleting user:', email);
    const userRecord = await admin.auth().getUserByEmail(email);
    
    await db.collection('users').doc(userRecord.uid).delete();
    await db.collection('stats').doc(userRecord.uid).delete();
    
    const historySnapshot = await db.collection('history')
      .where('userId', '==', userRecord.uid)
      .get();
    
    const batch = db.batch();
    historySnapshot.docs.forEach(doc => batch.delete(doc.ref));
    await batch.commit();

    await admin.auth().deleteUser(userRecord.uid);

    res.json({ success: true, message: 'User deleted completely' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== 11. ADMIN: VERIFY TOKEN ====================
app.post('/api/admin/verify', authenticateAdmin, (req, res) => {
  res.json({ valid: true, admin: req.admin });
});

// ==================== 12. ADMIN: LOGIN ====================
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPassword = process.env.ADMIN_PASSWORD;
    
    if (!adminEmail || !adminPassword) {
      return res.status(500).json({ error: 'Admin configuration error' });
    }
    
    if (email !== adminEmail || password !== adminPassword) {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }
    
    const token = jwt.sign(
      { email: adminEmail, role: 'admin' },
      JWT_SECRET,
      { expiresIn: '1d' }
    );
    
    res.json({ success: true, token, admin: { email: adminEmail } });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== 13. ADMIN: GET ALL USERS ====================
app.get('/api/admin/all-users', authenticateAdmin, async (req, res) => {
  try {
    const listUsersResult = await admin.auth().listUsers(1000);
    const users = listUsersResult.users;
    const usersData = [];
    
    for (const user of users) {
      const userDoc = await db.collection('users').doc(user.uid).get();
      const userSettings = userDoc.exists ? userDoc.data() : {};
      const statsDoc = await db.collection('stats').doc(user.uid).get();
      const stats = statsDoc.exists ? statsDoc.data() : { cdrs: 0, imei: 0, total: 0 };
      const status = userSettings.status || 'active';
      
      usersData.push({
        uid: user.uid,
        email: user.email,
        createdAt: user.metadata.creationTime,
        lastLogin: user.metadata.lastSignInTime,
        status: status,
        stats: {
          cdrs: stats.cdrs || 0,
          imei: stats.imei || 0,
          total: stats.total || 0
        },
        settings: userSettings.settings || {}
      });
    }
    
    res.json({ users: usersData });
  } catch (error) {
    console.error('Get all users error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== 14. ADMIN: BLOCK USER ====================
app.post('/api/admin/block-user', authenticateAdmin, async (req, res) => {
  try {
    const { uid } = req.body;
    if (!uid) return res.status(400).json({ error: 'User ID required' });
    
    console.log(`🔨 Admin blocking user: ${uid}`);
    
    await db.collection('users').doc(uid).set({
      status: 'blocked',
      blockedAt: admin.firestore.FieldValue.serverTimestamp(),
      blockedBy: req.admin.email
    }, { merge: true });
    
    await admin.auth().updateUser(uid, { disabled: true });
    await admin.auth().revokeRefreshTokens(uid);
    
    console.log(`✅ User ${uid} blocked successfully`);
    
    res.json({ success: true, message: 'User blocked successfully' });
  } catch (error) {
    console.error('Block user error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== 15. ADMIN: UNBLOCK USER ====================
app.post('/api/admin/unblock-user', authenticateAdmin, async (req, res) => {
  try {
    const { uid } = req.body;
    if (!uid) return res.status(400).json({ error: 'User ID required' });
    
    console.log(`🔓 Admin unblocking user: ${uid}`);
    
    await db.collection('users').doc(uid).set({ status: 'active' }, { merge: true });
    await admin.auth().updateUser(uid, { disabled: false });
    
    res.json({ success: true, message: 'User unblocked successfully' });
  } catch (error) {
    console.error('Unblock user error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== 16. ADMIN: FORCE LOGOUT USER ====================
app.post('/api/admin/logout-user', authenticateAdmin, async (req, res) => {
  try {
    const { uid } = req.body;
    if (!uid) return res.status(400).json({ error: 'User ID required' });
    
    console.log(`🚪 Admin force logging out user: ${uid}`);
    await admin.auth().revokeRefreshTokens(uid);
    
    res.json({ success: true, message: 'User logged out successfully' });
  } catch (error) {
    console.error('Force logout error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== EXPORT FOR VERCEL ====================
module.exports = app;
