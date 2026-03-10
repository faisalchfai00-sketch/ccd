// index.js - Complete Backend for Suspect Tracker
// Deploy on Vercel, single file, Firebase Admin + Express

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

try {
  console.log('🔥 Starting Firebase Admin initialization...');
  console.log('Project ID exists:', !!process.env.FIREBASE_PROJECT_ID);
  console.log('Private Key exists:', !!process.env.FIREBASE_PRIVATE_KEY);
  console.log('Client Email exists:', !!process.env.FIREBASE_CLIENT_EMAIL);

  if (!admin.apps.length) {
    // Format private key correctly
    let privateKey = process.env.FIREBASE_PRIVATE_KEY;
    if (privateKey) {
      // Handle both formats: with \n and actual line breaks
      privateKey = privateKey.replace(/\\n/g, '\n');
      console.log('Private key formatted, length:', privateKey.length);
    }

    const credential = {
      projectId: process.env.FIREBASE_PROJECT_ID,
      privateKey: privateKey,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    };

    console.log('Credential object created');

    admin.initializeApp({
      credential: admin.credential.cert(credential),
    });

    db = admin.firestore();
    firebaseInitialized = true;
    console.log('✅ Firebase Admin initialized successfully');
  }
} catch (error) {
  console.error('❌ Firebase Admin init error:', error);
  console.error('Error details:', {
    message: error.message,
    code: error.code,
    stack: error.stack
  });
}

// ==================== EXPRESS SETUP ====================
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_change_me';

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5500',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
  })
);

// Log all requests for debugging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// ==================== AUTH MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
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
  console.log('📝 Login endpoint hit');
  
  try {
    const { email, password } = req.body;
    console.log('Email:', email);
    console.log('Password provided:', !!password);

    if (!email || !password) {
      console.log('Missing email or password');
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Check Firebase Auth
    console.log('Checking Firebase Auth for user...');
    let userRecord;
    try {
      userRecord = await admin.auth().getUserByEmail(email);
      console.log('User found in Firebase Auth:', userRecord.uid);
    } catch (authError) {
      console.error('Firebase Auth error:', authError);
      return res.status(401).json({ error: 'User not found' });
    }

    // Verify password using Firebase REST API
    console.log('Verifying password with Firebase REST API...');
    const apiKey = process.env.FIREBASE_API_KEY;
    console.log('API Key exists:', !!apiKey);
    
    if (!apiKey) {
      console.error('FIREBASE_API_KEY missing in environment');
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

    const verifyData = await verifyResponse.json();
    console.log('Firebase REST API response status:', verifyResponse.status);

    if (!verifyResponse.ok) {
      console.error('Password verification failed:', verifyData.error);
      return res.status(401).json({ error: verifyData.error?.message || 'Invalid password' });
    }

    console.log('Password verified successfully');

    // Generate JWT token
    const token = jwt.sign(
      { 
        uid: userRecord.uid, 
        email: userRecord.email,
        verified: true 
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log('JWT token generated');

    // Get user data from Firestore
    console.log('Fetching user data from Firestore...');
    let userData = {};
    
    try {
      const userDoc = await db.collection('users').doc(userRecord.uid).get();
      
      if (userDoc.exists) {
        userData = userDoc.data();
        console.log('User data found in Firestore');
      } else {
        // Create default user data
        console.log('Creating default user data');
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
            divDate: '30/11/2025',
            refDate: '30/11/2025'
          }
        };
        await db.collection('users').doc(userRecord.uid).set(defaultData);
        userData = defaultData;
        console.log('Default user data created');
      }
    } catch (firestoreError) {
      console.error('Firestore error:', firestoreError);
      // Continue with empty user data
      userData = { settings: {} };
    }

    console.log('Login successful for:', email);
    res.json({
      token,
      user: {
        uid: userRecord.uid,
        email: userRecord.email,
        settings: userData.settings || {}
      }
    });

  } catch (error) {
    console.error('💥 Login error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ 
      error: 'Internal server error',
      details: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// ==================== 2. GET USER DATA ====================
app.get('/api/user-data', authenticateToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    console.log('Fetching user data for uid:', uid);
    
    const userDoc = await db.collection('users').doc(uid).get();

    if (!userDoc.exists) {
      console.log('User data not found');
      return res.status(404).json({ error: 'User data not found' });
    }

    console.log('User data fetched successfully');
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

    console.log('Saving settings for uid:', uid);
    await db.collection('users').doc(uid).set({
      settings: settings
    }, { merge: true });

    console.log('Settings saved successfully');
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

    console.log('Saving output to history for uid:', uid);
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

    // Update stats - ONLY FOR CDRS AND IMEI
    // Location, SubInfo, GET CNIC are NOT counted in dashboard stats
    const statsRef = db.collection('stats').doc(uid);
    const statsDoc = await statsRef.get();
    
    const count = Array.isArray(numbers) ? numbers.length : 1;
    
    if (!statsDoc.exists) {
      // Initialize stats with zeros
      await statsRef.set({
        cdrs: category === 'cdrs' ? count : 0,
        imei: category === 'imei' ? count : 0,
        total: (category === 'cdrs' || category === 'imei') ? count : 0
      });
    } else {
      const stats = statsDoc.data();
      const update = {};
      
      // Only update cdrs and imei counts
      if (category === 'cdrs') {
        update.cdrs = (stats.cdrs || 0) + count;
        update.total = (stats.total || 0) + count;
      } else if (category === 'imei') {
        update.imei = (stats.imei || 0) + count;
        update.total = (stats.total || 0) + count;
      } else {
        // For other categories (location, subinfo, get-cnic) - don't update stats
        // Just return without updating stats
        console.log('Category not counted in stats:', category);
        return res.json({ 
          success: true, 
          id: docRef.id,
          message: 'Output saved to history (not counted in stats)' 
        });
      }
      
      await statsRef.update(update);
    }

    console.log('Output saved to history with id:', docRef.id);
    res.json({ 
      success: true, 
      id: docRef.id,
      message: 'Output saved to history' 
    });
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

    console.log('Fetching history for uid:', uid, 'category:', category);

    // Check if db is initialized
    if (!db) {
      console.error('Firestore not initialized');
      return res.status(500).json({ error: 'Database not initialized' });
    }

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

    console.log('Found', history.length, 'history entries');
    res.json(history);
  } catch (error) {
    console.error('💥 Get history error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ 
      error: 'Internal server error',
      details: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// ==================== 6. GET STATS (ONLY CDRS & IMEI) ====================
app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    console.log('Fetching stats for uid:', uid);
    
    const statsDoc = await db.collection('stats').doc(uid).get();

    if (!statsDoc.exists) {
      console.log('No stats found, returning zeros');
      return res.json({ cdrs: 0, imei: 0, total: 0 });
    }

    const stats = statsDoc.data();
    console.log('Stats found:', stats);
    
    // Return only cdrs, imei, and total
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

    console.log('Deleting history entry:', historyId, 'for uid:', uid);

    const historyRef = db.collection('history').doc(historyId);
    const historyDoc = await historyRef.get();

    if (!historyDoc.exists) {
      return res.status(404).json({ error: 'History entry not found' });
    }

    const historyData = historyDoc.data();
    if (historyData.userId !== uid) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Update stats before deleting (only for cdrs and imei)
    const statsRef = db.collection('stats').doc(uid);
    const statsDoc = await statsRef.get();
    
    if (statsDoc.exists) {
      const stats = statsDoc.data();
      const count = Array.isArray(historyData.numbers) ? historyData.numbers.length : 1;
      const update = {};
      
      if (historyData.category === 'cdrs') {
        update.cdrs = Math.max(0, (stats.cdrs || 0) - count);
        update.total = Math.max(0, (stats.total || 0) - count);
      } else if (historyData.category === 'imei') {
        update.imei = Math.max(0, (stats.imei || 0) - count);
        update.total = Math.max(0, (stats.total || 0) - count);
      }
      // For other categories, don't update stats
      
      await statsRef.update(update);
    }

    await historyRef.delete();

    console.log('History entry deleted successfully');
    res.json({ success: true, message: 'History entry deleted' });
  } catch (error) {
    console.error('Delete history error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==================== 8. VERIFY TOKEN ====================
app.post('/api/verify-token', authenticateToken, (req, res) => {
  console.log('Token verified for uid:', req.user.uid);
  res.json({ 
    valid: true, 
    user: {
      uid: req.user.uid,
      email: req.user.email
    }
  });
});

// ==================== 9. ADMIN: CREATE USER (Manual) ====================
app.post('/api/admin/create-user', async (req, res) => {
  try {
    const { email, password, adminSecret } = req.body;
    
    if (adminSecret !== process.env.ADMIN_SECRET) {
      console.log('Admin create user: unauthorized attempt');
      return res.status(403).json({ error: 'Unauthorized' });
    }

    console.log('Creating new user:', email);

    const userRecord = await admin.auth().createUser({
      email,
      password,
    });

    // Create default user data
    await db.collection('users').doc(userRecord.uid).set({
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

    console.log('User created successfully:', userRecord.uid);
    res.json({ 
      success: true, 
      uid: userRecord.uid,
      message: 'User created successfully' 
    });
  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== 10. ADMIN: DELETE USER ====================
app.post('/api/admin/delete-user', async (req, res) => {
  try {
    const { email, adminSecret } = req.body;
    
    if (adminSecret !== process.env.ADMIN_SECRET) {
      console.log('Admin delete user: unauthorized attempt');
      return res.status(403).json({ error: 'Unauthorized' });
    }

    console.log('Deleting user:', email);
    const userRecord = await admin.auth().getUserByEmail(email);
    
    // Delete user data from Firestore
    await db.collection('users').doc(userRecord.uid).delete();
    
    // Delete stats
    await db.collection('stats').doc(userRecord.uid).delete();
    
    // Delete history (batched)
    const historySnapshot = await db.collection('history')
      .where('userId', '==', userRecord.uid)
      .get();
    
    const batch = db.batch();
    historySnapshot.docs.forEach(doc => {
      batch.delete(doc.ref);
    });
    await batch.commit();

    // Delete from Auth
    await admin.auth().deleteUser(userRecord.uid);

    console.log('User deleted completely:', userRecord.uid);
    res.json({ success: true, message: 'User deleted completely' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== START SERVER ====================
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔥 Firebase initialized: ${firebaseInitialized}`);
  console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Export for Vercel
module.exports = app;
