// index.js - Complete Backend for Suspect Tracker
// Deploy on Vercel, single file, Firebase Admin + Express

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
require('dotenv').config();

// ==================== FIX FOR node-fetch (CommonJS compatibility) ====================
// Yeh dono tarah se kaam karega - node-fetch v2 aur v3 ke saath
let fetch;
(async () => {
  try {
    // Pehle v2 try karo
    fetch = require('node-fetch');
  } catch (e) {
    // Agar v2 nahi hai to v3 dynamic import karo
    fetch = (await import('node-fetch')).default;
  }
})();

// ==================== FIREBASE ADMIN INIT ====================
let firebaseInitialized = false;
try {
  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      }),
    });
    firebaseInitialized = true;
    console.log('✅ Firebase Admin initialized');
  }
} catch (error) {
  console.error('❌ Firebase Admin init error:', error);
}

const db = admin.firestore();

// ==================== EXPRESS SETUP ====================
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_change_me';

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: process.env.FRONTEND_URL || 'https://suspect-tracker.free.nf',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
  })
);

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
    firebase: firebaseInitialized ? '✅ connected' : '❌ not connected'
  });
});

// ==================== 1. LOGIN (FIXED) ====================
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Firebase Auth se verify
    let userRecord;
    try {
      userRecord = await admin.auth().getUserByEmail(email);
    } catch (error) {
      return res.status(401).json({ error: 'User not found' });
    }

    const apiKey = process.env.FIREBASE_API_KEY;
    
    if (!apiKey) {
      return res.status(500).json({ error: 'Firebase API key missing' });
    }

    // fetch available hone tak wait karo
    if (!fetch) {
      await new Promise(resolve => setTimeout(resolve, 100));
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

    if (!verifyResponse.ok) {
      return res.status(401).json({ error: verifyData.error?.message || 'Invalid password' });
    }

    // User verified, generate JWT token
    const token = jwt.sign(
      { 
        uid: userRecord.uid, 
        email: userRecord.email,
        verified: true 
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Get user data from Firestore
    const userDoc = await db.collection('users').doc(userRecord.uid).get();
    let userData = {};
    if (userDoc.exists) {
      userData = userDoc.data();
    } else {
      // Create default user data
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

    await db.collection('users').doc(uid).set({
      settings: settings
    }, { merge: true });

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

    // Update stats
    const statsRef = db.collection('stats').doc(uid);
    const statsDoc = await statsRef.get();
    
    const count = Array.isArray(numbers) ? numbers.length : 1;
    
    if (!statsDoc.exists) {
      await statsRef.set({
        cdrs: category === 'cdrs' ? count : 0,
        imei: category === 'imei' ? count : 0,
        total: count
      });
    } else {
      const stats = statsDoc.data();
      const update = {};
      
      if (category === 'cdrs') {
        update.cdrs = (stats.cdrs || 0) + count;
      } else if (category === 'imei') {
        update.imei = (stats.imei || 0) + count;
      }
      
      update.total = (stats.total || 0) + count;
      
      await statsRef.update(update);
    }

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

// ==================== 5. GET HISTORY (FIXED) ====================
app.get('/api/history', authenticateToken, async (req, res) => {
  try {
    const uid = req.user.uid;
    const { category, limit = 50 } = req.query;

    // Without orderBy to avoid index error
    let query = db.collection('history').where('userId', '==', uid);
    
    if (category) {
      query = query.where('category', '==', category);
    }

    const snapshot = await query.get();
    
    // Manually sort by createdAt (descending)
    let history = [];
    snapshot.forEach(doc => {
      history.push({
        id: doc.id,
        ...doc.data(),
        createdAt: doc.data().createdAt?.toDate() || null
      });
    });
    
    // Sort by date (newest first)
    history.sort((a, b) => {
      if (!a.createdAt) return 1;
      if (!b.createdAt) return -1;
      return b.createdAt - a.createdAt;
    });
    
    // Apply limit after sorting
    history = history.slice(0, parseInt(limit));

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

    res.json(statsDoc.data());
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

    // Update stats before deleting
    const statsRef = db.collection('stats').doc(uid);
    const statsDoc = await statsRef.get();
    
    if (statsDoc.exists) {
      const stats = statsDoc.data();
      const count = Array.isArray(historyData.numbers) ? historyData.numbers.length : 1;
      const update = {};
      
      if (historyData.category === 'cdrs') {
        update.cdrs = Math.max(0, (stats.cdrs || 0) - count);
      } else if (historyData.category === 'imei') {
        update.imei = Math.max(0, (stats.imei || 0) - count);
      }
      
      update.total = Math.max(0, (stats.total || 0) - count);
      
      await statsRef.update(update);
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
    
    if (adminSecret !== 'your-admin-secret-123') {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const userRecord = await admin.auth().createUser({
      email,
      password,
    });

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
    
    if (adminSecret !== 'your-admin-secret-123') {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const userRecord = await admin.auth().getUserByEmail(email);
    
    await db.collection('users').doc(userRecord.uid).delete();
    await db.collection('stats').doc(userRecord.uid).delete();
    
    const historySnapshot = await db.collection('history')
      .where('userId', '==', userRecord.uid)
      .get();
    
    const batch = db.batch();
    historySnapshot.docs.forEach(doc => {
      batch.delete(doc.ref);
    });
    await batch.commit();

    await admin.auth().deleteUser(userRecord.uid);

    res.json({ success: true, message: 'User deleted completely' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ==================== START SERVER ====================
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

// Export for Vercel
module.exports = app;
