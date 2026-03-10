const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();

// Initialize Firebase Admin SDK
const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL
});

const db = admin.firestore();
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: ['http://localhost:5500', 'http://127.0.0.1:5500', 'https://suspect-tracker.free.nf'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==================== MIDDLEWARE: Verify Token ====================
async function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  const token = authHeader.split('Bearer ')[1];
  
  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

// ==================== TEST ENDPOINT ====================
app.get('/api/test', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Backend is working!',
    timestamp: new Date().toISOString()
  });
});

// ==================== LOGIN ENDPOINT ====================
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and password are required' 
      });
    }

    // Firebase mein user check karo
    try {
      const userRecord = await admin.auth().getUserByEmail(email);
      
      // Password verify karne ke liye, frontend Firebase Auth use karega
      // Yahan sirf user exist karta hai ya nahi check karte hain
      // Actual password verification frontend Firebase Auth se hogi
      
      // Custom token banao for session
      const customToken = await admin.auth().createCustomToken(userRecord.uid);
      
      // User data bhejo
      res.json({
        success: true,
        message: 'Login successful',
        token: customToken,
        user: {
          uid: userRecord.uid,
          email: userRecord.email
        }
      });
    } catch (error) {
      if (error.code === 'auth/user-not-found') {
        return res.status(401).json({ 
          success: false, 
          message: 'Invalid email or password' 
        });
      }
      throw error;
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// ==================== VERIFY USER ENDPOINT ====================
app.post('/api/verify-user', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    
    // Check if user still exists in Firebase Auth
    try {
      await admin.auth().getUser(uid);
      res.json({ 
        success: true, 
        message: 'User is valid',
        user: req.user
      });
    } catch (error) {
      if (error.code === 'auth/user-not-found') {
        return res.status(401).json({ 
          success: false, 
          message: 'User no longer exists' 
        });
      }
      throw error;
    }
  } catch (error) {
    console.error('Verify user error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// ==================== SAVE USER PREFERENCES ====================
app.post('/api/save-user-data', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const preferences = req.body;
    
    // Required fields check
    if (!preferences) {
      return res.status(400).json({ 
        success: false, 
        message: 'Preferences data is required' 
      });
    }

    // Firestore mein save karo
    await db.collection('users').doc(uid).set({
      preferences: preferences,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    res.json({ 
      success: true, 
      message: 'Preferences saved successfully' 
    });
  } catch (error) {
    console.error('Save preferences error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// ==================== GET USER DATA (PREFERENCES + STATS) ====================
app.get('/api/get-user-data', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    
    // Get user preferences
    const userDoc = await db.collection('users').doc(uid).get();
    const userData = userDoc.exists ? userDoc.data() : {};
    
    // Get stats from history
    const historySnapshot = await db.collection('history')
      .where('userId', '==', uid)
      .get();
    
    let cdrsTotal = 0;
    let imeiTotal = 0;
    
    historySnapshot.forEach(doc => {
      const data = doc.data();
      if (data.category === 'CDRS') {
        cdrsTotal += (data.numbersCount || 0);
      } else if (data.category === 'IMEI') {
        imeiTotal += (data.numbersCount || 0);
      } else if (data.category === 'LOCATION') {
        // Location bhi CDRS mein add karo ya alag? Tumhari marzi
        cdrsTotal += (data.numbersCount || 0);
      } else if (data.category === 'SUB INFO') {
        cdrsTotal += (data.numbersCount || 0);
      } else if (data.category === 'GET CNIC') {
        // CNIC alag category hai
      }
    });

    res.json({
      success: true,
      preferences: userData.preferences || {},
      stats: {
        cdrsTotal,
        imeiTotal
      }
    });
  } catch (error) {
    console.error('Get user data error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// ==================== SUBMIT GENERATED DATA (SAVE TO HISTORY) ====================
app.post('/api/submit-data', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { 
      category,        // 'CDRS', 'IMEI', 'LOCATION', 'SUB INFO', 'GET CNIC'
      subCategory,     // 'jazz', 'zong', 'telenor', 'ufone', etc.
      numbers,         // Array of numbers/CNICs/IMEIs
      numbersCount,    // Total count
      generatedContent, // Full HTML content
      refNo,
      centerDo,
      toDate,
      dateAfterTrack,
      fir,
      us,
      ps,
      io,
      ioNo,
      divisionRo,
      divRef,
      divDate
    } = req.body;

    if (!category || !numbersCount) {
      return res.status(400).json({ 
        success: false, 
        message: 'Category and numbersCount are required' 
      });
    }

    // Create history entry
    const historyEntry = {
      userId: uid,
      category,
      subCategory: subCategory || 'general',
      numbers: numbers || [],
      numbersCount,
      generatedContent: generatedContent || '',
      refNo: refNo || '',
      centerDo: centerDo || '',
      toDate: toDate || '',
      dateAfterTrack: dateAfterTrack || '',
      fir: fir || '',
      us: us || '',
      ps: ps || '',
      io: io || '',
      ioNo: ioNo || '',
      divisionRo: divisionRo || '',
      divRef: divRef || '',
      divDate: divDate || '',
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    // Save to Firestore
    const docRef = await db.collection('history').add(historyEntry);

    res.json({
      success: true,
      message: 'Data saved to history',
      historyId: docRef.id
    });
  } catch (error) {
    console.error('Submit data error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// ==================== GET HISTORY ====================
app.get('/api/get-history', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { limit = 50, offset = 0 } = req.query;
    
    // Get user's history
    const historySnapshot = await db.collection('history')
      .where('userId', '==', uid)
      .orderBy('createdAt', 'desc')
      .limit(parseInt(limit))
      .get();
    
    const history = [];
    historySnapshot.forEach(doc => {
      const data = doc.data();
      history.push({
        id: doc.id,
        ...data,
        createdAt: data.createdAt ? data.createdAt.toDate().toISOString() : null
      });
    });

    res.json({
      success: true,
      history
    });
  } catch (error) {
    console.error('Get history error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// ==================== DELETE HISTORY ENTRY ====================
app.delete('/api/history/:id', verifyToken, async (req, res) => {
  try {
    const { uid } = req.user;
    const { id } = req.params;
    
    // Check if entry exists and belongs to user
    const docRef = db.collection('history').doc(id);
    const doc = await docRef.get();
    
    if (!doc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: 'History entry not found' 
      });
    }
    
    const data = doc.data();
    if (data.userId !== uid) {
      return res.status(403).json({ 
        success: false, 
        message: 'Unauthorized to delete this entry' 
      });
    }
    
    // Delete entry
    await docRef.delete();
    
    res.json({
      success: true,
      message: 'History entry deleted'
    });
  } catch (error) {
    console.error('Delete history error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    firebase: admin.apps.length > 0 ? 'connected' : 'disconnected'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    success: false, 
    message: 'Endpoint not found' 
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ 
    success: false, 
    message: 'Internal server error' 
  });
});

// Export for Vercel
module.exports = app;
