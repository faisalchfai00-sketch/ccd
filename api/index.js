const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware
app.use(cors({
    origin: ['http://localhost', 'http://127.0.0.1', 'https://suspect-tracker.free.nf'],
    credentials: true
}));
app.use(express.json());

// Firebase Admin Initialization
let serviceAccount;
try {
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
        serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    } else {
        // For local development
        serviceAccount = require('./service-account.json');
    }
} catch (error) {
    console.error('Error parsing service account:', error);
}

if (!admin.apps.length) {
    try {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount),
            databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`
        });
        console.log('Firebase Admin initialized successfully');
    } catch (error) {
        console.error('Firebase Admin initialization error:', error);
    }
}

const db = admin.firestore();
const auth = admin.auth();

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this';

// ==================== MIDDLEWARE ====================
const verifyToken = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Check if user still exists in Firebase
        try {
            const user = await auth.getUser(decoded.uid);
            req.user = { uid: user.uid, email: user.email };
            next();
        } catch (error) {
            // User no longer exists in Firebase
            return res.status(401).json({ error: 'User no longer exists' });
        }
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// ==================== AUTH ENDPOINTS ====================

// Login Endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }
        
        // Get user by email
        const userRecord = await auth.getUserByEmail(email);
        
        // Get custom password hash from Firestore (stored during user creation)
        const userDoc = await db.collection('users').doc(userRecord.uid).get();
        
        if (!userDoc.exists) {
            return res.status(401).json({ error: 'User not found' });
        }
        
        const userData = userDoc.data();
        
        // Verify password
        const isValidPassword = await bcrypt.compare(password, userData.passwordHash);
        
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid password' });
        }
        
        // Generate JWT token
        const token = jwt.sign(
            { uid: userRecord.uid, email: userRecord.email },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            token,
            user: {
                uid: userRecord.uid,
                email: userRecord.email
            }
        });
        
    } catch (error) {
        console.error('Login error:', error);
        
        if (error.code === 'auth/user-not-found') {
            return res.status(401).json({ error: 'User not found' });
        }
        
        res.status(500).json({ error: 'Login failed' });
    }
});

// Verify User Endpoint
app.post('/api/verify-user', verifyToken, async (req, res) => {
    try {
        // User already verified by middleware
        res.json({ 
            valid: true, 
            user: req.user 
        });
    } catch (error) {
        res.status(401).json({ valid: false });
    }
});

// ==================== USER DATA ENDPOINTS ====================

// Get User Data (Preferences + Stats)
app.get('/api/get-user-data', verifyToken, async (req, res) => {
    try {
        const userId = req.user.uid;
        
        // Get user preferences
        const userDoc = await db.collection('users').doc(userId).get();
        const userData = userDoc.exists ? userDoc.data() : {};
        
        // Get user history for stats
        const historySnapshot = await db.collection('users')
            .doc(userId)
            .collection('history')
            .get();
        
        const history = [];
        let cdrsCount = 0;
        let imeiCount = 0;
        
        historySnapshot.forEach(doc => {
            const data = doc.data();
            history.push({ id: doc.id, ...data });
            
            // Calculate stats
            if (data.category === 'CDRS') {
                cdrsCount += data.numbersCount || 0;
            } else if (data.category === 'IMEI') {
                imeiCount += data.numbersCount || 0;
            }
        });
        
        // Sort history by date (newest first)
        history.sort((a, b) => b.timestamp - a.timestamp);
        
        res.json({
            preferences: userData.preferences || {},
            stats: {
                cdrs: cdrsCount,
                imei: imeiCount
            },
            history: history.slice(0, 50) // Last 50 entries
        });
        
    } catch (error) {
        console.error('Get user data error:', error);
        res.status(500).json({ error: 'Failed to get user data' });
    }
});

// Save User Preferences
app.post('/api/save-preferences', verifyToken, async (req, res) => {
    try {
        const userId = req.user.uid;
        const preferences = req.body;
        
        // Validate preferences (basic)
        if (typeof preferences !== 'object') {
            return res.status(400).json({ error: 'Invalid preferences format' });
        }
        
        // Save to Firestore
        await db.collection('users').doc(userId).set({
            preferences: preferences,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
        
        res.json({ success: true, message: 'Preferences saved' });
        
    } catch (error) {
        console.error('Save preferences error:', error);
        res.status(500).json({ error: 'Failed to save preferences' });
    }
});

// ==================== HISTORY ENDPOINTS ====================

// Save Generated Data to History
app.post('/api/save-to-history', verifyToken, async (req, res) => {
    try {
        const userId = req.user.uid;
        const { 
            category,        // 'CDRS', 'IMEI', 'LOCATION', 'SUB INFO', 'GET CNIC'
            subCategory,     // 'Jazz', 'Zong', 'Telenor', 'Ufone', etc.
            numbers,         // Array of numbers/IMEIs/CNICs
            numbersCount,    // Total count
            generatedContent, // The full generated HTML/text
            refNo,
            centerDo,
            fir,
            us,
            ps,
            io,
            ioNo,
            divisionRo,
            divRef,
            divDate,
            refDate,
            toDate,
            dateAfterTrack
        } = req.body;
        
        if (!category || !numbersCount) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        // Create history entry
        const historyEntry = {
            category,
            subCategory: subCategory || '',
            numbers: numbers || [],
            numbersCount,
            generatedContent: generatedContent || '',
            refNo: refNo || '',
            centerDo: centerDo || '',
            fir: fir || '',
            us: us || '',
            ps: ps || '',
            io: io || '',
            ioNo: ioNo || '',
            divisionRo: divisionRo || '',
            divRef: divRef || '',
            divDate: divDate || '',
            refDate: refDate || '',
            toDate: toDate || '',
            dateAfterTrack: dateAfterTrack || '',
            timestamp: Date.now(),
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };
        
        // Save to user's history subcollection
        const historyRef = await db.collection('users')
            .doc(userId)
            .collection('history')
            .add(historyEntry);
        
        res.json({ 
            success: true, 
            historyId: historyRef.id,
            message: 'Saved to history' 
        });
        
    } catch (error) {
        console.error('Save to history error:', error);
        res.status(500).json({ error: 'Failed to save to history' });
    }
});

// Get History (with pagination)
app.get('/api/get-history', verifyToken, async (req, res) => {
    try {
        const userId = req.user.uid;
        const { limit = 50, startAfter } = req.query;
        
        let query = db.collection('users')
            .doc(userId)
            .collection('history')
            .orderBy('timestamp', 'desc')
            .limit(parseInt(limit));
        
        if (startAfter) {
            const startAfterDoc = await db.collection('users')
                .doc(userId)
                .collection('history')
                .doc(startAfter)
                .get();
            
            if (startAfterDoc.exists) {
                query = query.startAfter(startAfterDoc);
            }
        }
        
        const snapshot = await query.get();
        
        const history = [];
        snapshot.forEach(doc => {
            history.push({
                id: doc.id,
                ...doc.data()
            });
        });
        
        res.json({ history });
        
    } catch (error) {
        console.error('Get history error:', error);
        res.status(500).json({ error: 'Failed to get history' });
    }
});

// Get Single History Entry
app.get('/api/get-history/:id', verifyToken, async (req, res) => {
    try {
        const userId = req.user.uid;
        const historyId = req.params.id;
        
        const doc = await db.collection('users')
            .doc(userId)
            .collection('history')
            .doc(historyId)
            .get();
        
        if (!doc.exists) {
            return res.status(404).json({ error: 'History entry not found' });
        }
        
        res.json({
            id: doc.id,
            ...doc.data()
        });
        
    } catch (error) {
        console.error('Get history entry error:', error);
        res.status(500).json({ error: 'Failed to get history entry' });
    }
});

// Delete History Entry
app.delete('/api/delete-history/:id', verifyToken, async (req, res) => {
    try {
        const userId = req.user.uid;
        const historyId = req.params.id;
        
        await db.collection('users')
            .doc(userId)
            .collection('history')
            .doc(historyId)
            .delete();
        
        res.json({ success: true, message: 'History entry deleted' });
        
    } catch (error) {
        console.error('Delete history error:', error);
        res.status(500).json({ error: 'Failed to delete history' });
    }
});

// ==================== ADMIN ENDPOINTS (For Firebase Console Alternative) ====================

// Create User (Admin only - but we'll keep it simple)
app.post('/api/admin/create-user', async (req, res) => {
    try {
        const { email, password, createdBy } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }
        
        // Create user in Firebase Auth
        const userRecord = await auth.createUser({
            email,
            password,
            emailVerified: false
        });
        
        // Hash password for our own verification
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        
        // Save user data in Firestore
        await db.collection('users').doc(userRecord.uid).set({
            email,
            passwordHash,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            createdBy: createdBy || 'admin',
            preferences: {}
        });
        
        res.json({ 
            success: true, 
            uid: userRecord.uid,
            message: 'User created successfully' 
        });
        
    } catch (error) {
        console.error('Create user error:', error);
        
        if (error.code === 'auth/email-already-exists') {
            return res.status(400).json({ error: 'Email already exists' });
        }
        
        res.status(500).json({ error: 'Failed to create user' });
    }
});

// Delete User (Admin only)
app.post('/api/admin/delete-user', async (req, res) => {
    try {
        const { uid } = req.body;
        
        if (!uid) {
            return res.status(400).json({ error: 'User ID required' });
        }
        
        // Delete from Firebase Auth
        await auth.deleteUser(uid);
        
        // Delete from Firestore
        await db.collection('users').doc(uid).delete();
        
        // Delete all history (Firestore collection deletion is recursive)
        const historySnapshot = await db.collection('users')
            .doc(uid)
            .collection('history')
            .get();
        
        const batch = db.batch();
        historySnapshot.forEach(doc => {
            batch.delete(doc.ref);
        });
        await batch.commit();
        
        res.json({ success: true, message: 'User deleted successfully' });
        
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// List Users (Admin only)
app.get('/api/admin/list-users', async (req, res) => {
    try {
        const usersSnapshot = await db.collection('users').get();
        
        const users = [];
        usersSnapshot.forEach(doc => {
            const data = doc.data();
            users.push({
                uid: doc.id,
                email: data.email,
                createdAt: data.createdAt,
                preferences: data.preferences
            });
        });
        
        res.json({ users });
        
    } catch (error) {
        console.error('List users error:', error);
        res.status(500).json({ error: 'Failed to list users' });
    }
});

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: Date.now(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// ==================== ERROR HANDLING ====================

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// ==================== EXPORT ====================

module.exports = app;
