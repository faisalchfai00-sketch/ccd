const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

// Middleware
app.use(cors({
    origin: ['http://localhost', 'http://suspect-tracker.free.nf', 'https://suspect-tracker.free.nf'],
    credentials: true
}));
app.use(express.json());

// Initialize Firebase Admin SDK
try {
    const serviceAccount = {
        type: "service_account",
        project_id: process.env.FIREBASE_PROJECT_ID,
        private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
        private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
        client_email: process.env.FIREBASE_CLIENT_EMAIL,
        client_id: process.env.FIREBASE_CLIENT_ID,
        auth_uri: "https://accounts.google.com/o/oauth2/auth",
        token_uri: "https://oauth2.googleapis.com/token",
        auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
        client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL
    };

    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        databaseURL: `https://${process.env.FIREBASE_PROJECT_ID}.firebaseio.com`
    });
    
    console.log('Firebase Admin initialized successfully');
} catch (error) {
    console.error('Firebase Admin initialization error:', error);
}

const db = admin.firestore();

// ==================== MIDDLEWARE ====================
// Verify user token and check if user exists
async function verifyUser(req, res, next) {
    try {
        const token = req.headers.authorization?.split('Bearer ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        // Verify the token
        const decodedToken = await admin.auth().verifyIdToken(token);
        
        // Check if user still exists
        try {
            await admin.auth().getUser(decodedToken.uid);
        } catch (error) {
            return res.status(401).json({ error: 'User no longer exists' });
        }

        req.user = decodedToken;
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// ==================== AUTH ENDPOINTS ====================

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        // Firebase Admin SDK doesn't have a direct sign-in method
        // We'll use the REST API for this
        const apiKey = process.env.FIREBASE_API_KEY;
        const response = await fetch(
            `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email,
                    password,
                    returnSecureToken: true
                })
            }
        );

        const data = await response.json();

        if (!response.ok) {
            return res.status(401).json({ error: data.error?.message || 'Invalid credentials' });
        }

        // Return the ID token
        res.json({
            token: data.idToken,
            refreshToken: data.refreshToken,
            expiresIn: data.expiresIn,
            email: data.email,
            localId: data.localId
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Verify user endpoint
app.post('/api/verify-user', async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({ error: 'Token required' });
        }

        const decodedToken = await admin.auth().verifyIdToken(token);
        
        // Check if user exists
        try {
            await admin.auth().getUser(decodedToken.uid);
            res.json({ valid: true, user: decodedToken });
        } catch (error) {
            res.json({ valid: false, error: 'User not found' });
        }

    } catch (error) {
        console.error('Verify user error:', error);
        res.status(401).json({ valid: false, error: 'Invalid token' });
    }
});

// ==================== USER DATA ENDPOINTS ====================

// Get user data (preferences + history summary for dashboard)
app.get('/api/get-user-data', verifyUser, async (req, res) => {
    try {
        const userId = req.user.uid;
        
        // Get user preferences
        const prefsDoc = await db.collection('users').doc(userId).collection('data').doc('preferences').get();
        const preferences = prefsDoc.exists ? prefsDoc.data() : {};
        
        // Get stats for dashboard
        const historySnapshot = await db.collection('users').doc(userId).collection('history').get();
        
        let cdrsCount = 0;
        let imeiCount = 0;
        
        historySnapshot.forEach(doc => {
            const data = doc.data();
            if (data.category === 'CDRS') {
                cdrsCount += data.numbersCount || 0;
            } else if (data.category === 'IMEI') {
                imeiCount += data.numbersCount || 0;
            }
        });
        
        res.json({
            preferences,
            stats: {
                cdrs: cdrsCount,
                imei: imeiCount
            }
        });

    } catch (error) {
        console.error('Get user data error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Save user preferences
app.post('/api/save-user-data', verifyUser, async (req, res) => {
    try {
        const userId = req.user.uid;
        const preferences = req.body;

        // Remove any invalid fields
        delete preferences.userId;
        delete preferences.token;

        await db.collection('users').doc(userId).collection('data').doc('preferences').set(preferences, { merge: true });

        res.json({ success: true, message: 'Preferences saved successfully' });

    } catch (error) {
        console.error('Save user data error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Submit generated data (save to history)
app.post('/api/submit-data', verifyUser, async (req, res) => {
    try {
        const userId = req.user.uid;
        const { 
            category,          // 'CDRS', 'IMEI', 'LOCATION', 'SUB INFO', 'GET CNIC'
            subCategory,       // 'Jazz', 'Zong', 'Telenor', 'Ufone', etc.
            numbersCount,      // Kitne numbers/IMEIs/CNICs use hue
            generatedContent,  // Pura generated HTML content
            refNo,            // Reference number used
            centerDo,         // Center/DO used
            fir,              // FIR used
            us,               // US used
            ps,               // PS used
            io,               // IO used
            ioNo,             // IO No used
            divisionRo,       // Division/RO used
            divRef,           // Div Ref used
            divDate,          // Div Date used
            dateAfterTrack,   // Date After Track (agar use hua)
            toDate            // TO Date (agar use hua)
        } = req.body;

        if (!category || !numbersCount) {
            return res.status(400).json({ error: 'Category and numbersCount required' });
        }

        const historyEntry = {
            category,
            subCategory: subCategory || 'General',
            numbersCount,
            generatedContent,
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
            dateAfterTrack: dateAfterTrack || '',
            toDate: toDate || '',
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            date: new Date().toISOString().split('T')[0] // YYYY-MM-DD for easy filtering
        };

        const docRef = await db.collection('users').doc(userId).collection('history').add(historyEntry);

        res.json({ 
            success: true, 
            id: docRef.id,
            message: 'Data saved to history' 
        });

    } catch (error) {
        console.error('Submit data error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get complete history
app.post('/api/get-history', verifyUser, async (req, res) => {
    try {
        const userId = req.user.uid;
        const { limit = 100, startDate, endDate } = req.body;

        let query = db.collection('users').doc(userId).collection('history')
            .orderBy('timestamp', 'desc')
            .limit(limit);

        if (startDate) {
            query = query.where('date', '>=', startDate);
        }
        if (endDate) {
            query = query.where('date', '<=', endDate);
        }

        const snapshot = await query.get();
        
        const history = [];
        snapshot.forEach(doc => {
            history.push({
                id: doc.id,
                ...doc.data(),
                timestamp: doc.data().timestamp?.toDate() || new Date()
            });
        });

        res.json({ history });

    } catch (error) {
        console.error('Get history error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete specific history entry
app.delete('/api/delete-history/:id', verifyUser, async (req, res) => {
    try {
        const userId = req.user.uid;
        const entryId = req.params.id;

        await db.collection('users').doc(userId).collection('history').doc(entryId).delete();

        res.json({ success: true, message: 'History entry deleted' });

    } catch (error) {
        console.error('Delete history error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ==================== TEST ENDPOINT ====================
app.get('/api/test', (req, res) => {
    res.json({ message: 'Backend is working!' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

module.exports = app;
