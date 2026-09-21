const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Master Admin Key (Used to generate new access keys)
const MASTER_ADMIN_KEY = process.env.ADMIN_KEY || "ADMIN_SECRET_KEY_999";

// In-memory key store for active keys and expiration timestamps
const activeKeys = new Map();

// In-memory session store for authorized sessions
const validSessions = new Set();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Application state store
let appConfig = {
    HS_NECK: false,
    HS_CHEST: false,
    BYPASSV1: false,
    BACKJUMPV1: false,
    HIGH_SENSI: false,
    SPEED_HACK: false,
    SPEED_VALUE: 3.0
};

// --- AUTHENTICATION MIDDLEWARE ---
const requireAuth = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || !validSessions.has(authHeader)) {
        return res.status(401).json({ success: false, message: 'Unauthorized: Invalid or expired session' });
    }
    
    next();
};

// --- ADMIN ROUTES ---

// POST /api/admin/generate-key
// Generate new access keys with custom expiration (in days)
app.post('/api/admin/generate-key', (req, res) => {
    const { adminKey, days } = req.body;

    if (adminKey !== MASTER_ADMIN_KEY) {
        return res.status(403).json({ success: false, message: 'Unauthorized Admin Request' });
    }

    const validityDays = parseFloat(days) || 1;
    const key = 'ZAIN-' + crypto.randomBytes(8).toString('hex').toUpperCase();
    const expiresAt = Date.now() + (validityDays * 24 * 60 * 60 * 1000);
    
    activeKeys.set(key, expiresAt);

    const expiryDate = new Date(expiresAt).toISOString();
    console.log(`[KEY CREATED] Key: ${key} | Valid for: ${validityDays} days | Expires: ${expiryDate}`);

    res.json({
        success: true,
        key: key,
        validityDays: validityDays,
        expiresAt: expiryDate
    });
});

// --- PUBLIC ROUTES ---

// GET /api/ip/check
// Get client IP address
app.get('/api/ip/check', (req, res) => {
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    const ip = clientIp.includes('::ffff:') ? clientIp.split('::ffff:')[1] : clientIp;
    res.json({ ip: ip });
});

// POST /api/login
// Verify access key and issue session token
app.post('/api/login', (req, res) => {
    const { key } = req.body;

    if (!key) {
        return res.status(400).json({ success: false, message: 'Access key required' });
    }

    if (!activeKeys.has(key)) {
        return res.status(401).json({ success: false, message: 'Invalid Access Key' });
    }

    const expiresAt = activeKeys.get(key);

    if (Date.now() > expiresAt) {
        activeKeys.delete(key);
        console.log(`[AUTH EXPIRED] Key attempted: ${key}`);
        return res.status(401).json({ success: false, message: 'Access Key has expired' });
    }

    const token = 'session_' + crypto.randomBytes(16).toString('hex');
    validSessions.add(token);

    console.log(`[AUTH SUCCESS] Key ${key} logged in. Session: ${token}`);
    return res.json({ 
        success: true, 
        token: token, 
        expiresAt: new Date(expiresAt).toISOString(),
        message: 'Key accepted' 
    });
});

// --- PROTECTED ROUTES ---

// GET /api/config
// Fetch current settings
app.get('/api/config', requireAuth, (req, res) => {
    res.json({ config: appConfig });
});

// POST /api/toggle
// Update settings and features
app.post('/api/toggle', requireAuth, (req, res) => {
    const { feature, value } = req.body;

    if (!feature) {
        return res.status(400).json({ success: false, message: 'Feature name required' });
    }

    const featureMap = {
        'hs_neck': 'HS_NECK',
        'hs_chest': 'HS_CHEST',
        'bypass_v1': 'BYPASSV1',
        'backjump_v1': 'BACKJUMPV1',
        'high_sensi': 'HIGH_SENSI',
        'speed_hack': 'SPEED_HACK',
        'speed_value': 'SPEED_VALUE'
    };

    const targetKey = featureMap[feature];

    if (targetKey) {
        appConfig[targetKey] = value;

        // Mutual exclusion logic for HS_NECK and HS_CHEST
        if (feature === 'hs_neck' && value === true) {
            appConfig.HS_CHEST = false;
        } else if (feature === 'hs_chest' && value === true) {
            appConfig.HS_NECK = false;
        }

        console.log(`[CONFIG UPDATE] ${targetKey} set to: ${value}`);
        return res.json({ success: true, config: appConfig });
    }

    res.status(400).json({ success: false, message: 'Invalid feature key' });
});

// Fallback route to serve main page
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Master Admin Key: ${MASTER_ADMIN_KEY}`);
}); ${MASTER_ADMIN_KEY}`);
});