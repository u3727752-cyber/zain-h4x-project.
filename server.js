const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Admin Password for managing keys
const ADMIN_SECRET = "MY_ADMIN_SECRET_123";

// In-Memory Key Database
let apiKeys = {
    "ZAIN-KEY-1234": {
        status: "active",
        expiresAt: "2026-12-31T23:59:59Z",
        createdAt: new Date().toISOString()
    }
};

// Application Configuration
let appConfig = {
    HS_NECK: false,
    HS_CHEST: false,
    BYPASSV1: false,
    BACKJUMPV1: false,
    HIGH_SENSI: false,
    SPEED_HACK: false,
    SPEED_VALUE: 3.0
};

// Utility: Generate Unique Random Key
function generateRandomKey(prefix = "INRIH4X") {
    const randomHex = crypto.randomBytes(4).toString('hex').toUpperCase();
    return `${prefix}-${randomHex}`;
}

// Middleware: Verify API Key Status & Expiry
function verifyKey(req, res, next) {
    const userKey = req.headers['x-api-key'] || req.query.key || req.body.key;

    if (!userKey) {
        return res.status(401).json({ success: false, message: "API key is required" });
    }

    const keyData = apiKeys[userKey];

    if (!keyData) {
        return res.status(403).json({ success: false, message: "Invalid API key" });
    }

    if (keyData.status === 'suspended') {
        return res.status(403).json({ success: false, message: "Your key has been suspended" });
    }

    const now = new Date();
    const expiry = new Date(keyData.expiresAt);

    if (now > expiry || keyData.status === 'expired') {
        keyData.status = 'expired';
        return res.status(403).json({ success: false, message: "API key has expired" });
    }

    req.keyData = keyData;
    next();
}

// API: Check IP
app.get('/api/ip/check', (req, res) => {
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    res.json({ ip: clientIp });
});

// API: Verify Key Status
app.post('/api/key/verify', verifyKey, (req, res) => {
    res.json({
        success: true,
        message: "Key authorized",
        expiresAt: req.keyData.expiresAt,
        status: req.keyData.status
    });
});

// ADMIN API: Generate New Key
// Body parameters: adminSecret, daysValid (number), customPrefix (optional)
app.post('/api/admin/generate-key', (req, res) => {
    const { adminSecret, daysValid = 30, customPrefix = "ZAIN" } = req.body;

    if (adminSecret !== ADMIN_SECRET) {
        return res.status(401).json({ success: false, message: "Unauthorized admin access" });
    }

    const newKey = generateRandomKey(customPrefix);
    
    // Calculate Expiration Date
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + parseInt(daysValid));

    apiKeys[newKey] = {
        status: "active",
        expiresAt: expiryDate.toISOString(),
        createdAt: new Date().toISOString()
    };

    console.log(`[KEY GENERATED] ${newKey} valid for ${daysValid} days.`);

    res.json({
        success: true,
        key: newKey,
        status: "active",
        expiresAt: apiKeys[newKey].expiresAt
    });
});

// ADMIN API: Control Keys (Suspend, Activate, Extend)
app.post('/api/admin/key-control', (req, res) => {
    const { adminSecret, targetKey, action, newExpiry } = req.body;

    if (adminSecret !== ADMIN_SECRET) {
        return res.status(401).json({ success: false, message: "Unauthorized admin access" });
    }

    if (!apiKeys[targetKey]) {
        return res.status(404).json({ success: false, message: "Key not found" });
    }

    if (action === "suspend") {
        apiKeys[targetKey].status = "suspended";
    } else if (action === "activate") {
        apiKeys[targetKey].status = "active";
    } else if (action === "extend" && newExpiry) {
        apiKeys[targetKey].expiresAt = newExpiry;
        apiKeys[targetKey].status = "active";
    }

    res.json({ success: true, message: `Key ${targetKey} set to ${action}`, keyData: apiKeys[targetKey] });
});

// API: Get Config (Protected)
app.get('/api/config', verifyKey, (req, res) => {
    res.json({ config: appConfig });
});

// API: Toggle Features (Protected)
app.post('/api/toggle', verifyKey, (req, res) => {
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
        if (feature === 'hs_neck' && value === true) appConfig.HS_CHEST = false;
        if (feature === 'hs_chest' && value === true) appConfig.HS_NECK = false;
        return res.json({ success: true, config: appConfig });
    }

    res.status(400).json({ success: false, message: 'Invalid feature' });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
