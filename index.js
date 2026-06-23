const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'ryoiki-super-secret-key-123!';

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Initialize uploads folder
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// Setup SQLite Database
const db = new sqlite3.Database('./ryoiki.db', (err) => {
    if (err) console.error(err.message);
    else console.log('Connected to the SQLite database.');
});

// Create tables
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        uuid TEXT PRIMARY KEY,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        skin_url TEXT,
        cosmetics TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS otps (
        email TEXT PRIMARY KEY,
        otp TEXT,
        username TEXT,
        password TEXT,
        expires_at INTEGER
    )`);
});

// --- ROUTES ---

// 1. Register - Sends OTP
app.post('/api/auth/register', (req, res) => {
    const { email, username, password } = req.body;
    if (!email || !username || !password) return res.status(400).json({ error: 'Missing fields' });

    db.get(`SELECT email, username FROM users WHERE email = ? OR username = ?`, [email, username], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (row) return res.status(400).json({ error: 'Email or Username already exists' });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = Date.now() + 10 * 60 * 1000; // 10 mins

        bcrypt.hash(password, 10, (err, hash) => {
            if (err) return res.status(500).json({ error: 'Hashing error' });
            
            db.run(`INSERT OR REPLACE INTO otps (email, otp, username, password, expires_at) VALUES (?, ?, ?, ?, ?)`,
                [email, otp, username, hash, expiresAt], (err) => {
                    if (err) return res.status(500).json({ error: err.message });
                    
                    // In a real app, use nodemailer here. For local testing, log it:
                    console.log(`\n================================`);
                    console.log(`[Ryoiki Auth] OTP for ${email}: ${otp}`);
                    console.log(`================================\n`);

                    res.json({ message: 'OTP sent to email. Please verify.', email });
            });
        });
    });
});

// 2. Verify OTP & Create Account
app.post('/api/auth/verify', (req, res) => {
    const { email, otp } = req.body;

    db.get(`SELECT * FROM otps WHERE email = ?`, [email], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(400).json({ error: 'No OTP requested for this email' });
        
        if (Date.now() > row.expires_at) return res.status(400).json({ error: 'OTP expired' });
        if (row.otp !== otp) return res.status(400).json({ error: 'Invalid OTP' });

        // OTP is valid! Create user.
        const uuid = uuidv4().replace(/-/g, ''); // Minecraft UUIDs are usually 32 hex chars
        
        db.run(`INSERT INTO users (uuid, username, email, password, skin_url, cosmetics) VALUES (?, ?, ?, ?, ?, ?)`,
            [uuid, row.username, row.email, row.password, '', '[]'], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                
                // Cleanup OTP
                db.run(`DELETE FROM otps WHERE email = ?`, [email]);

                const token = jwt.sign({ uuid, username: row.username }, JWT_SECRET, { expiresIn: '30d' });
                res.json({ message: 'Account created successfully', token, uuid, username: row.username });
        });
    });
});

// 3. Login
app.post('/api/auth/login', (req, res) => {
    const { identifier, password } = req.body; // identifier can be email or username
    if (!identifier || !password) return res.status(400).json({ error: 'Missing fields' });

    db.get(`SELECT * FROM users WHERE email = ? OR username = ?`, [identifier, identifier], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(400).json({ error: 'Invalid credentials' });

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).json({ error: err.message });
            if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

            const token = jwt.sign({ uuid: user.uuid, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
            res.json({ message: 'Login successful', token, uuid: user.uuid, username: user.username });
        });
    });
});

// --- AUTH MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// 4. Get User Profile (Public Endpoint for Game Client)
app.get('/api/profile/:uuid', (req, res) => {
    const { uuid } = req.params;
    db.get(`SELECT username, skin_url, cosmetics FROM users WHERE uuid = ?`, [uuid], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        res.json({
            username: user.username,
            skin_url: user.skin_url,
            cosmetics: JSON.parse(user.cosmetics)
        });
    });
});

// 5. Upload Custom Skin
const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        cb(null, req.user.uuid + '.png'); // Always overwrite the user's single skin
    }
});
const upload = multer({ storage });

app.post('/api/profile/skin', authenticateToken, upload.single('skin'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const baseUrl = process.env.API_URL || `http://localhost:${PORT}`;
    const skinUrl = `${baseUrl}/uploads/${req.file.filename}?t=${Date.now()}`;
    db.run(`UPDATE users SET skin_url = ? WHERE uuid = ?`, [skinUrl, req.user.uuid], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Skin updated successfully', skinUrl });
    });
});

// 6. Get All Cosmetics (For Game Client Sync)
app.get('/api/cosmetics', (req, res) => {
    db.all(`SELECT uuid, cosmetics FROM users WHERE cosmetics != '[]'`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const allCosmetics = {};
        rows.forEach(row => {
            try {
                // Return in format expected by Client: { "uuid": { cape: "...", bandana: "..." } }
                const list = JSON.parse(row.cosmetics);
                const obj = {};
                list.forEach(c => {
                    if(c.includes("cape_")) obj.cape = c.replace("cape_", "");
                    else if(c.includes("wings_")) obj.wings = c.replace("wings_", "");
                    else if(c.includes("bandana_")) obj.bandana = c.replace("bandana_", "");
                });
                if(Object.keys(obj).length > 0) allCosmetics[row.uuid] = obj;
            } catch (e) {}
        });
        res.json(allCosmetics);
    });
});

// 7. Upload Cosmetics (From Game Client)
app.post('/api/cosmetics', (req, res) => {
    const { uuid, token, cape, bandana, wings, hat, pet } = req.body;
    // VERY simple auth for the client
    if (!uuid) return res.status(400).json({ error: 'Missing uuid' });
    
    const cosmeticsList = [];
    if(cape && cape !== 'none') cosmeticsList.push("cape_" + cape);
    if(bandana && bandana !== 'none') cosmeticsList.push("bandana_" + bandana);
    if(wings && wings !== 'none') cosmeticsList.push("wings_" + wings);

    db.run(`UPDATE users SET cosmetics = ? WHERE uuid = ?`, [JSON.stringify(cosmeticsList), uuid], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Cosmetics updated' });
    });
});

app.listen(PORT, () => {
    console.log(`Ryoiki Backend running on http://localhost:${PORT}`);
});
