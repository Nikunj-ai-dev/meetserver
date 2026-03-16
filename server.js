const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg'); // Assuming PostgreSQL based on your RDS config

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// AWS RDS Connection
const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: 5432,
  ssl: { rejectUnauthorized: false }
});

// --- Auth Endpoints ---

// 1. Sync User (Called after Social Login)
app.post('/api/auth/sync', async (req, res) => {
  const { uid, email, displayName } = req.body;
  try {
    // Example: Upsert user into your RDS database
    await pool.query(
      'INSERT INTO users (firebase_uid, email, name) VALUES ($1, $2, $3) ON CONFLICT (firebase_uid) DO UPDATE SET last_login = NOW()',
      [uid, email, displayName]
    );
    res.json({ success: true, message: 'User synced with RDS' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database sync failed' });
  }
});

// 2. Send OTP (If you are using a custom service like Twilio or AWS SNS)
app.post('/api/auth/send-otp', async (req, res) => {
  const { phone } = req.body;
  try {
    // Logic to generate and send OTP via SMS provider
    console.log(`Sending OTP to ${phone}`);
    res.json({ success: true, message: 'OTP sent successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// 3. Login/Verify
app.post('/api/auth/login', async (req, res) => {
  // Logic to verify OTP or custom credentials
  res.json({ success: true, token: 'mock-jwt-token' });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
