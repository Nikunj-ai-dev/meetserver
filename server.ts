import express from "express";
import cors from "cors";
import { Pool } from "pg";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import bcrypt from "bcrypt";

dotenv.config();

const app = express();
// Port 3000 is used to match your current App Runner and Docker configuration
const PORT = process.env.PORT || 3000;

// Database Connection for Supabase
// Use the Connection String details from your Supabase Project Settings -> Database
const pool = new Pool({
  host: process.env.DB_HOST || 'db.eslozrabziwinovsoaen.supabase.co',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'postgres',
  port: parseInt(process.env.DB_PORT || "5432"),
  // Supabase requires SSL for external connections
  ssl: { rejectUnauthorized: false }
});

// SMTP Transporter for OTP
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_SERVER,
  port: parseInt(process.env.SMTP_PORT || "587"),
  auth: {
    user: process.env.SMTP_LOGIN,
    pass: process.env.SMTP_KEY,
  },
});

app.use(cors());
app.use(express.json());

// --- AWS App Runner Health Check ---
// Essential to prevent "Health check failed" errors in App Runner
app.get("/", (req, res) => {
  res.status(200).send("Nexus Meet Server (Supabase) is Healthy");
});

const otpStore = new Map<string, { otp: string; expires: number }>();

// 1. Send OTP
app.post("/api/auth/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required" });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore.set(email, { otp, expires: Date.now() + 600000 });

  try {
    await transporter.sendMail({
      from: `"Nexus Meet" <${process.env.SENDER_EMAIL}>`,
      to: email,
      subject: "Your Verification Code",
      html: `<b>Your OTP is ${otp}</b><p>It expires in 10 minutes.</p>`,
    });
    res.json({ success: true, message: "OTP sent" });
  } catch (err) {
    console.error("Mail Error:", err);
    res.status(500).json({ error: "Failed to send email" });
  }
});

// 2. Signup / Set Password
app.post("/api/auth/signup", async (req, res) => {
  const { email, password, otp, provider = 'email' } = req.body;
  
  if (provider === 'email') {
    const stored = otpStore.get(email);
    if (!stored || stored.otp !== otp || stored.expires < Date.now()) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }
    otpStore.delete(email);
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const passwordHash = await bcrypt.hash(password, 10);
    
    let userRes = await client.query("SELECT id FROM users WHERE email = $1", [email]);
    let userId;

    if (userRes.rows.length === 0) {
      const newUser = await client.query(
        "INSERT INTO users (email, password_hash, auth_provider, is_verified) VALUES ($1, $2, $3, $4) RETURNING id",
        [email, passwordHash, provider, true]
      );
      userId = newUser.rows[0].id;
      await client.query("INSERT INTO user_profiles (user_id, display_name) VALUES ($1, $2)", [userId, email.split("@")[0]]);
    } else {
      userId = userRes.rows[0].id;
      await client.query("UPDATE users SET password_hash = $1 WHERE id = $2", [passwordHash, userId]);
    }

    await client.query("COMMIT");
    res.json({ success: true, userId });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Signup Error:", err);
    res.status(500).json({ error: "Signup failed" });
  } finally {
    client.release();
  }
});

// 3. Login
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userRes.rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });

    const user = userRes.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    const profileRes = await pool.query("SELECT * FROM user_profiles WHERE user_id = $1", [user.id]);
    res.json({ success: true, user: { ...user, profile: profileRes.rows[0] } });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// 4. Social Sync
app.post("/api/auth/sync", async (req, res) => {
  const { email, displayName, photoURL } = req.body;
  try {
    let userRes = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userRes.rows.length === 0) return res.json({ success: true, needsPassword: true });

    const userId = userRes.rows[0].id;
    await pool.query("UPDATE user_profiles SET display_name = $1, avatar_url = $2 WHERE user_id = $3", [displayName, photoURL, userId]);
    res.json({ success: true, userId });
  } catch (err) {
    console.error("Sync Error:", err);
    res.status(500).json({ error: "Sync failed" });
  }
});

// Prevent server crash on unhandled promise rejections
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
