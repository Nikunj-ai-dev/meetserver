import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import bcrypt from "bcrypt";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

/**
 * SUPABASE CONFIGURATION
 * Accessed via Supabase URL (derived from ID) and Anon Key
 */
const SUPABASE_URL = process.env.SUPABASE_URL || `https://${process.env.SUPABASE_ID}.supabase.co`;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

// Initialize Supabase client
// Note: On the backend, if you have RLS enabled, you might need the SERVICE_ROLE_KEY 
// instead of the ANON_KEY to perform admin actions like querying all users.
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY!);

/**
 * SMTP CONFIGURATION (Brevo)
 * All values moved to ENV variables as requested
 */
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_SERVER || "smtp-relay.brevo.com",
  port: parseInt(process.env.SMTP_PORT || "587"),
  auth: {
    user: process.env.SMTP_LOGIN,
    pass: process.env.SMTP_KEY,
  },
});

// In-memory OTP store
const otpStore = new Map<string, { otp: string; expires: number }>();

async function startServer() {
  app.use(cors());
  app.use(express.json());

  // AWS Health Check
  app.get("/health", (req, res) => res.status(200).send("OK"));

  /**
   * 1. SEND OTP
   */
  app.post("/api/auth/send-otp", async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore.set(email, { otp, expires: Date.now() + 600000 });

    try {
      await transporter.sendMail({
        from: `"Nexus Meet" <${process.env.SENDER_EMAIL}>`,
        to: email,
        subject: "Your Verification Code - Nexus Meet",
        html: `<div style="font-family: sans-serif; padding: 20px; text-align: center;">
                <h2 style="color: #4f46e5;">Nexus Meet</h2>
                <p>Your verification code is:</p>
                <div style="font-size: 32px; font-weight: bold; margin: 20px 0;">${otp}</div>
                <p>Expires in 10 minutes.</p>
              </div>`,
      });
      res.json({ success: true, message: "OTP sent" });
    } catch (err) {
      console.error("Email error:", err);
      res.status(500).json({ error: "Failed to send email" });
    }
  });

  /**
   * 2. SIGNUP / COMPLETE SOCIAL SIGNUP
   */
  app.post("/api/auth/signup", async (req, res) => {
    const { email, password, otp, provider = 'email' } = req.body;
    
    if (provider === 'email' && otp) {
      const stored = otpStore.get(email);
      if (!stored || stored.otp !== otp || stored.expires < Date.now()) {
        return res.status(400).json({ error: "Invalid or expired OTP" });
      }
      otpStore.delete(email);
    }

    try {
      const passwordHash = await bcrypt.hash(password, 10);
      const dbProvider = provider === 'google.com' ? 'google' : 'email';

      // Check if user exists
      const { data: existingUser } = await supabase
        .from('users')
        .select('*')
        .eq('email', email)
        .single();

      let userId;

      if (!existingUser) {
        // Create Org if none exists
        let { data: orgs } = await supabase.from('organizations').select('id').limit(1);
        let orgId = orgs?.[0]?.id;

        if (!orgId) {
          const { data: newOrg } = await supabase
            .from('organizations')
            .insert({ name: "My Workspace", billing_tier: "free" })
            .select()
            .single();
          orgId = newOrg?.id;
        }

        // Create User
        const { data: newUser, error: userErr } = await supabase
          .from('users')
          .insert({
            org_id: orgId,
            email,
            password_hash: passwordHash,
            auth_provider: dbProvider,
            is_verified: true,
            role: 'member'
          })
          .select()
          .single();
        
        if (userErr) throw userErr;
        userId = newUser.id;

        // Create Profile
        await supabase.from('user_profiles').insert({
          user_id: userId,
          display_name: email.split("@")[0]
        });
      } else {
        // Update existing user
        userId = existingUser.id;
        await supabase
          .from('users')
          .update({ password_hash: passwordHash, is_verified: true, auth_provider: dbProvider })
          .eq('id', userId);
      }

      res.json({ success: true, userId });
    } catch (err) {
      console.error("Signup error:", err);
      res.status(500).json({ error: "Signup failed" });
    }
  });

  /**
   * 3. LOGIN
   */
  app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body;
    try {
      const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('email', email)
        .single();

      if (error || !user) return res.status(401).json({ error: "Account not found" });

      const valid = await bcrypt.compare(password, user.password_hash);
      if (!valid) return res.status(401).json({ error: "Invalid password" });

      const { data: profile } = await supabase
        .from('user_profiles')
        .select('*')
        .eq('user_id', user.id)
        .single();
      
      res.json({ 
        success: true, 
        user: { id: user.id, email: user.email, displayName: profile?.display_name, orgId: user.org_id } 
      });
    } catch (err) {
      res.status(500).json({ error: "Login failed" });
    }
  });

  /**
   * 4. SOCIAL SYNC
   */
  app.post("/api/auth/sync", async (req, res) => {
    const { email, displayName, photoURL } = req.body;
    try {
      const { data: user } = await supabase.from('users').select('id').eq('email', email).single();
      
      if (!user) return res.json({ success: true, needsPassword: true });

      await supabase
        .from('user_profiles')
        .upsert({
          user_id: user.id,
          display_name: displayName,
          avatar_url: photoURL,
          updated_at: new Date().toISOString()
        }, { onConflict: 'user_id' });

      res.json({ success: true, userId: user.id });
    } catch (err) {
      res.status(500).json({ error: "Sync failed" });
    }
  });

  /**
   * VITE & STATIC SERVING
   */
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({ server: { middlewareMode: true }, appType: "spa" });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => res.sendFile(path.join(distPath, "index.html")));
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer();
