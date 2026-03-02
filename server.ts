import express from "express";
import { createServer as createViteServer } from "vite";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import cors from "cors";
import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";
import webpush from "web-push";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const db = new Database("users.db");
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

// Initialize database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    number TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    profession TEXT,
    gender TEXT,
    address TEXT,
    role TEXT DEFAULT 'user'
  );

  CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    contact TEXT,
    address TEXT,
    tags TEXT,
    status TEXT DEFAULT 'pending',
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(userId) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    category TEXT NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS push_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    subscription TEXT NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(userId) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

try {
  db.prepare("ALTER TABLE submissions ADD COLUMN tags TEXT").run();
} catch (err) {
  // Column might already exist
}

// Handle VAPID Keys
let VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || "";
let VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || "";

const initializeVapid = () => {
  try {
    if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
      const storedPublic = db.prepare("SELECT value FROM settings WHERE key = 'VAPID_PUBLIC_KEY'").get();
      const storedPrivate = db.prepare("SELECT value FROM settings WHERE key = 'VAPID_PRIVATE_KEY'").get();

      if (storedPublic && storedPrivate) {
        VAPID_PUBLIC_KEY = (storedPublic as any).value;
        VAPID_PRIVATE_KEY = (storedPrivate as any).value;
      } else {
        const keys = webpush.generateVAPIDKeys();
        VAPID_PUBLIC_KEY = keys.publicKey;
        VAPID_PRIVATE_KEY = keys.privateKey;
        db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").run('VAPID_PUBLIC_KEY', VAPID_PUBLIC_KEY);
        db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").run('VAPID_PRIVATE_KEY', VAPID_PRIVATE_KEY);
        console.log("Generated new VAPID keys and saved to database.");
      }
    }

    if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
      webpush.setVapidDetails(
        "mailto:thakurgaoncityapp@gmail.com",
        VAPID_PUBLIC_KEY,
        VAPID_PRIVATE_KEY
      );
      console.log("WebPush VAPID details set successfully.");
    }
  } catch (err: any) {
    console.error("WebPush setup failed:", err.message);
    if (err.message.includes("65 bytes long") || err.message.includes("invalid")) {
      console.log("Invalid VAPID keys detected. Clearing database settings and regenerating...");
      db.prepare("DELETE FROM settings WHERE key IN ('VAPID_PUBLIC_KEY', 'VAPID_PRIVATE_KEY')").run();
      VAPID_PUBLIC_KEY = "";
      VAPID_PRIVATE_KEY = "";
      // Retry once
      initializeVapid();
    }
  }
};

initializeVapid();

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.get("/api/health", (req, res) => {
    try {
      const userCount = db.prepare("SELECT COUNT(*) as count FROM users").get();
      db.prepare("BEGIN TRANSACTION").run();
      db.prepare("COMMIT").run();

      res.json({ 
        status: "ok", 
        time: new Date().toISOString(),
        database: "connected & writable",
        userCount: (userCount as any).count
      });
    } catch (err: any) {
      console.error("Health check failed:", err);
      res.status(500).json({ 
        status: "error", 
        database: "error",
        message: err.message 
      });
    }
  });

  app.use(express.json());
  app.use(cookieParser());
  app.use(cors({
    origin: (origin, callback) => {
      if (!origin || origin.endsWith(".run.app") || origin.endsWith(".netlify.app") || origin.includes("localhost") || origin.includes("127.0.0.1")) {
        callback(null, true);
      } else {
        callback(null, true);
      }
    },
    credentials: true
  }));

  // Auth Middleware
  const authenticate = (req: any, res: any, next: any) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      next();
    } catch (err) {
      res.status(401).json({ error: "Invalid token" });
    }
  };

  // Admin Middleware
  const isAdmin = (req: any, res: any, next: any) => {
    if (req.user?.role !== 'admin') return res.status(403).json({ error: "Forbidden" });
    next();
  };

  // Auth Routes
  app.post("/api/auth/signup", async (req, res) => {
    const { name, number, email, password, profession, gender, address } = req.body;
    try {
      const userCount: any = db.prepare("SELECT COUNT(*) as count FROM users").get();
      const role = userCount.count === 0 ? 'admin' : 'user';
      
      const hashedPassword = await bcrypt.hash(password, 10);
      const stmt = db.prepare("INSERT INTO users (name, number, email, password, profession, gender, address, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
      const result = stmt.run(name, number, email, hashedPassword, profession, gender, address, role);
      
      const token = jwt.sign({ id: result.lastInsertRowid, role }, JWT_SECRET);
      res.cookie("token", token, { httpOnly: true, secure: true, sameSite: 'none' });
      res.json({ success: true, user: { id: result.lastInsertRowid, name, role } });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body;
    console.log(`Login attempt for email: ${email}`);
    try {
      const user: any = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
      if (!user) {
        console.log(`Login failed: User not found for email ${email}`);
        return res.status(401).json({ error: "Invalid credentials" });
      }
      
      const isPasswordMatch = await bcrypt.compare(password, user.password);
      if (!isPasswordMatch) {
        console.log(`Login failed: Password mismatch for email ${email}`);
        return res.status(401).json({ error: "Invalid credentials" });
      }

      console.log(`Login successful for user: ${user.name} (ID: ${user.id})`);
      const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
      res.cookie("token", token, { httpOnly: true, secure: true, sameSite: 'none' });
      res.json({ success: true, user: { id: user.id, name: user.name, role: user.role } });
    } catch (err: any) {
      console.error(`Login error for email ${email}:`, err);
      res.status(400).json({ error: err.message });
    }
  });

  app.post("/api/auth/logout", (req, res) => {
    res.clearCookie("token");
    res.json({ success: true });
  });

  app.get("/api/user/me", authenticate, (req: any, res) => {
    const user = db.prepare("SELECT id, name, number, email, profession, gender, address, role FROM users WHERE id = ?").get(req.user.id);
    res.json(user);
  });

  app.put("/api/user/profile", authenticate, (req: any, res) => {
    const { name, profession, gender, number, address } = req.body;
    try {
      db.prepare("UPDATE users SET name = ?, profession = ?, gender = ?, number = ?, address = ? WHERE id = ?")
        .run(name, profession, gender, number, address, req.user.id);
      res.json({ success: true });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // Admin Routes
  app.get("/api/admin/users", authenticate, isAdmin, (req, res) => {
    const users = db.prepare("SELECT id, name, number, email, profession, gender, address, role FROM users").all();
    res.json(users);
  });

  // Submission Routes
  app.post("/api/submissions", authenticate, (req: any, res) => {
    const { category, title, description, contact, address, tags } = req.body;
    try {
      const stmt = db.prepare("INSERT INTO submissions (userId, category, title, description, contact, address, tags) VALUES (?, ?, ?, ?, ?, ?, ?)");
      stmt.run(req.user.id, category, title, description, contact, address, tags);
      res.json({ success: true });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.get("/api/user/submissions", authenticate, (req: any, res) => {
    const submissions = db.prepare("SELECT * FROM submissions WHERE userId = ? ORDER BY createdAt DESC").all(req.user.id);
    res.json(submissions);
  });

  app.get("/api/admin/submissions", authenticate, isAdmin, (req, res) => {
    const submissions = db.prepare(`
      SELECT s.*, u.name as userName 
      FROM submissions s 
      JOIN users u ON s.userId = u.id 
      ORDER BY s.createdAt DESC
    `).all();
    res.json(submissions);
  });

  app.put("/api/admin/submissions/:id/status", authenticate, isAdmin, (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    try {
      db.prepare("UPDATE submissions SET status = ? WHERE id = ?").run(status, id);
      res.json({ success: true });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.get("/api/items", (req, res) => {
    const { categoryId } = req.query;
    let query = "SELECT * FROM submissions WHERE status = 'approved'";
    let params: any[] = [];
    
    if (categoryId) {
      query += " AND category = ?";
      params.push(categoryId);
    }
    
    const items = db.prepare(query).all(...params);
    res.json(items);
  });

  // Announcement & Push Routes
  app.get("/api/announcements", (req, res) => {
    const announcements = db.prepare("SELECT * FROM announcements ORDER BY createdAt DESC LIMIT 10").all();
    res.json(announcements);
  });

  app.post("/api/admin/announcements", authenticate, isAdmin, async (req, res) => {
    const { title, message, category } = req.body;
    try {
      const stmt = db.prepare("INSERT INTO announcements (title, message, category) VALUES (?, ?, ?)");
      const result = stmt.run(title, message, category);
      
      // Send push notifications
      const subscriptions = db.prepare("SELECT subscription FROM push_subscriptions").all();
      const notificationPayload = JSON.stringify({
        title: `জরুরী: ${title}`,
        body: message,
        data: { url: "/" }
      });

      const pushPromises = subscriptions.map((sub: any) => {
        try {
          const subscription = JSON.parse(sub.subscription);
          return webpush.sendNotification(subscription, notificationPayload);
        } catch (err) {
          console.error("Push error:", err);
          return Promise.resolve();
        }
      });

      await Promise.allSettled(pushPromises);

      res.json({ success: true, id: result.lastInsertRowid });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.post("/api/notifications/subscribe", authenticate, (req: any, res) => {
    const { subscription } = req.body;
    try {
      const existing = db.prepare("SELECT id FROM push_subscriptions WHERE userId = ? AND subscription = ?").get(req.user.id, JSON.stringify(subscription));
      if (!existing) {
        db.prepare("INSERT INTO push_subscriptions (userId, subscription) VALUES (?, ?)")
          .run(req.user.id, JSON.stringify(subscription));
      }
      res.json({ success: true });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.get("/api/notifications/vapid-key", (req, res) => {
    res.json({ publicKey: VAPID_PUBLIC_KEY });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
