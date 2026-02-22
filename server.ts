import express from "express";
import { createServer as createViteServer } from "vite";
import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import multer from "multer";
import { v4 as uuidv4 } from "uuid";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const db = new Database("legacy_lock.db");
const JWT_SECRET = process.env.JWT_SECRET || "legacy-lock-super-secret-key";

// Ensure ENCRYPTION_KEY is exactly 32 bytes for AES-256
const rawKey = process.env.ENCRYPTION_KEY || "legacy-lock-default-secret-key-32";
const ENCRYPTION_KEY = crypto.createHash('sha256').update(rawKey).digest();
const IV_LENGTH = 16;

// Ensure uploads directory exists
const UPLOADS_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR);
}

// Initialize Database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    password TEXT,
    name TEXT,
    country TEXT DEFAULT 'United States',
    vault_key TEXT, -- User-specific encryption key
    escalation_stage TEXT DEFAULT 'Normal', -- Normal, Reminder, Wellness, Circle, Activation
    escalation_config TEXT, -- JSON: { reminderDays: 7, wellnessDays: 14, circleDays: 21, activationDays: 30 }
    last_check_in DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'active'
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    title TEXT,
    message TEXT,
    type TEXT, -- info, warning, alert
    is_read INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS sections (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    name TEXT,
    icon TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    section_id TEXT,
    user_id TEXT,
    beneficiary_id TEXT, -- Linked to trusted_contacts
    title TEXT,
    file_name TEXT,
    file_type TEXT,
    priority TEXT DEFAULT 'Medium',
    notes TEXT,
    version_count INTEGER DEFAULT 1,
    integrity_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(section_id) REFERENCES sections(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(beneficiary_id) REFERENCES trusted_contacts(id)
  );

  CREATE TABLE IF NOT EXISTS document_versions (
    id TEXT PRIMARY KEY,
    document_id TEXT,
    file_name TEXT,
    version_number INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(document_id) REFERENCES documents(id)
  );

  CREATE TABLE IF NOT EXISTS trusted_contacts (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    name TEXT,
    email TEXT,
    relationship TEXT,
    access_code TEXT,
    password TEXT,
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS legacy_messages (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    recipient_id TEXT,
    category TEXT, -- Celebration, Guidance, Milestone, Reflection
    type TEXT, -- Text, Audio, Video
    content TEXT,
    release_event TEXT, -- Birthday, Graduation, etc.
    status TEXT DEFAULT 'scheduled',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(recipient_id) REFERENCES trusted_contacts(id)
  );

  CREATE TABLE IF NOT EXISTS confidential_links (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    beneficiary_id TEXT,
    title TEXT,
    username TEXT,
    password TEXT,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(beneficiary_id) REFERENCES trusted_contacts(id)
  );

  CREATE TABLE IF NOT EXISTS blockchain_proofs (
    id TEXT PRIMARY KEY,
    document_id TEXT,
    hash TEXT,
    tx_id TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(document_id) REFERENCES documents(id)
  );

  CREATE TABLE IF NOT EXISTS death_verifications (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    beneficiary_id TEXT,
    file_name TEXT,
    status TEXT DEFAULT 'pending', -- pending, verified, rejected
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(beneficiary_id) REFERENCES trusted_contacts(id)
  );

  CREATE TABLE IF NOT EXISTS system_logs (
    id TEXT PRIMARY KEY,
    type TEXT,
    recipient TEXT,
    subject TEXT,
    body TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Migration: Add access_code to trusted_contacts if it doesn't exist
try {
  db.prepare("ALTER TABLE trusted_contacts ADD COLUMN access_code TEXT").run();
} catch (e) {}

// Migration: Add password to trusted_contacts if it doesn't exist
try {
  db.prepare("ALTER TABLE trusted_contacts ADD COLUMN password TEXT").run();
} catch (e) {}

// Encryption Helpers
function encrypt(buffer: Buffer, userKey?: string) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = userKey ? Buffer.from(userKey, 'hex') : ENCRYPTION_KEY;
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const encrypted = Buffer.concat([iv, cipher.update(buffer), cipher.final()]);
  return encrypted;
}

function decrypt(buffer: Buffer, userKey?: string) {
  const iv = buffer.slice(0, IV_LENGTH);
  const encryptedData = buffer.slice(IV_LENGTH);
  const key = userKey ? Buffer.from(userKey, 'hex') : ENCRYPTION_KEY;
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
  return decrypted;
}

// Mock Notification Service
const sendNotification = (to: string, type: 'email' | 'sms', subject: string, body: string) => {
  console.log(`[MOCK ${type.toUpperCase()}] To: ${to}`);
  console.log(`[MOCK ${type.toUpperCase()}] Subject: ${subject}`);
  console.log(`[MOCK ${type.toUpperCase()}] Body: ${body}`);
  console.log('-----------------------------------');
  
  // Save to system_logs for simulation UI
  try {
    db.prepare(`
      INSERT INTO system_logs (id, type, recipient, subject, body)
      VALUES (?, ?, ?, ?, ?)
    `).run(uuidv4(), type, to, subject, body);
  } catch (e) {
    console.error("Failed to save system log:", e);
  }
};
const storage = multer.memoryStorage();
const upload = multer({ storage: storage, limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB limit

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // Auth Middleware
  const authenticate = (req: any, res: any, next: any) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      req.user = decoded;
      next();
    } catch (e) {
      res.status(401).json({ error: "Invalid token" });
    }
  };

  // --- Auth Routes ---
  app.post("/api/auth/register", async (req, res) => {
    const { email, password, name, country } = req.body;
    if (!email || !password || !name) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const vaultKey = crypto.randomBytes(32).toString('hex');
    const escalationConfig = JSON.stringify({ reminderDays: 7, wellnessDays: 14, circleDays: 21, activationDays: 30 });
    try {
      db.prepare("INSERT INTO users (id, email, password, name, country, vault_key, escalation_config) VALUES (?, ?, ?, ?, ?, ?, ?)").run(id, email, hashedPassword, name, country || 'United States', vaultKey, escalationConfig);
      const token = jwt.sign({ id, email, name }, JWT_SECRET);
      res.json({ token, user: { id, email, name, country: country || 'United States', last_check_in: new Date().toISOString() } });
    } catch (e: any) {
      console.error("Registration error:", e);
      if (e.message?.includes("UNIQUE constraint failed: users.email")) {
        res.status(400).json({ error: "Email already exists" });
      } else {
        res.status(500).json({ error: "Database error during registration: " + e.message });
      }
    }
  });

  app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email) as any;
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    // Update last check in on login
    db.prepare("UPDATE users SET last_check_in = CURRENT_TIMESTAMP WHERE id = ?").run(user.id);
    const updatedUser = db.prepare("SELECT * FROM users WHERE id = ?").get(user.id) as any;
    
    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET);
    const lastCheckIn = updatedUser.last_check_in ? new Date(updatedUser.last_check_in.replace(' ', 'T') + 'Z').toISOString() : new Date().toISOString();
    res.json({ 
      token, 
      user: { 
        id: updatedUser.id, 
        email: updatedUser.email, 
        name: updatedUser.name, 
        last_check_in: lastCheckIn
      } 
    });
  });

  // --- Check-In Route ---
  app.post("/api/check-in", authenticate, (req: any, res) => {
    db.prepare("UPDATE users SET last_check_in = CURRENT_TIMESTAMP WHERE id = ?").run(req.user.id);
    sendNotification(req.user.email, 'email', 'Continuity Confirmed', 'Your Life Continuity Mode™ has been reassured. System status: Normal.');
    res.json({ success: true, last_check_in: new Date().toISOString() });
  });

  // --- Section Routes ---
  app.get("/api/sections", authenticate, (req: any, res) => {
    const sections = db.prepare("SELECT * FROM sections WHERE user_id = ? ORDER BY created_at DESC").all(req.user.id);
    res.json(sections);
  });

  app.post("/api/sections", authenticate, (req: any, res) => {
    const { name, icon } = req.body;
    const id = uuidv4();
    db.prepare("INSERT INTO sections (id, user_id, name, icon) VALUES (?, ?, ?, ?)").run(id, req.user.id, name, icon || "Folder");
    res.json({ id, name, icon });
  });

  app.delete("/api/sections/:id", authenticate, (req: any, res) => {
    db.prepare("DELETE FROM documents WHERE section_id = ? AND user_id = ?").run(req.params.id, req.user.id);
    db.prepare("DELETE FROM sections WHERE id = ? AND user_id = ?").run(req.params.id, req.user.id);
    res.json({ success: true });
  });

  // --- Document Routes ---
  app.get("/api/documents", authenticate, (req: any, res) => {
    const docs = db.prepare("SELECT * FROM documents WHERE user_id = ? ORDER BY priority DESC, created_at DESC").all(req.user.id);
    res.json(docs);
  });

  app.get("/api/documents/:id", authenticate, (req: any, res) => {
    console.log(`Preview request for document: ${req.params.id}`);
    const doc = db.prepare("SELECT * FROM documents WHERE id = ? AND user_id = ?").get(req.params.id, req.user.id) as any;
    if (!doc) {
      console.error(`Document not found: ${req.params.id}`);
      return res.status(404).json({ error: "Document not found" });
    }

    const filePath = path.join(UPLOADS_DIR, doc.file_name);
    if (!fs.existsSync(filePath)) {
      console.error(`File not found on disk: ${filePath}`);
      return res.status(404).json({ error: "File not found" });
    }

    try {
      const encryptedData = fs.readFileSync(filePath);
      console.log(`Read ${encryptedData.length} bytes from disk`);
      const user = db.prepare("SELECT vault_key FROM users WHERE id = ?").get(req.user.id) as any;
      const decryptedData = decrypt(encryptedData, user.vault_key);
      console.log(`Decrypted into ${decryptedData.length} bytes`);
      
      res.setHeader("Content-Type", doc.file_type);
      res.setHeader("Content-Length", decryptedData.length);
      res.send(decryptedData);
    } catch (err: any) {
      console.error("Decryption error:", err);
      res.status(500).json({ error: "Failed to decrypt document: " + err.message });
    }
  });

  app.post("/api/documents", authenticate, upload.single("file"), (req: any, res) => {
    console.log("Upload attempt received:", req.body);
    const { title, section_id, priority, notes, beneficiary_id } = req.body;
    const file = req.file;
    
    if (!file) {
      console.error("Upload failed: No file provided");
      return res.status(400).json({ error: "No file uploaded" });
    }

    if (!section_id) {
      console.error("Upload failed: No section_id provided");
      return res.status(400).json({ error: "No section selected" });
    }

    const id = uuidv4();
    try {
      const user = db.prepare("SELECT vault_key FROM users WHERE id = ?").get(req.user.id) as any;
      const encryptedData = encrypt(file.buffer, user.vault_key);
      const fileName = `${id}.enc`;
      const filePath = path.join(UPLOADS_DIR, fileName);
      
      fs.writeFileSync(filePath, encryptedData);
      console.log("File encrypted with user-specific key and saved to:", filePath);

      db.prepare(`
        INSERT INTO documents (id, section_id, user_id, beneficiary_id, title, file_name, file_type, priority, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(id, section_id, req.user.id, beneficiary_id || null, title, fileName, file.mimetype, priority || "Medium", notes || "");
      
      console.log("Document record created in database:", id);
      res.json({ id, title, section_id, priority, beneficiary_id });
    } catch (err: any) {
      console.error("Upload processing error:", err);
      res.status(500).json({ error: "Internal server error during upload: " + err.message });
    }
  });

  app.patch("/api/documents/:id", authenticate, (req: any, res) => {
    const { priority, section_id, notes, beneficiary_id } = req.body;
    if (priority) {
      db.prepare("UPDATE documents SET priority = ? WHERE id = ? AND user_id = ?").run(priority, req.params.id, req.user.id);
    }
    if (section_id) {
      db.prepare("UPDATE documents SET section_id = ? WHERE id = ? AND user_id = ?").run(section_id, req.params.id, req.user.id);
    }
    if (notes !== undefined) {
      db.prepare("UPDATE documents SET notes = ? WHERE id = ? AND user_id = ?").run(notes, req.params.id, req.user.id);
    }
    if (beneficiary_id !== undefined) {
      db.prepare("UPDATE documents SET beneficiary_id = ? WHERE id = ? AND user_id = ?").run(beneficiary_id, req.params.id, req.user.id);
    }
    res.json({ success: true });
  });

  app.delete("/api/documents/:id", authenticate, (req: any, res) => {
    const doc = db.prepare("SELECT file_name FROM documents WHERE id = ? AND user_id = ?").get(req.params.id, req.user.id) as any;
    if (doc) {
      const filePath = path.join(UPLOADS_DIR, doc.file_name);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      db.prepare("DELETE FROM documents WHERE id = ?").run(req.params.id);
    }
    res.json({ success: true });
  });

  // --- Legacy Message Routes ---
  app.get("/api/messages", authenticate, (req: any, res) => {
    const messages = db.prepare("SELECT * FROM legacy_messages WHERE user_id = ?").all(req.user.id);
    res.json(messages);
  });

  app.post("/api/messages", authenticate, (req: any, res) => {
    const { recipient_id, category, type, content, release_event } = req.body;
    const id = uuidv4();
    db.prepare(`
      INSERT INTO legacy_messages (id, user_id, recipient_id, category, type, content, release_event)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, req.user.id, recipient_id, category, type, content, release_event);
    res.json({ id, recipient_id, category, type, content, release_event, status: 'scheduled' });
  });

  app.patch("/api/messages/:id", authenticate, (req: any, res) => {
    const { content, category, release_event, recipient_id } = req.body;
    if (content) db.prepare("UPDATE legacy_messages SET content = ? WHERE id = ? AND user_id = ?").run(content, req.params.id, req.user.id);
    if (category) db.prepare("UPDATE legacy_messages SET category = ? WHERE id = ? AND user_id = ?").run(category, req.params.id, req.user.id);
    if (release_event) db.prepare("UPDATE legacy_messages SET release_event = ? WHERE id = ? AND user_id = ?").run(release_event, req.params.id, req.user.id);
    if (recipient_id) db.prepare("UPDATE legacy_messages SET recipient_id = ? WHERE id = ? AND user_id = ?").run(recipient_id, req.params.id, req.user.id);
    res.json({ success: true });
  });

  app.delete("/api/messages/:id", authenticate, (req: any, res) => {
    db.prepare("DELETE FROM legacy_messages WHERE id = ? AND user_id = ?").run(req.params.id, req.user.id);
    res.json({ success: true });
  });

  // --- Confidential Link Routes ---
  app.get("/api/confidential-links", authenticate, (req: any, res) => {
    const links = db.prepare("SELECT * FROM confidential_links WHERE user_id = ?").all(req.user.id);
    res.json(links);
  });

  app.post("/api/confidential-links", authenticate, (req: any, res) => {
    const { beneficiary_id, title, username, password, notes } = req.body;
    const id = uuidv4();
    db.prepare(`
      INSERT INTO confidential_links (id, user_id, beneficiary_id, title, username, password, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, req.user.id, beneficiary_id, title, username, password, notes);
    res.json({ id, beneficiary_id, title, username, password, notes });
  });

  app.delete("/api/confidential-links/:id", authenticate, (req: any, res) => {
    db.prepare("DELETE FROM confidential_links WHERE id = ? AND user_id = ?").run(req.params.id, req.user.id);
    res.json({ success: true });
  });

  app.get("/api/documents/:id/download", authenticate, (req: any, res) => {
    const doc = db.prepare("SELECT * FROM documents WHERE id = ? AND user_id = ?").get(req.params.id, req.user.id) as any;
    if (!doc) return res.status(404).json({ error: "Document not found" });

    const filePath = path.join(UPLOADS_DIR, doc.file_name);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: "File not found" });

    const encryptedData = fs.readFileSync(filePath);
    const user = db.prepare("SELECT vault_key FROM users WHERE id = ?").get(req.user.id) as any;
    const decryptedData = decrypt(encryptedData, user.vault_key);

    res.setHeader("Content-Type", doc.file_type);
    res.setHeader("Content-Disposition", `attachment; filename="${doc.title}"`);
    res.send(decryptedData);
  });

  // --- Death Verification Routes ---
  app.post("/api/death-verification", authenticate, upload.single("file"), (req: any, res) => {
    const { beneficiary_id } = req.body;
    const file = req.file;
    if (!file) return res.status(400).json({ error: "No certificate uploaded" });

    const id = uuidv4();
    const fileName = `${id}_death_cert.enc`;
    const filePath = path.join(UPLOADS_DIR, fileName);
    
    // Encrypt with a system key or just store for verification
    fs.writeFileSync(filePath, encrypt(file.buffer));

    db.prepare(`
      INSERT INTO death_verifications (id, user_id, beneficiary_id, file_name, status)
      VALUES (?, ?, ?, ?, ?)
    `).run(id, req.user.id, beneficiary_id || null, fileName, 'pending');

    res.json({ success: true, id });
  });

  app.post("/api/beneficiary/death-verification", upload.single("file"), (req: any, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      if (decoded.role !== 'beneficiary') return res.status(403).json({ error: "Forbidden" });

      const file = req.file;
      if (!file) return res.status(400).json({ error: "No certificate uploaded" });

      const id = uuidv4();
      const fileName = `${id}_death_cert.enc`;
      const filePath = path.join(UPLOADS_DIR, fileName);
      
      fs.writeFileSync(filePath, encrypt(file.buffer));

      db.prepare(`
        INSERT INTO death_verifications (id, user_id, beneficiary_id, file_name, status)
        VALUES (?, ?, ?, ?, ?)
      `).run(id, decoded.owner_id, decoded.id, fileName, 'pending');

      res.json({ success: true, id });
    } catch (e) {
      res.status(401).json({ error: "Invalid token" });
    }
  });

  app.get("/api/death-verification", authenticate, (req: any, res) => {
    const verifications = db.prepare("SELECT * FROM death_verifications WHERE user_id = ?").all(req.user.id);
    res.json(verifications);
  });

  app.post("/api/death-verification/:id/verify", authenticate, (req: any, res) => {
    const verification = db.prepare("SELECT * FROM death_verifications WHERE id = ? AND user_id = ?").get(req.params.id, req.user.id) as any;
    if (!verification) return res.status(404).json({ error: "Verification not found" });

    db.prepare("UPDATE death_verifications SET status = 'verified' WHERE id = ?").run(req.params.id);
    
    // Trigger activation
    db.prepare("UPDATE users SET escalation_stage = 'Activation' WHERE id = ?").run(req.user.id);
    
    res.json({ success: true });
  });

  // --- Beneficiary Access Routes ---
  app.post("/api/beneficiary/login", async (req, res) => {
    const { email, password } = req.body;
    
    const contact = db.prepare("SELECT * FROM trusted_contacts WHERE email = ?").get(email) as any;
    if (!contact) return res.status(401).json({ error: "This email is not registered in any Trust Network." });

    // If password is not set yet, this is the "set password" step
    if (!contact.password) {
      if (!password || password.length < 4) {
        return res.status(400).json({ error: "First-time login: Please set a secure password (min 4 characters)." });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      db.prepare("UPDATE trusted_contacts SET password = ? WHERE id = ?").run(hashedPassword, contact.id);
      contact.password = hashedPassword;
    } else {
      // Standard login
      if (!password || !(await bcrypt.compare(password, contact.password))) {
        return res.status(401).json({ error: "Invalid password." });
      }
    }

    const user = db.prepare("SELECT escalation_stage FROM users WHERE id = ?").get(contact.user_id) as any;
    // Allow login in all stages, but UI will handle what's visible
    const token = jwt.sign({ id: contact.id, email: contact.email, name: contact.name, role: 'beneficiary', owner_id: contact.user_id }, JWT_SECRET);
    res.json({ token, beneficiary: contact });
  });

  app.get("/api/beneficiary/assets", (req: any, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      if (decoded.role !== 'beneficiary') return res.status(403).json({ error: "Forbidden" });

      const documents = db.prepare("SELECT * FROM documents WHERE beneficiary_id = ?").all(decoded.id);
      const messages = db.prepare("SELECT * FROM legacy_messages WHERE recipient_id = ?").all(decoded.id);
      const credentials = db.prepare("SELECT * FROM confidential_links WHERE beneficiary_id = ?").all(decoded.id);
      const owner = db.prepare("SELECT name, email, country, escalation_stage FROM users WHERE id = ?").get(decoded.owner_id) as any;
      const verifications = db.prepare("SELECT * FROM death_verifications WHERE beneficiary_id = ?").all(decoded.id);

      res.json({ documents, messages, credentials, owner, verifications });
    } catch (e) {
      res.status(401).json({ error: "Invalid token" });
    }
  });

  app.post("/api/beneficiary/confirm-wellness", (req: any, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      if (decoded.role !== 'beneficiary') return res.status(403).json({ error: "Forbidden" });

      db.prepare("UPDATE users SET escalation_stage = 'Normal', last_check_in = CURRENT_TIMESTAMP WHERE id = ?").run(decoded.owner_id);
      
      // Log the action
      const id = uuidv4();
      db.prepare("INSERT INTO system_logs (id, type, recipient, subject, body) VALUES (?, ?, ?, ?, ?)")
        .run(id, 'system', 'ADMIN', 'Wellness Confirmed by Beneficiary', `Beneficiary ${decoded.name} confirmed wellness for owner.`);

      res.json({ success: true });
    } catch (e) {
      res.status(401).json({ error: "Invalid token" });
    }
  });

  app.get("/api/beneficiary/download/:id", (req: any, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      if (decoded.role !== 'beneficiary') return res.status(403).json({ error: "Forbidden" });

      const doc = db.prepare("SELECT * FROM documents WHERE id = ? AND beneficiary_id = ?").get(req.params.id, decoded.id) as any;
      if (!doc) return res.status(404).json({ error: "Document not found" });

      const filePath = path.join(UPLOADS_DIR, doc.file_name);
      const encryptedData = fs.readFileSync(filePath);
      
      const owner = db.prepare("SELECT vault_key FROM users WHERE id = ?").get(decoded.owner_id) as any;
      const decryptedData = decrypt(encryptedData, owner.vault_key);

      res.setHeader("Content-Type", doc.file_type);
      res.setHeader("Content-Disposition", `attachment; filename="${doc.title}"`);
      res.send(decryptedData);
    } catch (e) {
      res.status(401).json({ error: "Invalid token" });
    }
  });
  app.get("/api/notifications", authenticate, (req: any, res) => {
    const notifications = db.prepare("SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC").all(req.user.id);
    res.json(notifications);
  });

  app.post("/api/notifications/read", authenticate, (req: any, res) => {
    db.prepare("UPDATE notifications SET is_read = 1 WHERE user_id = ?").run(req.user.id);
    res.json({ success: true });
  });

  // --- Admin Routes ---
  app.post("/api/admin/login", (req, res) => {
    const { email, password } = req.body;
    // Hardcoded for simulation
    if (email === "admin@2026" && password === "12345") {
      const token = jwt.sign({ id: 'admin', email, role: 'admin' }, JWT_SECRET);
      res.json({ token, user: { id: 'admin', name: 'System Administrator', email, role: 'admin' } });
    } else {
      res.status(401).json({ error: "Invalid admin credentials" });
    }
  });

  app.get("/api/admin/users", (req: any, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      if (decoded.role !== 'admin') return res.status(403).json({ error: "Forbidden" });
      const users = db.prepare("SELECT id, email, name, country, escalation_stage, last_check_in, status FROM users").all();
      res.json(users);
    } catch (e) {
      res.status(401).json({ error: "Invalid token" });
    }
  });

  app.get("/api/admin/verifications", (req: any, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      if (decoded.role !== 'admin') return res.status(403).json({ error: "Forbidden" });
      const verifications = db.prepare(`
        SELECT dv.*, u.name as user_name, u.email as user_email, tc.name as beneficiary_name 
        FROM death_verifications dv
        JOIN users u ON dv.user_id = u.id
        LEFT JOIN trusted_contacts tc ON dv.beneficiary_id = tc.id
      `).all();
      res.json(verifications);
    } catch (e) {
      res.status(401).json({ error: "Invalid token" });
    }
  });

  app.get("/api/admin/verifications/:id/file", (req: any, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      if (decoded.role !== 'admin') return res.status(403).json({ error: "Forbidden" });

      const verification = db.prepare("SELECT * FROM death_verifications WHERE id = ?").get(req.params.id) as any;
      if (!verification) return res.status(404).json({ error: "Verification not found" });

      const filePath = path.join(UPLOADS_DIR, verification.file_name);
      if (!fs.existsSync(filePath)) return res.status(404).json({ error: "File not found" });

      const encryptedData = fs.readFileSync(filePath);
      const decryptedData = decrypt(encryptedData); // Encrypted with system key

      res.setHeader("Content-Type", "application/pdf");
      res.send(decryptedData);
    } catch (e) {
      res.status(401).json({ error: "Invalid token" });
    }
  });

  app.post("/api/admin/verifications/:id/verify", (req: any, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      if (decoded.role !== 'admin') return res.status(403).json({ error: "Forbidden" });

      const verification = db.prepare("SELECT * FROM death_verifications WHERE id = ?").get(req.params.id) as any;
      if (!verification) return res.status(404).json({ error: "Verification not found" });

      db.prepare("UPDATE death_verifications SET status = 'verified' WHERE id = ?").run(req.params.id);
      db.prepare("UPDATE users SET escalation_stage = 'Activation' WHERE id = ?").run(verification.user_id);

      // Log the action
      const logId = uuidv4();
      db.prepare("INSERT INTO system_logs (id, type, recipient, subject, body) VALUES (?, ?, ?, ?, ?)")
        .run(logId, 'system', 'ADMIN', 'Death Verified & Legacy Released', `Admin verified death certificate for user ${verification.user_id}. Legacy released.`);

      res.json({ success: true });
    } catch (e) {
      res.status(401).json({ error: "Invalid token" });
    }
  });

  app.post("/api/death-verification/:id/verify", authenticate, (req: any, res) => {
    const verification = db.prepare("SELECT * FROM death_verifications WHERE id = ? AND user_id = ?").get(req.params.id, req.user.id) as any;
    if (!verification) return res.status(404).json({ error: "Verification not found" });

    db.prepare("UPDATE death_verifications SET status = 'verified' WHERE id = ?").run(req.params.id);
    db.prepare("UPDATE users SET escalation_stage = 'Activation' WHERE id = ?").run(req.user.id);

    res.json({ success: true });
  });

  app.get("/api/admin/logs", (req: any, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      if (decoded.role !== 'admin') return res.status(403).json({ error: "Forbidden" });
      const logs = db.prepare("SELECT * FROM system_logs ORDER BY created_at DESC LIMIT 100").all();
      res.json(logs);
    } catch (e) {
      res.status(401).json({ error: "Invalid token" });
    }
  });

  app.post("/api/admin/verifications/:id/verify", (req: any, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      if (decoded.role !== 'admin') return res.status(403).json({ error: "Forbidden" });
      
      const verification = db.prepare("SELECT * FROM death_verifications WHERE id = ?").get(req.params.id) as any;
      if (!verification) return res.status(404).json({ error: "Verification not found" });

      db.prepare("UPDATE death_verifications SET status = 'verified' WHERE id = ?").run(req.params.id);
      db.prepare("UPDATE users SET escalation_stage = 'Activation' WHERE id = ?").run(verification.user_id);
      
      res.json({ success: true });
    } catch (e) {
      res.status(401).json({ error: "Invalid token" });
    }
  });

  // --- Escalation Simulation Route ---
  app.post("/api/simulate/escalation", authenticate, (req: any, res) => {
    const { stage } = req.body;
    const userId = req.user.id;
    
    db.prepare("UPDATE users SET escalation_stage = ? WHERE id = ?").run(stage, userId);
    
    let title = "";
    let message = "";
    let type = "info";

    if (stage === 'Reminder') {
      title = "Continuity Check-In Due";
      message = "It's been a while since your last check-in. Please confirm your status to reassure the system.";
      type = "warning";
      sendNotification(req.user.email, 'email', title, message);
      sendNotification('USER_PHONE', 'sms', title, message);
    } else if (stage === 'Wellness') {
      title = "Urgent: Wellness Confirmation";
      message = "Action required. Please complete biometric verification immediately to prevent escalation.";
      type = "alert";
      sendNotification(req.user.email, 'email', title, message);
      sendNotification('USER_PHONE', 'sms', title, message);
    } else if (stage === 'Circle') {
      title = "Trusted Circle Notified";
      message = "Your primary continuity partners have been alerted that you are unresponsive. They may contact you soon.";
      type = "alert";
      
      // Simulate sending emails to trust network
      const contacts = db.prepare("SELECT * FROM trusted_contacts WHERE user_id = ?").all(userId) as any[];
      contacts.forEach(c => {
        sendNotification(c.email, 'email', `Urgent: Check on ${req.user.name}`, `User ${req.user.name} is unresponsive. Please check on them.`);
      });
    } else if (stage === 'Activation') {
      title = "Legacy Activation Initiated";
      message = "The final stage of your continuity plan has been triggered. Your legacy assets are being released to beneficiaries.";
      type = "alert";

      // Simulate sending vault content to beneficiaries
      const documents = db.prepare("SELECT * FROM documents WHERE user_id = ? AND beneficiary_id IS NOT NULL").all(userId) as any[];
      const messages = db.prepare("SELECT * FROM legacy_messages WHERE user_id = ?").all(userId) as any[];
      const credentials = db.prepare("SELECT * FROM confidential_links WHERE user_id = ?").all(userId) as any[];
      const contacts = db.prepare("SELECT * FROM trusted_contacts WHERE user_id = ?").all(userId) as any[];

      contacts.forEach(c => {
        const beneficiaryDocs = documents.filter(d => d.beneficiary_id === c.id);
        const beneficiaryMsgs = messages.filter(m => m.recipient_id === c.id);
        const beneficiaryCreds = credentials.filter(l => l.beneficiary_id === c.id);

        if (beneficiaryDocs.length > 0 || beneficiaryMsgs.length > 0 || beneficiaryCreds.length > 0) {
          sendNotification(c.email, 'email', `Legacy Released: ${req.user.name}`, `The legacy assets from ${req.user.name} have been released to you. You can now access them via your secure portal.`);
        }
      });
    }

    if (title) {
      db.prepare("INSERT INTO notifications (id, user_id, title, message, type) VALUES (?, ?, ?, ?, ?)")
        .run(uuidv4(), userId, title, message, type);
    }

    res.json({ success: true, stage });
  });
  app.post("/api/blockchain/verify", authenticate, (req: any, res) => {
    const { document_id } = req.body;
    const doc = db.prepare("SELECT * FROM documents WHERE id = ? AND user_id = ?").get(document_id, req.user.id) as any;
    if (!doc) return res.status(404).json({ error: "Document not found" });

    const hash = crypto.createHash('sha256').update(doc.id + doc.title + doc.created_at).digest('hex');
    const tx_id = "0x" + crypto.randomBytes(32).toString('hex');
    const id = uuidv4();

    db.prepare("INSERT INTO blockchain_proofs (id, document_id, hash, tx_id) VALUES (?, ?, ?, ?)").run(id, document_id, hash, tx_id);
    res.json({ hash, tx_id, timestamp: new Date().toISOString() });
  });

  app.get("/api/blockchain/proofs/:document_id", authenticate, (req: any, res) => {
    const proof = db.prepare("SELECT * FROM blockchain_proofs WHERE document_id = ?").get(req.params.document_id);
    res.json(proof || null);
  });

  // --- Continuity Settings ---
  app.get("/api/user/settings", authenticate, (req: any, res) => {
    const user = db.prepare("SELECT country, escalation_config FROM users WHERE id = ?").get(req.user.id) as any;
    res.json(user);
  });

  app.patch("/api/user/settings", authenticate, (req: any, res) => {
    const { country, escalation_config } = req.body;
    if (country) db.prepare("UPDATE users SET country = ? WHERE id = ?").run(country, req.user.id);
    if (escalation_config) db.prepare("UPDATE users SET escalation_config = ? WHERE id = ?").run(JSON.stringify(escalation_config), req.user.id);
    res.json({ success: true });
  });

  app.get("/api/contacts", authenticate, (req: any, res) => {
    const contacts = db.prepare("SELECT * FROM trusted_contacts WHERE user_id = ?").all(req.user.id);
    res.json(contacts);
  });

  app.post("/api/contacts", authenticate, (req: any, res) => {
    const { name, email, relationship } = req.body;
    const id = uuidv4();
    const accessCode = Math.random().toString(36).substring(2, 8).toUpperCase();
    db.prepare("INSERT INTO trusted_contacts (id, user_id, name, email, relationship, access_code) VALUES (?, ?, ?, ?, ?, ?)").run(id, req.user.id, name, email, relationship, accessCode);
    res.json({ id, name, email, relationship, access_code: accessCode, status: 'active' });
  });

  app.delete("/api/contacts/:id", authenticate, (req: any, res) => {
    db.prepare("DELETE FROM trusted_contacts WHERE id = ? AND user_id = ?").run(req.params.id, req.user.id);
    res.json({ success: true });
  });

  // Vite middleware
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
