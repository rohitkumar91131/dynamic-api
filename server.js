require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const hpp = require("hpp");
const xss = require("xss");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const { MongoClient, ObjectId } = require("mongodb");
const OpenAI = require("openai");
const nodemailer = require("nodemailer");
let sharp = null;
try { sharp = require("sharp"); } catch (e) { console.warn("⚠️ sharp not installed - thumbnails will be skipped until npm install"); }

const app = express();

// ==================== ENV VALIDATION ====================
const REQUIRED_ENVS = ["MONGODB_URI"];
const missing = REQUIRED_ENVS.filter(k => !process.env[k]);
if (missing.length) {
    console.warn(`⚠️  Missing required env: ${missing.join(", ")} - some features may fail`);
}
const KIRA_API_KEY = process.env.KIRA_API_KEY;
const KIRA_BASE_URL = process.env.KIRA_BASE_URL || "https://kiraai.vn/api/v1";
const KIRA_MODEL = process.env.KIRA_MODEL || "kira-3.5-flash";
const KIRA_IMAGE_MODEL = process.env.KIRA_IMAGE_MODEL || "kira-3.0-image";
const KIRA_TTS_MODEL = process.env.KIRA_TTS_MODEL || "kira-3.0-flash-tts";
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || process.env.SMTP_USER || "").toLowerCase().trim();
const ADMIN_BASE = (process.env.ADMIN_URL || "/admin-secure-xyz123").trim();
const normalizedAdminBase = ADMIN_BASE.startsWith("/") ? ADMIN_BASE : `/${ADMIN_BASE}`;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "";
const PORT = parseInt(process.env.PORT || "3000", 10);
const NODE_ENV = process.env.NODE_ENV || "development";
const isProd = NODE_ENV === "production";
// Telegram thumbnail config
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || "";
const THUMB_MAX_KB = parseInt(process.env.THUMB_MAX_KB || "25", 10);
const THUMB_WIDTH = parseInt(process.env.THUMB_WIDTH || "320", 10);
const THUMB_QUALITY = parseInt(process.env.THUMB_QUALITY || "65", 10);

// ==================== SECURITY MIDDLEWARE ====================
app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    hsts: isProd ? { maxAge: 31536000, includeSubDomains: true } : false
}));

// CORS - strict whitelist if CORS_ORIGIN set, else allow but log warning
let corsOptions = {};
if (CORS_ORIGIN) {
    const allowed = CORS_ORIGIN.split(",").map(s => s.trim()).filter(Boolean);
    corsOptions = {
        origin: (origin, cb) => {
            if (!origin) return cb(null, true); // mobile / curl / same-origin
            if (allowed.includes("*") || allowed.includes(origin)) return cb(null, true);
            return cb(new Error("CORS blocked"));
        },
        credentials: true,
        methods: ["GET","POST","PATCH","DELETE","OPTIONS"],
        allowedHeaders: ["Content-Type","Authorization","X-API-Key","X-Admin-Token"]
    };
} else {
    // Personal use: default restrictive - same-origin + localhost, not wildcard star echo? but for dev allow all with warning
    if (isProd) console.warn("⚠️  CORS_ORIGIN not set in production - defaulting to deny all cross-origin. Set CORS_ORIGIN env.");
    corsOptions = {
        origin: isProd ? false : true,
        credentials: true
    };
}
app.use(cors());

// Body limit reduced from 50mb -> 1mb to prevent DoS
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));
app.use(hpp());

// Custom Mongo Sanitizer (works with Express 5 where query is getter)
function sanitizeMongo(obj) {
    if (!obj || typeof obj !== "object") return;
    for (const key in obj) {
        if (key.startsWith("$") || key.includes(".") || key === "__proto__" || key === "constructor" || key === "prototype") {
            delete obj[key];
            continue;
        }
        const val = obj[key];
        if (val && typeof val === "object") sanitizeMongo(val);
    }
}
app.use((req, res, next) => {
    if (req.body) sanitizeMongo(req.body);
    if (req.query) sanitizeMongo(req.query);
    if (req.params) sanitizeMongo(req.params);
    next();
});

// Rate limiters
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: "Too many requests, try later" }
});
const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: "API rate limit exceeded (60/min)" }
});
const otpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: "Too many OTP requests, try later" }
});
app.use(globalLimiter);

// ==================== MONGODB ====================
if (!process.env.MONGODB_URI) console.error("❌ MONGODB_URI is required");
const client = new MongoClient(process.env.MONGODB_URI || "mongodb://localhost:27017", {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 8000,
    connectTimeoutMS: 8000,
});
let db = null;
async function getDB() {
    if (!db) {
        await client.connect();
        const dbName = process.env.DATABASE_NAME || undefined; // if undefined, use from URI
        db = dbName ? client.db(dbName) : client.db();
        console.log("✅ MongoDB Connected");
        // Ensure indexes
        try {
            await db.collection("otps").createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
            await db.collection("admin_sessions").createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
            await db.collection("api_keys").createIndex({ keyHash: 1 }, { unique: true, sparse: true });
            await db.collection("api_keys").createIndex({ key: 1 }, { unique: true, sparse: true }); // legacy, kept for migration period
            await db.collection("api_keys").createIndex({ isActive: 1 });
            await db.collection("invalid_api_attempts").createIndex({ timestamp: -1 });
            await db.collection("invalid_api_attempts").createIndex({ timestamp: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 }); // TTL 30 days
            await db.collection("invalid_api_attempts").createIndex({ reason: 1 });
            await db.collection("thumbnails").createIndex({ collection: 1, docId: 1, idx: 1 }, { unique: true });
            await db.collection("thumbnails").createIndex({ createdAt: -1 });
        } catch (e) { console.warn("Index ensure warn:", e.message); }
        // Auto-migrate existing plaintext keys to hashed on boot (idempotent, for build-time safety)
        try {
            const col = db.collection("api_keys");
            const plaintextKeys = await col.find({ key: { $regex: "^dyn_" } }).limit(50).toArray();
            for (const doc of plaintextKeys) {
                if (doc.key && !isHashedKey(doc.key) && !doc.keyHash) {
                    const hashed = hashApiKey(doc.key);
                    const preview = doc.keyPreview || maskKey(doc.key);
                    // skip if hash already exists
                    const exists = await col.findOne({ keyHash: hashed });
                    if (exists) continue;
                    await col.updateOne({ _id: doc._id }, { $set: { keyHash: hashed, key: hashed, keyPreview: preview, migratedAt: new Date() } });
                    console.log(`🔐 auto-migrated key ${doc._id} ${preview}`);
                }
            }
            if (plaintextKeys.length) console.log(`✅ auto-migration checked ${plaintextKeys.length} plaintext keys`);
        } catch (e) { console.warn("auto-migrate warn:", e.message); }
    }
    return db;
}

// ==================== KIRA AI (OpenAI compatible) ====================
let kiraClient = null;
function getKiraClient() {
    if (!kiraClient) {
        if (!KIRA_API_KEY) {
            console.warn("⚠️  KIRA_API_KEY not set - AI features will fail");
        }
        kiraClient = new OpenAI({
            apiKey: KIRA_API_KEY || "missing",
            baseURL: KIRA_BASE_URL,
            timeout: 25000,
            maxRetries: 1
        });
    }
    return kiraClient;
}

// Dynamic prompts - allow env override
const DEFAULT_TAG_PROMPT = process.env.KIRA_TAG_PROMPT || `You are a medical categorization AI. Read the user's daily health log (which might be in Hinglish/Hindi/English) and generate 1 to 3 highly relevant, concise medical/symptom hashtags.
CRITICAL RULES:
- Output ONLY the hashtags separated by spaces (e.g., #Headache #Acidity #Fatigue).
- If the log is about eating too much and bloating, output tags like #Bloating #Overeating.
- Do NOT write any text, no explanations, no formatting. Just the hashtags.`;

const DEFAULT_ANALYSIS_PROMPT = process.env.KIRA_ANALYSIS_PROMPT || `You are an empathetic and smart health assistant. Your task is to analyze daily health logs.
CRITICAL RULES:
- Focus ONLY on the actual health symptoms, feelings, or notes provided by the user.
- The user might write in Hindi, English, or Hinglish (e.g., "matha dard kar raha hai"). Understand it and reply in English.

Please format your response in clear Markdown with these exact sections:
### 📋 Quick Summary
(One clear sentence about how the user is feeling)

### 💡 Insights & Possible Causes
(Short logical reasoning based on the symptoms)

### 🌿 Gentle Suggestions
(1-2 quick home remedies or advice like rest/hydration)

### ⚠️ Note
(A standard 1-line medical disclaimer)`;

// ==================== HELPERS ====================
function isValidCollection(name) {
    return typeof name === "string" && name.length >= 1 && name.length <= 64 && /^[a-zA-Z0-9_-]+$/.test(name);
}
function isValidObjectId(id) {
    return ObjectId.isValid(id) && String(new ObjectId(id)) === id;
}
function sanitizeString(str, max = 5000) {
    if (typeof str !== "string") return "";
    let s = str.slice(0, max);
    // xss clean + trim
    s = xss(s);
    // remove prompt injection control sequences
    s = s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
    return s.trim();
}
function extractNotes(data) {
    let text = "";
    if (data && data.fields && Array.isArray(data.fields)) {
        text = data.fields.map(f => {
            const label = sanitizeString(String(f.label || ""), 200);
            const value = sanitizeString(String(f.value || ""), 500);
            return `${label}: ${value}`;
        }).join(", ");
    } else if (typeof data === "string") {
        text = sanitizeString(data, 4000);
    } else {
        try { text = sanitizeString(JSON.stringify(data).slice(0, 4000), 4000); } catch { text = ""; }
    }
    // hard limit + prevent prompt injection overflow
    if (text.length > 4000) text = text.slice(0, 4000);
    // strip common injection prefixes
    text = text.replace(/^(system|assistant|user)\s*:/gi, "");
    return text;
}
function stripMongoOperators(obj) {
    if (!obj || typeof obj !== "object") return obj;
    const clean = {};
    for (const [k, v] of Object.entries(obj)) {
        if (k.startsWith("$") || k.includes(".") || ["__proto__","constructor","prototype"].includes(k)) continue;
        clean[k] = v;
    }
    return clean;
}
function getClientIp(req) {
    return req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip || req.socket.remoteAddress || "unknown";
}
function hashApiKey(key) {
    return crypto.createHash("sha256").update(String(key)).digest("hex");
}
function isHashedKey(str) {
    return typeof str === "string" && /^[a-f0-9]{64}$/.test(str);
}
function maskKey(key) {
    const s = String(key);
    if (s.length <= 12) return s.slice(0,4) + "****";
    return s.slice(0, 8) + "••••••••" + s.slice(-4);
}

// ==================== THUMBNAIL + TELEGRAM HELPERS (25kb webp) ====================
function extractTallyImages(data) {
    const urls = [];
    try {
        if (data && data.fields && Array.isArray(data.fields)) {
            for (const f of data.fields) {
                if (f.type === "FILE_UPLOAD" && Array.isArray(f.value)) {
                    for (const file of f.value) {
                        if (file && file.url) urls.push({
                            url: String(file.url),
                            name: String(file.name||"file"),
                            id: String(file.id||""),
                            mimeType: String(file.mimeType||""),
                            size: file.size || 0
                        });
                    }
                }
            }
        }
    } catch {}
    return urls;
}

function detectFileKind(buf, fileName, mimeHint) {
    const name = String(fileName||"").toLowerCase();
    const mime = String(mimeHint||"").toLowerCase();
    // quick check via mime / extension
    if (mime.startsWith("image/") || /\.(jpe?g|png|webp|gif|bmp|tiff|heic|avif)$/i.test(name)) return "image";
    if (mime.startsWith("video/") || /\.(mp4|mov|avi|webm|mkv|m4v|3gp)$/i.test(name)) return "video";
    if (mime === "application/pdf" || /\.pdf$/i.test(name)) return "pdf";
    if (mime.startsWith("audio/") || /\.(mp3|wav|ogg|m4a|aac|flac)$/i.test(name)) return "audio";
    // magic bytes fallback
    if (buf && buf.length >= 4) {
        // JPEG FF D8 FF, PNG 89 50 4E 47, WEBP 52 49 46 46, GIF 47 49 46, PDF 25 50 44 46, MP4 ftyp
        if (buf[0]===0xFF && buf[1]===0xD8) return "image";
        if (buf[0]===0x89 && buf[1]===0x50) return "image";
        if (buf[0]===0x25 && buf[1]===0x50 && buf[2]===0x44) return "pdf";
        if (buf.slice(4,8).toString()==="ftyp") return "video";
        if (buf.slice(0,4).toString()==="RIFF" && buf.slice(8,12).toString()==="WEBP") return "image";
    }
    return "other";
}

async function generatePlaceholderWebp(label, subLabel) {
    if (!sharp) throw new Error("sharp not available");
    const w = THUMB_WIDTH, h = Math.round(w * 0.66); // 320x211
    const bg = label==="video" ? "#0f172a" : label==="pdf" ? "#451a03" : label==="audio" ? "#14532d" : "#1e293b";
    const accent = label==="video" ? "#38bdf8" : label==="pdf" ? "#f87171" : label==="audio" ? "#4ade80" : "#94a3b8";
    const icon = label==="video" ? "▶" : label==="pdf" ? "PDF" : label==="audio" ? "♫" : "FILE";
    const svg = `<svg width="${w}" height="${h}" xmlns="http://www.w3.org/2000/svg">
      <rect width="100%" height="100%" rx="12" fill="${bg}"/>
      <rect x="12" y="12" width="${w-24}" height="${h-24}" rx="10" fill="none" stroke="${accent}" stroke-opacity="0.3" stroke-width="1.5" stroke-dasharray="6 4"/>
      <text x="50%" y="42%" dominant-baseline="middle" text-anchor="middle" font-family="Inter,Arial,sans-serif" font-size="42" font-weight="800" fill="${accent}">${icon}</text>
      <text x="50%" y="62%" dominant-baseline="middle" text-anchor="middle" font-family="Inter,Arial,sans-serif" font-size="11" font-weight="700" fill="#e2e8f0" letter-spacing="0.6">${String(subLabel||label).slice(0,24).toUpperCase()}</text>
      <text x="50%" y="75%" dominant-baseline="middle" text-anchor="middle" font-family="Arial,sans-serif" font-size="9" fill="#94a3b8">${w}w • webp • &lt;25kb</text>
    </svg>`;
    const buf = await sharp(Buffer.from(svg)).webp({ quality: THUMB_QUALITY, effort: 6 }).toBuffer();
    return { buffer: buf, quality: THUMB_QUALITY, size: buf.length, placeholder: true, kind: label };
}

async function generateWebpThumbnail(inputBuffer, fileNameHint, mimeHint) {
    if (!sharp) throw new Error("sharp not available");
    const kind = detectFileKind(inputBuffer, fileNameHint, mimeHint);
    if (kind !== "image") {
        // video/pdf/audio/other -> crisp placeholder webp (still <25kb, ~4-6kb)
        return generatePlaceholderWebp(kind, fileNameHint ? fileNameHint.split('.').pop() : kind);
    }
    const targetBytes = THUMB_MAX_KB * 1024;
    const qualities = [THUMB_QUALITY, 60, 50, 40, 30, 20];
    let best = null;
    for (const q of qualities) {
        try {
            const buf = await sharp(inputBuffer)
                .rotate()
                .resize({ width: THUMB_WIDTH, withoutEnlargement: true })
                .webp({ quality: q, effort: 6 })
                .toBuffer();
            best = buf;
            if (buf.length <= targetBytes) return { buffer: buf, quality: q, size: buf.length, kind: "image" };
        } catch (e) {
            // sharp failed -> fallback to placeholder (e.g. heic without decoder)
            console.warn("sharp image decode fail, placeholder:", e.message);
            return generatePlaceholderWebp("image", "image");
        }
    }
    if (best && best.length > targetBytes) {
        try {
            const smaller = await sharp(inputBuffer).rotate().resize({ width: 240, withoutEnlargement: true }).webp({ quality: 30, effort: 6 }).toBuffer();
            return { buffer: smaller, quality: 30, size: smaller.length, fallback: true, kind: "image" };
        } catch { return generatePlaceholderWebp("image", "image"); }
    }
    return { buffer: best, quality: qualities[qualities.length-1], size: best.length, kind: "image" };
}

async function uploadToTelegram(webpBuffer, caption = "") {
    if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return null;
    try {
        const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendPhoto`;
        const form = new FormData();
        form.append("chat_id", TELEGRAM_CHAT_ID);
        const blob = new Blob([webpBuffer], { type: "image/webp" });
        form.append("photo", blob, "thumb.webp");
        if (caption) form.append("caption", String(caption).slice(0, 900));
        const controller = new AbortController();
        const t = setTimeout(()=>controller.abort(), 15000);
        try {
            const res = await fetch(url, { method: "POST", body: form, signal: controller.signal });
            const j = await res.json().catch(()=>null);
            if (!res.ok || !j?.ok) {
                console.warn("Telegram upload failed:", res.status, j?.description || j);
                return null;
            }
            // Telegram returns photo array sorted smallest->largest
            const photos = j.result?.photo || [];
            const largest = photos[photos.length-1];
            return {
                file_id: largest?.file_id || null,
                file_unique_id: largest?.file_unique_id || null,
                message_id: j.result?.message_id || null,
                raw: j.result
            };
        } finally { clearTimeout(t); }
    } catch (e) {
        console.warn("uploadToTelegram error:", e.message);
        return null;
    }
}

async function processThumbnailsForDoc(collection, docId, data) {
    const images = extractTallyImages(data);
    if (!images.length) return { processed: 0 };
    if (!sharp) { console.warn("sharp missing - skip thumbnail for", docId); return { processed: 0, skipped: true }; }
    const database = await getDB();
    const results = [];
    for (let idx = 0; idx < images.length; idx++) {
        const img = images[idx];
        try {
            // fetch original (tally private url) - 10s timeout, 8mb max (images) / 15mb for video/pdf
            const controller = new AbortController();
            const t = setTimeout(()=>controller.abort(), 15000);
            let origBuf; let contentType = img.mimeType || "";
            try {
                const r = await fetch(img.url, { signal: controller.signal });
                if (!r.ok) throw new Error(`fetch ${r.status}`);
                contentType = r.headers.get("content-type") || contentType;
                const ab = await r.arrayBuffer();
                // video/pdf may be larger, allow 15mb for fetch but still thumb is 25kb
                const limit = contentType.startsWith("video/") || contentType==="application/pdf" ? 15*1024*1024 : 8*1024*1024;
                if (ab.byteLength > limit) throw new Error("file too large");
                origBuf = Buffer.from(ab);
            } finally { clearTimeout(t); }
            const { buffer: webpBuf, quality, size, kind, placeholder } = await generateWebpThumbnail(origBuf, img.name, contentType);
            console.log(`🖼️ thumb ${docId}[${idx}] kind=${kind} ${origBuf.length} -> ${size} bytes q=${quality} webp${placeholder?" (placeholder)":""}`);

            // upload to telegram (optional) - always photo (webp placeholder for video/pdf too)
            const tg = await uploadToTelegram(webpBuf, `${collection}/${docId} #${idx} [${kind}] ${img.name} ${size}B q${quality}${placeholder?" placeholder":""}`);
            // store in dedicated thumbnails collection for fast proxy (binary)
            const thumbDoc = {
                collection,
                docId: new ObjectId(docId),
                idx,
                origUrl: img.url,
                origName: img.name,
                origMime: contentType,
                kind, // image | video | pdf | audio | other | placeholder
                isPlaceholder: !!placeholder,
                createdAt: new Date(),
                thumbSize: size,
                thumbWidth: THUMB_WIDTH,
                quality,
                mimeType: "image/webp",
                buffer: webpBuf,
                telegram: tg ? { file_id: tg.file_id, file_unique_id: tg.file_unique_id, message_id: tg.message_id } : null
            };
            await database.collection("thumbnails").updateOne(
                { collection, docId: new ObjectId(docId), idx },
                { $set: thumbDoc },
                { upsert: true }
            );
            results.push({ idx, size, quality, kind, placeholder: !!placeholder, telegram_file_id: tg?.file_id || null });
        } catch (e) {
            console.warn(`thumb fail ${docId}[${idx}]`, e.message);
            results.push({ idx, error: e.message });
        }
    }
    // update original doc with thumbRefs array (no binary, just refs)
    try {
        await database.collection(collection).updateOne(
            { _id: new ObjectId(docId) },
            { $set: { thumbnails: results, thumbnailAt: new Date() } }
        );
    } catch {}
    return { processed: results.length, results };
}

// Kira call with timeout + sanitization
async function callKiraChat(messages, modelOverride) {
    const model = sanitizeString(modelOverride || KIRA_MODEL, 100) || KIRA_MODEL;
    // validate messages
    if (!Array.isArray(messages) || messages.length === 0) throw new Error("Invalid messages");
    const safeMessages = messages.slice(0, 20).map(m => ({
        role: ["system","user","assistant"].includes(m.role) ? m.role : "user",
        content: sanitizeString(String(m.content || ""), 8000)
    }));
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    try {
        const client = getKiraClient();
        const completion = await client.chat.completions.create({
            model,
            messages: safeMessages,
            temperature: 0.7,
            max_tokens: 2000
        }, { signal: controller.signal });
        return completion.choices[0]?.message?.content?.trim() || "";
    } finally {
        clearTimeout(timeout);
    }
}

// Nodemailer transporter lazy
let transporter = null;
function getTransporter() {
    if (transporter) return transporter;
    const host = process.env.SMTP_HOST;
    const port = parseInt(process.env.SMTP_PORT || "587", 10);
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;
    if (!host || !user || !pass) {
        console.warn("⚠️  SMTP not fully configured - OTP emails will be logged to console in dev");
        return null;
    }
    transporter = nodemailer.createTransport({
        host,
        port,
        secure: port === 465, // true for 465, false for 587
        auth: { user, pass },
        tls: { rejectUnauthorized: false }
    });
    return transporter;
}
async function sendOtpEmail(toEmail, code) {
    const from = process.env.SMTP_FROM || process.env.SMTP_USER || "noreply@dynamic-api.local";
    const subject = "Your Dynamic API OTP Code";
    const html = `
    <div style="font-family:Inter,Arial,sans-serif;max-width:480px;margin:auto;background:#0f172a;color:#e2e8f0;padding:24px;border-radius:12px">
      <h2 style="color:#38bdf8;margin:0 0 12px">🔐 Verification Code</h2>
      <p style="color:#94a3b8">Use this code to verify your email and manage API keys. Expires in 10 minutes.</p>
      <div style="background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px;text-align:center;margin:16px 0">
        <span style="font-size:32px;letter-spacing:8px;font-weight:800;color:#f8fafc">${code}</span>
      </div>
      <p style="font-size:12px;color:#64748b">If you didn't request this, ignore this email. IP: ${toEmail}</p>
      <hr style="border:none;border-top:1px solid #1e293b;margin:16px 0">
      <p style="font-size:11px;color:#475569">Dynamic API • Kira AI • Personal Use</p>
    </div>`;
    const text = `Your OTP code is ${code}. Expires in 10 minutes.`;
    const tx = getTransporter();
    if (!tx) {
        console.log(`\n📧 [DEV OTP] To: ${toEmail} | Code: ${code}\n`);
        // In dev, return true so flow continues even without SMTP
        if (!isProd) return true;
        throw new Error("SMTP not configured");
    }
    await tx.sendMail({ from, to: toEmail, subject, html, text });
    return true;
}

// Helper to log invalid/expired attempts (non-blocking, masked)
async function logInvalidAttempt(req, attemptedKey, reason, extra = {}) {
    try {
        const database = await getDB();
        const masked = attemptedKey ? maskKey(String(attemptedKey).trim()) : "missing";
        await database.collection("invalid_api_attempts").insertOne({
            timestamp: new Date(),
            ip: getClientIp(req),
            method: req.method,
            path: req.originalUrl || req.url,
            attemptedKeyPreview: masked,
            attemptedKeyHash: attemptedKey ? hashApiKey(String(attemptedKey).trim()).slice(0, 12) + "..." : null, // partial hash for debug, not full
            reason, // invalid_format | missing | invalid | inactive | expired | error
            userAgent: (req.headers["user-agent"] || "").slice(0, 300),
            extra,
        });
        // Also console for Vercel logs
        console.warn(`⚠️ invalid_api_attempt [${reason}] ip=${getClientIp(req)} preview=${masked} path=${req.originalUrl}`);
    } catch (e) { /* never block */ }
}

// ==================== MIDDLEWARES ====================
async function requireApiKey(req, res, next) {
    try {
        const headerKey = req.headers["x-api-key"] || req.headers["authorization"]?.replace(/^Bearer\s+/i, "") || req.query.api_key;
        if (!headerKey) {
            logInvalidAttempt(req, null, "missing");
            return res.status(401).json({ success: false, message: "API key required. Send X-API-Key header or Authorization: Bearer <key>", reason: "missing" });
        }
        const key = String(headerKey).trim();
        if (key.length < 10 || key.length > 128) {
            logInvalidAttempt(req, key, "invalid_format");
            return res.status(401).json({ success: false, message: "Invalid API key format", reason: "invalid_format" });
        }

        const hashed = hashApiKey(key);
        const database = await getDB();
        // Support both new (keyHash) and legacy plaintext (key) during migration — first try active, then check why failed
        const doc = await database.collection("api_keys").findOne({
            $or: [{ keyHash: hashed }, { key: key }, { key: hashed }],
        });
        if (!doc) {
            logInvalidAttempt(req, key, "invalid");
            return res.status(401).json({ success: false, message: "Invalid API key", reason: "invalid" });
        }
        if (!doc.isActive) {
            logInvalidAttempt(req, key, "inactive", { keyId: String(doc._id), name: doc.name });
            return res.status(401).json({ success: false, message: "API key inactive (revoked)", reason: "inactive" });
        }
        if (doc.expiresAt && new Date(doc.expiresAt) < new Date()) {
            logInvalidAttempt(req, key, "expired", { keyId: String(doc._id), name: doc.name, expiresAt: doc.expiresAt });
            return res.status(401).json({ success: false, message: "API key expired", reason: "expired", expiresAt: doc.expiresAt });
        }
        // success — update usage async (non-blocking)
        database.collection("api_keys").updateOne({ _id: doc._id }, { $set: { lastUsedAt: new Date() }, $inc: { usageCount: 1 } }).catch(()=>{});
        req.apiKeyDoc = doc;
        next();
    } catch (e) {
        console.error("requireApiKey error:", e);
        logInvalidAttempt(req, req.headers["x-api-key"] || "", "error", { error: e.message });
        res.status(500).json({ success: false, message: isProd ? "Internal server error" : e.message, reason: "error" });
    }
}

async function requireAdminAuth(req, res, next) {
    try {
        const token = req.headers["x-admin-token"] || req.headers["authorization"]?.replace(/^Bearer\s+/i, "") || req.query.token;
        if (!token) return res.status(401).json({ success: false, message: "Admin token required. Verify OTP first." });
        const database = await getDB();
        const session = await database.collection("admin_sessions").findOne({ token: String(token).trim() });
        if (!session) return res.status(401).json({ success: false, message: "Invalid or expired admin token" });
        if (new Date(session.expiresAt) < new Date()) {
            await database.collection("admin_sessions").deleteOne({ _id: session._id }).catch(()=>{});
            return res.status(401).json({ success: false, message: "Admin session expired, re-verify OTP" });
        }
        req.adminEmail = session.email;
        next();
    } catch (e) {
        res.status(500).json({ success: false, message: isProd ? "Internal server error" : e.message });
    }
}

// Generic error helper - never leak err.message in prod
function sendError(res, err, fallback = "Internal server error", code = 500) {
    console.error(err);
    const msg = isProd ? fallback : (err.message || fallback);
    res.status(code).json({ success: false, message: msg });
}

// ==================== HEALTH & ROOT ====================
app.get("/", (req, res) => {
    res.json({
        success: true,
        service: "Dynamic API v2",
        kira: { baseURL: KIRA_BASE_URL, defaultModel: KIRA_MODEL },
        adminPanel: normalizedAdminBase,
        docs: "Use X-API-Key header for /api/* . Get key via admin panel OTP."
    });
});
app.get("/health", (req, res) => {
    res.json({ success: true, status: "ok", uptime: process.uptime(), env: NODE_ENV });
});

// ==================== ADMIN PANEL & OTP ====================

// Serve minimal admin UI
const adminHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Dynamic API – Admin</title>
<style>
*{box-sizing:border-box;font-family:Inter,system-ui,Segoe UI,Roboto,Arial}
body{margin:0;background:#020617;color:#e2e8f0;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:20px}
.card{width:100%;max-width:860px;background:#0f172a;border:1px solid #1e293b;border-radius:16px;overflow:hidden;box-shadow:0 10px 40px rgba(0,0,0,.5)}
.hdr{padding:20px 24px;border-bottom:1px solid #1e293b;display:flex;justify-content:space-between;align-items:center;gap:12px}
.hdr h1{margin:0;font-size:18px;letter-spacing:.3px}
.badge{font-size:11px;background:#1e40af;color:#bfdbfe;padding:4px 8px;border-radius:999px;border:1px solid #1e3a8a}
.body{padding:24px;display:grid;gap:18px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:700px){.grid{grid-template-columns:1fr}}
.panel{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px}
.panel h3{margin:0 0 10px;font-size:13px;letter-spacing:.4px;color:#38bdf8;text-transform:uppercase}
input{width:100%;background:#0b1220;color:#e2e8f0;border:1px solid #334155;border-radius:8px;padding:10px 12px;outline:none}
input:focus{border-color:#38bdf8;box-shadow:0 0 0 3px rgba(56,189,248,.15)}
button{background:#38bdf8;color:#020617;border:none;border-radius:8px;padding:10px 14px;font-weight:700;cursor:pointer}
button:disabled{opacity:.6;cursor:not-allowed}
button.sec{background:#334155;color:#e2e8f0}
.row{display:flex;gap:8px;align-items:center}
.muted{color:#94a3b8;font-size:12px}
.ok{color:#4ade80;font-size:13px}
.err{color:#f87171;font-size:13px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:10px 8px;border-bottom:1px solid #1e293b;text-align:left;word-break:break-all}
th{color:#94a3b8;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.4px}
.key{font-family:ui-monospace,Menlo,monospace;background:#020617;border:1px solid #1e293b;padding:6px 8px;border-radius:8px;display:inline-block;max-width:420px;overflow:auto}
.actions{display:flex;gap:6px}
.small{font-size:11px}
hr{border:none;border-top:1px solid #1e293b;margin:0}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.7);display:none;align-items:center;justify-content:center;z-index:9999;padding:20px}
.modal.open{display:flex}
.modal-card{background:#0f172a;border:1px solid #334155;border-radius:16px;max-width:520px;width:100%;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.7)}
.modal-hdr{padding:16px 20px;border-bottom:1px solid #1e293b;display:flex;justify-content:space-between;align-items:center}
.modal-hdr h3{margin:0;font-size:14px;color:#f8fafc}
.modal-body{padding:20px;display:grid;gap:12px}
.modal-key{background:#020617;border:1px solid #38bdf8;border-radius:10px;padding:14px;font-family:ui-monospace,Menlo,monospace;word-break:break-all;color:#38bdf8;font-size:13px;position:relative}
.modal-warn{background:#451a03;border:1px solid #9a3412;color:#fed7aa;border-radius:8px;padding:10px;font-size:12px}
.badge-expired{background:#7f1d1d;color:#fecaca;border:1px solid #991b1b;padding:2px 6px;border-radius:999px;font-size:10px}
.badge-active{background:#14532d;color:#bbf7d0;border:1px solid #166534;padding:2px 6px;border-radius:999px;font-size:10px}
.badge-inactive{background:#334155;color:#cbd5e1;border:1px solid #475569;padding:2px 6px;border-radius:999px;font-size:10px}
.badge-invalid{background:#7c2d12;color:#fed7aa;border:1px solid #9a3412;padding:2px 6px;border-radius:999px;font-size:10px}
.tab-active{border-color:#38bdf8 !important;box-shadow:0 0 0 2px rgba(56,189,248,.15)}
.pagination{display:flex;gap:6px;align-items:center;margin-top:8px}
</style>
</head>
<body>
<div class="card">
  <div class="hdr">
    <h1>🔐 Dynamic API – Admin</h1>
    <span class="badge">API Key Manager • Kira AI</span>
  </div>
  <div class="body">
    <div class="panel" id="authPanel">
      <h3>1. Verify via Gmail OTP (SMTP)</h3>
      <div class="row" style="margin-bottom:8px">
        <input id="email" placeholder="admin email (ADMIN_EMAIL)" autocomplete="email"/>
        <button type="button" id="btnSend">Send OTP</button>
      </div>
      <div class="row">
        <input id="code" placeholder="6-digit code" maxlength="6" style="max-width:160px"/>
        <button type="button" id="btnVerify">Verify</button>
        <span id="authMsg" class="muted"></span>
      </div>
      <p class="muted small" style="margin:8px 0 0">OTP sent via SMTP Gmail to your ADMIN_EMAIL. Code expires in 10 min. After verify you get 60-min admin token stored locally.</p>
    </div>

    <div class="grid">
      <div class="panel">
        <h3>2. Create API Key</h3>
        <div class="row" style="margin-bottom:8px">
          <input id="keyName" placeholder="Key name e.g. My Phone / Postman"/>
        </div>
        <div class="row" style="margin-bottom:8px">
          <input id="keyExpiry" type="date" title="Expiry optional"/>
          <button type="button" id="btnCreate">Create UUID Key</button>
        </div>
        <div id="createMsg"></div>
        <p class="muted small">Hashed (SHA-256) storage — full key shown <b>only once in modal</b>. Copy before closing!</p>
      </div>
      <div class="panel">
        <h3>Status</h3>
        <div id="statusBox" class="muted small">Not verified. Send OTP first.</div>
        <div style="margin-top:10px" class="row">
          <button type="button" class="sec small" id="btnRefresh">Refresh Keys</button>
          <button type="button" class="sec small" id="btnLogout">Logout</button>
        </div>
      </div>
    </div>

    <div class="panel">
      <h3>🔑 Your API Keys</h3>
      <div class="row" style="margin-bottom:10px;flex-wrap:wrap">
        <button class="sec small" onclick="filterKeys('all')" id="tabAll">All</button>
        <button class="sec small" onclick="filterKeys('active')" id="tabActive">Active</button>
        <button class="sec small" onclick="filterKeys('expired')" id="tabExpired">Expired</button>
        <button class="sec small" onclick="filterKeys('inactive')" id="tabInactive">Inactive</button>
        <span id="keyCounts" class="muted small" style="margin-left:auto"></span>
      </div>
      <div id="keysBox" class="muted">Verify to load keys…</div>
    </div>

    <div class="panel">
      <h3>📊 Stats — All / Expired / Invalid</h3>
      <div id="statsBox" class="muted small">Verify to load stats…</div>
      <div class="row" style="margin-top:8px">
        <button class="sec small" onclick="loadStats()">Refresh Stats</button>
        <span class="muted small">Shows active/expired/inactive + invalid attempts by reason</span>
      </div>
    </div>

    <div class="panel">
      <h3>⚠️ Invalid & Expired Attempts — All</h3>
      <div class="row" style="margin-bottom:8px;flex-wrap:wrap;gap:6px">
        <select id="reasonFilter" style="background:#0b1220;color:#e2e8f0;border:1px solid #334155;border-radius:8px;padding:8px">
          <option value="">All reasons</option>
          <option value="invalid">invalid</option>
          <option value="invalid_format">invalid_format</option>
          <option value="missing">missing</option>
          <option value="inactive">inactive</option>
          <option value="expired">expired</option>
        </select>
        <button class="sec small" onclick="loadInvalid(1)">Filter</button>
        <button class="sec small" onclick="loadInvalid(currentInvalidPage)">Refresh</button>
        <button class="sec small" style="background:#7f1d1d;color:#fecaca;border:1px solid #991b1b" onclick="clearInvalid()">Clear All</button>
        <span id="invalidInfo" class="muted small"></span>
      </div>
      <div id="invalidBox" class="muted small">Verify to load…</div>
      <div id="expiredKeysBox" class="muted small" style="margin-top:12px"></div>
    </div>

    <div class="muted small" style="text-align:center;padding-top:4px">Use header <code>X-API-Key: &lt;key&gt;</code> or <code>Authorization: Bearer &lt;key&gt;</code> for all <code>/api/*</code>. Base: <span id="baseUrl"></span></div>
  </div>
</div>

<!-- Copy Modal -->
<div id="keyModal" class="modal" onclick="if(event.target===this) closeModal()">
  <div class="modal-card">
    <div class="modal-hdr">
      <h3>🔑 API Key Created</h3>
      <button class="sec small" onclick="closeModal()">✕</button>
    </div>
    <div class="modal-body">
      <div class="modal-warn">⚠️ Copy now — this key is <b>hashed (SHA-256)</b> and will never be shown again. Store securely!</div>
      <div id="modalKeyName" class="muted small"></div>
      <div id="modalKeyValue" class="modal-key"></div>
      <div class="row">
        <button id="btnCopyModal" onclick="copyModalKey()">📋 Copy Key</button>
        <button class="sec" onclick="closeModal()">Done</button>
        <span id="copyMsg" class="muted small"></span>
      </div>
    </div>
  </div>
</div>

<script>
const ADMIN_BASE = "${normalizedAdminBase}";
console.log("Admin base:", ADMIN_BASE);
const qs = s=>document.querySelector(s);
let emailEl, codeEl, authMsg, statusBox, keysBox, createMsg;
function initEls(){
  emailEl=qs('#email'); codeEl=qs('#code'); authMsg=qs('#authMsg'); statusBox=qs('#statusBox'); keysBox=qs('#keysBox'); createMsg=qs('#createMsg');
  const baseUrlEl=qs('#baseUrl'); if(baseUrlEl) baseUrlEl.textContent = location.origin;
}
initEls();
function getToken(){ return localStorage.getItem('admin_token')||''; }
function setToken(t){ if(t) localStorage.setItem('admin_token', t); else localStorage.removeItem('admin_token'); }
function setStatus(msg, ok){ statusBox.innerHTML = msg; statusBox.className = ok ? 'ok small' : 'muted small'; }
function showAuth(m, ok){ authMsg.textContent=m; authMsg.className = ok ? 'ok' : 'err'; }

async function api(path, opts={}){
  const token=getToken();
  const headers={'Content-Type':'application/json', ...(token?{'X-Admin-Token':token}:{}), ...(opts.headers||{})};
  const r = await fetch(ADMIN_BASE + path, { ...opts, headers });
  const j = await r.json().catch(()=>({success:false,message:'Invalid JSON'}));
  if(!r.ok) throw new Error(j.message||('HTTP '+r.status));
  return j;
}

function attachBtn(id, handler){
  const el = qs('#'+id);
  if(!el){ console.error('Missing button', id); return; }
  el.addEventListener('click', handler);
}
attachBtn('btnSend', async ()=>{
  if(!emailEl) initEls();
  const email = (emailEl?.value||'').trim();
  if(!email) return showAuth('Enter email', false);
  showAuth('Sending…', true);
  console.log('Sending OTP to', email, 'via', ADMIN_BASE+'/request-otp');
  try{
    const r = await fetch(ADMIN_BASE+'/request-otp',{method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email})});
    const j = await r.json().catch(()=>({success:false,message:'Invalid JSON '+r.status}));
    console.log('OTP response', r.status, j);
    if(!j.success) throw new Error(j.message || ('HTTP '+r.status));
    showAuth('OTP sent to '+email+' (check Gmail/spam). Dev: check server console if SMTP not set.', true);
    setStatus('OTP sent to '+email+'. Enter code.', true);
  } catch(e){ console.error('OTP send failed', e); showAuth(e.message||String(e),false); }
});

attachBtn('btnVerify', async ()=>{
  if(!emailEl) initEls();
  const email = (emailEl?.value||'').trim(), code = (codeEl?.value||'').trim();
  if(!email||!code) return showAuth('Email + code required', false);
  showAuth('Verifying…', true);
  try{ const j= await fetch(ADMIN_BASE+'/verify-otp',{method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email,code})}).then(r=>r.json()); if(!j.success) throw new Error(j.message); setToken(j.adminToken); showAuth('Verified! Token valid 60 min', true); setStatus('Verified as '+email+'<br>Token: <code class=key>'+j.adminToken.slice(0,16)+'...</code><br>Expires: '+new Date(j.expiresAt).toLocaleString(), true); loadKeys(); loadStats(); loadInvalid(1); } catch(e){ showAuth(e.message,false); }
});

let lastCreatedKey = "";
function openModal(key, name){
  lastCreatedKey = key;
  qs('#modalKeyName').textContent = name ? 'Name: ' + name : '';
  qs('#modalKeyValue').textContent = key;
  qs('#copyMsg').textContent = '';
  qs('#keyModal').classList.add('open');
}
function closeModal(){ qs('#keyModal').classList.remove('open'); }
function copyModalKey(){
  if(!lastCreatedKey) return;
  navigator.clipboard.writeText(lastCreatedKey).then(()=>{
    qs('#copyMsg').textContent='Copied!'; qs('#copyMsg').className='ok small';
    setTimeout(()=> qs('#copyMsg').textContent='', 1500);
  }).catch(()=>{ qs('#copyMsg').textContent='Copy failed, select manually'; });
}
window.closeModal=closeModal; window.copyModalKey=copyModalKey;

qs('#btnCreate').onclick = async ()=>{
  const name = qs('#keyName').value.trim() || 'Key '+new Date().toLocaleString();
  const expiresAt = qs('#keyExpiry').value ? new Date(qs('#keyExpiry').value).toISOString() : null;
  if(!getToken()) return createMsg.innerHTML='<span class=err>Verify OTP first</span>';
  createMsg.innerHTML='<span class=muted>Creating…</span>';
  try{
    const j = await api('/createapikey', {method:'POST', body:JSON.stringify({name, expiresAt})});
    createMsg.innerHTML = '<span class=ok>Created! Opening modal…</span>';
    openModal(j.key, j.name);
    loadKeys(); loadStats();
  } catch(e){ createMsg.innerHTML='<span class=err>'+e.message+'</span>'; }
};

qs('#btnRefresh').onclick = ()=>{ loadKeys(); loadStats(); };
qs('#btnLogout').onclick = ()=>{ setToken(''); setStatus('Logged out. Token cleared.', false); keysBox.innerHTML='<span class=muted>Verify to load keys…</span>'; qs('#statsBox').innerHTML='<span class=muted>Verify to load stats…</span>'; qs('#invalidBox').innerHTML='<span class=muted>Verify to load…</span>'; showAuth('Logged out', true); };

let allKeysCache = [];
let currentKeyFilter = 'all';
let currentInvalidPage = 1;

function isExpired(k){ return k.expiresAt && new Date(k.expiresAt) <= new Date(); }
function getKeyStatus(k){
  if (!k.isActive) return 'inactive';
  if (isExpired(k)) return 'expired';
  return 'active';
}
function badgeForStatus(s){
  if(s==='expired') return '<span class="badge-expired">expired</span>';
  if(s==='active') return '<span class="badge-active">active</span>';
  if(s==='inactive') return '<span class="badge-inactive">inactive</span>';
  return '';
}
function renderKeys(){
  if(!allKeysCache.length){ keysBox.innerHTML='<span class=muted>No keys yet. Create one above.</span>'; qs('#keyCounts').textContent=''; return; }
  let filtered = allKeysCache;
  if(currentKeyFilter!=='all') filtered = allKeysCache.filter(k=> getKeyStatus(k)===currentKeyFilter);
  ['all','active','expired','inactive'].forEach(f=>{
    const btn=qs('#tab'+f.charAt(0).toUpperCase()+f.slice(1));
    if(btn) btn.classList.toggle('tab-active', f===currentKeyFilter);
  });
  const counts = {all:allKeysCache.length, active:allKeysCache.filter(k=>getKeyStatus(k)==='active').length, expired:allKeysCache.filter(k=>isExpired(k)).length, inactive:allKeysCache.filter(k=>!k.isActive).length};
  qs('#keyCounts').textContent = 'All:' + counts.all + ' Active:' + counts.active + ' Expired:' + counts.expired + ' Inactive:' + counts.inactive + ' | Showing:' + filtered.length;
  if(!filtered.length){ keysBox.innerHTML='<span class=muted>No '+currentKeyFilter+' keys</span>'; return; }
  let html = '<table><tr><th>Name</th><th>Key (masked)</th><th>Status</th><th>Created</th><th>Uses</th><th></th></tr>';
  filtered.forEach(k=>{
    const created = new Date(k.createdAt).toLocaleDateString();
    const preview = k.keyPreview || k.preview || (k.key ? (k.key.length===64 ? k.key.slice(0,8)+'••••••••'+k.key.slice(-4) : k.key.slice(0,8)+'••••••••'+k.key.slice(-4)) : '••••');
    const status = getKeyStatus(k);
    const badge = badgeForStatus(status);
    const expiresInfo = k.expiresAt ? '<br><span class="muted small">exp:'+new Date(k.expiresAt).toLocaleDateString()+'</span>' : '';
    const keyCell = '<code class=key title="Hashed - full key not retrievable">'+preview+'</code> <span class="muted small">(hashed)</span>';
    html += '<tr><td>'+(k.name||'-')+'</td><td>'+keyCell+'</td><td>'+badge+expiresInfo+'</td><td>'+created+'</td><td>'+(k.usageCount||0)+'</td><td class=actions><button class="sec small" onclick="revoke(\''+k._id+'\')">delete</button></td></tr>';
  });
  html+='</table>';
  keysBox.innerHTML = html;
}
function filterKeys(f){ currentKeyFilter=f; renderKeys(); }

async function loadKeys(){
  if(!getToken()){ keysBox.innerHTML='<span class=err>Not verified. Enter OTP first.</span>'; return; }
  keysBox.innerHTML='<span class=muted>Loading…</span>';
  try{
    const j = await api('/keys');
    allKeysCache = j.keys || [];
    renderKeys();
    setStatus('Loaded '+allKeysCache.length+' key(s). Token: '+(getToken().slice(0,16))+'...', true);
  } catch(e){ keysBox.innerHTML='<span class=err>'+e.message+'</span>'; }
}
async function loadStats(){
  if(!getToken()) return;
  const box=qs('#statsBox');
  box.innerHTML='<span class=muted>Loading stats…</span>';
  try{
    const j = await api('/stats');
    const k=j.keys, inv=j.invalidAttempts;
    box.innerHTML = \`
      <div class="row" style="flex-wrap:wrap;gap:8px">
        <span class="badge-active">Active: \${k.active}</span>
        <span class="badge-expired">Expired: \${k.expired}</span>
        <span class="badge-inactive">Inactive: \${k.inactive}</span>
        <span class="badge" style="background:#1e293b;border:1px solid #334155">Total keys: \${k.total}</span>
        <span class="badge-invalid">Invalid attempts: \${inv.total}</span>
      </div>
      <div class="muted small" style="margin-top:8px">By reason: \${Object.entries(inv.byReason||{}).map(([r,c])=> r+':'+c).join(' • ') || 'none'} \${inv.lastAt ? '<br>Last invalid: '+new Date(inv.lastAt).toLocaleString() : ''}</div>
    \`;
  } catch(e){ box.innerHTML='<span class=err>'+e.message+'</span>'; }
}
async function loadInvalid(page=1){
  if(!getToken()){ qs('#invalidBox').innerHTML='<span class=err>Not verified</span>'; return; }
  currentInvalidPage=page;
  const reason = qs('#reasonFilter').value;
  const box=qs('#invalidBox'), info=qs('#invalidInfo'), expBox=qs('#expiredKeysBox');
  box.innerHTML='<span class=muted>Loading…</span>';
  try{
    const j = await api('/invalid-attempts?limit=50&page='+page + (reason ? '&reason='+encodeURIComponent(reason) : ''));
    info.textContent = \`Total:\${j.total} Page:\${j.page}/\${j.pages}\`;
    if(!j.logs.length){ box.innerHTML='<span class=muted>No invalid attempts yet (all good!)</span>'; }
    else {
      let html='<table><tr><th>Time</th><th>Reason</th><th>Preview</th><th>IP</th><th>Path</th></tr>';
      j.logs.forEach(l=>{
        const t=new Date(l.timestamp).toLocaleString();
        const badge = l.reason==='expired' ? 'badge-expired' : l.reason==='invalid' ? 'badge-invalid' : l.reason==='inactive' ? 'badge-inactive' : 'badge';
        html+=\`<tr><td>\${t}</td><td><span class="\${badge}">\${l.reason}</span></td><td><code class=key>\${l.attemptedKeyPreview||'••••'}</code></td><td>\${l.ip}</td><td style="max-width:200px;overflow:auto">\${l.path||''}</td></tr>\`;
      });
      html+='</table>';
      html+=\`<div class="pagination">\`;
      if(j.page>1) html+=\`<button class="sec small" onclick="loadInvalid(\${j.page-1})">Prev</button>\`;
      if(j.page<j.pages) html+=\`<button class="sec small" onclick="loadInvalid(\${j.page+1})">Next</button>\`;
      html+=\`</div>\`;
      box.innerHTML=html;
    }
    if(j.expiredKeys && j.expiredKeys.length){
      let h='<div class="muted small" style="margin-top:8px"><b>Expired Keys (masked):</b></div><table><tr><th>Name</th><th>Preview</th><th>Expired At</th></tr>';
      j.expiredKeys.forEach(k=>{
        h+=\`<tr><td>\${k.name||'-'}</td><td><code class=key>\${k.keyPreview||''}</code></td><td>\${new Date(k.expiresAt).toLocaleString()} <span class="badge-expired">expired</span></td></tr>\`;
      });
      h+='</table>';
      expBox.innerHTML=h;
    } else expBox.innerHTML='<span class="muted small">No expired keys</span>';
  } catch(e){ box.innerHTML='<span class=err>'+e.message+'</span>'; }
}
async function clearInvalid(){
  if(!confirm('Clear all invalid attempt logs?')) return;
  try{ const j=await api('/invalid-attempts', {method:'DELETE'}); alert('Cleared '+j.deleted+' logs'); loadInvalid(1); loadStats(); } catch(e){ alert(e.message); }
}
async function revoke(id){
  if(!confirm('Delete this API key? This cannot be undone.')) return;
  try{ await api('/keys/'+id, {method:'DELETE'}); loadKeys(); loadStats(); } catch(e){ alert(e.message); }
}
window.revoke=revoke; window.filterKeys=filterKeys; window.loadInvalid=loadInvalid; window.clearInvalid=clearInvalid; window.loadStats=loadStats;
// auto load if token exists
if(getToken()){ setStatus('Token found in local storage, loading…', true); loadKeys(); loadStats(); loadInvalid(1); }
</script>
</body>
</html>`;

app.get(normalizedAdminBase, (req, res) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    // No cache for admin panel
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
    res.send(adminHTML);
});
// support trailing slash
app.get(normalizedAdminBase + "/", (req, res) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.send(adminHTML);
});

// OTP request
app.post(`${normalizedAdminBase}/request-otp`, otpLimiter, async (req, res) => {
    try {
        const email = String(req.body?.email || "").toLowerCase().trim();
        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ success: false, message: "Valid email required" });
        }
        // Personal use: only ADMIN_EMAIL allowed
        if (ADMIN_EMAIL && email !== ADMIN_EMAIL) {
            // small delay to prevent enumeration
            await new Promise(r => setTimeout(r, 600));
            return res.status(403).json({ success: false, message: "Email not authorized for this personal instance" });
        }
        // Generate code
        const code = String(crypto.randomInt(100000, 999999));
        const database = await getDB();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
        // upsert: delete previous otps for this email
        await database.collection("otps").deleteMany({ email });
        await database.collection("otps").insertOne({
            email,
            code,
            expiresAt,
            attempts: 0,
            createdAt: new Date(),
            ip: getClientIp(req)
        });
        try {
            await sendOtpEmail(email, code);
        } catch (mailErr) {
            console.error("sendOtpEmail fail:", mailErr);
            if (isProd) return res.status(500).json({ success: false, message: "Failed to send email. Check SMTP config." });
            // in dev, still succeed and leak code for testing
            return res.json({ success: true, message: `OTP generated (SMTP failed in dev, code: ${code})`, devCode: code });
        }
        res.json({ success: true, message: `OTP sent to ${email} (valid 10 min). Check Gmail/spam.` });
    } catch (e) { sendError(res, e, "Failed to send OTP"); }
});

app.post(`${normalizedAdminBase}/verify-otp`, async (req, res) => {
    try {
        const email = String(req.body?.email || "").toLowerCase().trim();
        const code = String(req.body?.code || "").trim();
        if (!email || !code) return res.status(400).json({ success: false, message: "Email and code required" });
        const database = await getDB();
        const otp = await database.collection("otps").findOne({ email, code });
        if (!otp) {
            // increment attempts if exists
            return res.status(400).json({ success: false, message: "Invalid code" });
        }
        if (new Date(otp.expiresAt) < new Date()) {
            await database.collection("otps").deleteOne({ _id: otp._id });
            return res.status(400).json({ success: false, message: "Code expired, request new one" });
        }
        // success - delete otp
        await database.collection("otps").deleteOne({ _id: otp._id });
        // create admin session
        const token = crypto.randomUUID();
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 60 min
        await database.collection("admin_sessions").insertOne({
            token,
            email,
            expiresAt,
            createdAt: new Date(),
            ip: getClientIp(req)
        });
        res.json({ success: true, message: "Verified", adminToken: token, expiresAt });
    } catch (e) { sendError(res, e, "Verification failed"); }
});

// Admin API - list keys (masked, never expose plaintext hash as copyable)
app.get(`${normalizedAdminBase}/keys`, requireAdminAuth, async (req, res) => {
    try {
        const database = await getDB();
        const keys = await database.collection("api_keys").find({}).sort({ createdAt: -1 }).limit(100).toArray();
        // Sanitize: ensure preview exists, don't leak full plaintext (already hashed, but mask hash too)
        const sanitized = keys.map(k => ({
            _id: k._id,
            name: k.name,
            keyPreview: k.keyPreview || (k.key ? maskKey(k.key) : "••••"),
            keyHash: k.keyHash || (isHashedKey(k.key) ? k.key : undefined),
            // keep raw `key` masked for legacy UI that expects k.key — we send preview there too if hashed
            key: isHashedKey(k.key) ? (k.keyPreview || maskKey(k.key)) : maskKey(k.key || ""),
            email: k.email,
            createdAt: k.createdAt,
            lastUsedAt: k.lastUsedAt,
            usageCount: k.usageCount,
            isActive: k.isActive,
            expiresAt: k.expiresAt
        }));
        res.json({ success: true, keys: sanitized });
    } catch (e) { sendError(res, e); }
});
app.get(`${normalizedAdminBase}/createapikey`, requireAdminAuth, async (req, res) => {
    // convenience GET -> list (same sanitized)
    const database = await getDB();
    const keys = await database.collection("api_keys").find({}).sort({ createdAt: -1 }).limit(100).toArray();
    const sanitized = keys.map(k => ({
        _id: k._id,
        name: k.name,
        keyPreview: k.keyPreview || (k.key ? maskKey(k.key) : "••••"),
        key: isHashedKey(k.key) ? (k.keyPreview || maskKey(k.key)) : maskKey(k.key || ""),
        email: k.email,
        createdAt: k.createdAt,
        lastUsedAt: k.lastUsedAt,
        usageCount: k.usageCount,
        isActive: k.isActive,
        expiresAt: k.expiresAt
    }));
    res.json({ success: true, keys: sanitized, hint: "POST to this endpoint with {name} to create" });
});

// === NEW: Stats + Invalid/Expired logs (all visible from admin) ===
app.get(`${normalizedAdminBase}/stats`, requireAdminAuth, async (req, res) => {
    try {
        const database = await getDB();
        const now = new Date();
        const allKeys = await database.collection("api_keys").find({}).toArray();
        const active = allKeys.filter(k => k.isActive && (!k.expiresAt || new Date(k.expiresAt) > now)).length;
        const expired = allKeys.filter(k => k.expiresAt && new Date(k.expiresAt) <= now).length;
        const inactive = allKeys.filter(k => !k.isActive).length;
        const total = allKeys.length;
        const invalidCount = await database.collection("invalid_api_attempts").countDocuments({});
        const lastInvalid = await database.collection("invalid_api_attempts").find({}).sort({ timestamp: -1 }).limit(1).toArray();
        const byReason = await database.collection("invalid_api_attempts").aggregate([
            { $group: { _id: "$reason", count: { $sum: 1 } } }
        ]).toArray();
        res.json({
            success: true,
            keys: { total, active, expired, inactive },
            invalidAttempts: {
                total: invalidCount,
                lastAt: lastInvalid[0]?.timestamp || null,
                byReason: Object.fromEntries(byReason.map(r => [r._id, r.count]))
            }
        });
    } catch (e) { sendError(res, e); }
});

app.get(`${normalizedAdminBase}/invalid-attempts`, requireAdminAuth, async (req, res) => {
    try {
        const database = await getDB();
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || "50", 10)));
        const page = Math.max(1, parseInt(req.query.page || "1", 10));
        const skip = (page - 1) * limit;
        const reason = req.query.reason ? String(req.query.reason).trim() : null;
        const filter = reason ? { reason } : {};
        const total = await database.collection("invalid_api_attempts").countDocuments(filter);
        const logs = await database.collection("invalid_api_attempts").find(filter).sort({ timestamp: -1 }).skip(skip).limit(limit).toArray();
        // also return expired keys list for "expired" tab convenience
        const expiredKeys = await database.collection("api_keys").find({ expiresAt: { $lte: new Date() } }).sort({ expiresAt: -1 }).limit(50).toArray();
        const sanitizedExpired = expiredKeys.map(k => ({
            _id: k._id, name: k.name, keyPreview: k.keyPreview || maskKey(k.key || ""), expiresAt: k.expiresAt, isActive: k.isActive, usageCount: k.usageCount
        }));
        res.json({ success: true, total, page, limit, pages: Math.ceil(total / limit), logs, expiredKeys: sanitizedExpired });
    } catch (e) { sendError(res, e); }
});

app.delete(`${normalizedAdminBase}/invalid-attempts`, requireAdminAuth, async (req, res) => {
    try {
        const database = await getDB();
        const r = await database.collection("invalid_api_attempts").deleteMany({});
        res.json({ success: true, deleted: r.deletedCount });
    } catch (e) { sendError(res, e); }
});

// Backfill thumbnails for existing docs (admin only) - handles old images without thumbs
app.post(`${normalizedAdminBase}/backfill-thumbnails`, requireAdminAuth, async (req, res) => {
    try {
        const collection = sanitizeString(String(req.body?.collection || "hourlyhealthreport"), 64) || "hourlyhealthreport";
        if (!isValidCollection(collection)) return res.status(400).json({ success: false, message: "Invalid collection" });
        const limit = Math.min(200, Math.max(1, parseInt(req.body?.limit || "20", 10)));
        const dryRun = !!req.body?.dryRun;
        const database = await getDB();
        // Find docs that have FILE_UPLOAD but no thumbnails yet (or thumbnails empty)
        const candidates = await database.collection(collection).find({
            $and: [
                { "data.fields": { $elemMatch: { type: "FILE_UPLOAD" } } },
                { $or: [ { thumbnails: { $exists: false } }, { thumbnails: { $size: 0 } }, { thumbnailAt: { $exists: false } } ] }
            ]
        }).sort({ createdAt: -1 }).limit(limit).toArray();
        if (dryRun) {
            return res.json({ success: true, dryRun: true, found: candidates.length, sampleIds: candidates.slice(0,5).map(c=>c._id) });
        }
        let processed = 0, failed = 0, details = [];
        for (const doc of candidates) {
            try {
                const r = await processThumbnailsForDoc(collection, doc._id, doc.data);
                processed++;
                details.push({ id: doc._id, processed: r.processed, results: r.results });
            } catch (e) {
                failed++;
                details.push({ id: doc._id, error: e.message });
            }
            // small delay to avoid hammering
            await new Promise(r=>setTimeout(r, 300));
        }
        // also count remaining
        const remaining = await database.collection(collection).countDocuments({
            "data.fields": { $elemMatch: { type: "FILE_UPLOAD" } },
            $or: [ { thumbnails: { $exists: false } }, { thumbnails: { $size: 0 } }, { thumbnailAt: { $exists: false } } ]
        });
        res.json({ success: true, processed, failed, remaining, details: details.slice(0,20) });
    } catch (e) { sendError(res, e); }
});

// Create API key - uuid minimal + SHA256 hashing (hashed storage)
app.post(`${normalizedAdminBase}/createapikey`, requireAdminAuth, async (req, res) => {
    try {
        const name = sanitizeString(String(req.body?.name || `Key ${new Date().toLocaleDateString()}`), 100) || `Key ${Date.now()}`;
        let expiresAt = null;
        if (req.body?.expiresAt) {
            const d = new Date(req.body.expiresAt);
            if (!isNaN(d.getTime()) && d > new Date()) expiresAt = d;
        }
        // Minimal UUID key: dyn_ + uuid without dashes + 8 hex (plaintext shown only once)
        const uuidPart = uuidv4().replace(/-/g, "");
        const rand = crypto.randomBytes(4).toString("hex");
        const key = `dyn_${uuidPart}${rand}`;
        const keyHash = hashApiKey(key);
        const keyPreview = maskKey(key);
        const database = await getDB();
        const doc = {
            keyHash,
            key: keyHash, // keep `key` as hash for legacy unique index, plaintext never stored
            keyPreview,
            name,
            email: req.adminEmail,
            createdAt: new Date(),
            lastUsedAt: null,
            usageCount: 0,
            isActive: true,
            expiresAt
        };
        const result = await database.collection("api_keys").insertOne(doc);
        // Return plaintext ONLY once for modal copy — never stored
        res.status(201).json({ success: true, message: "API key created — copy now, hashed storage", key, keyPreview, keyHash, id: result.insertedId, name, expiresAt });
    } catch (e) {
        if (e.code === 11000) return res.status(409).json({ success: false, message: "Key collision, retry" });
        sendError(res, e);
    }
});
// alias POST /keys (same as /createapikey, hashed)
app.post(`${normalizedAdminBase}/keys`, requireAdminAuth, async (req, res) => {
    try {
        const name = sanitizeString(String(req.body?.name || `Key ${new Date().toLocaleDateString()}`), 100) || `Key ${Date.now()}`;
        const uuidPart = uuidv4().replace(/-/g, "");
        const rand = crypto.randomBytes(4).toString("hex");
        const key = `dyn_${uuidPart}${rand}`;
        const keyHash = hashApiKey(key);
        const keyPreview = maskKey(key);
        const database = await getDB();
        let expiresAt = null;
        if (req.body?.expiresAt) {
            const d = new Date(req.body.expiresAt);
            if (!isNaN(d.getTime()) && d > new Date()) expiresAt = d;
        }
        const result = await database.collection("api_keys").insertOne({
            keyHash, key: keyHash, keyPreview, name, email: req.adminEmail, createdAt: new Date(), lastUsedAt: null, usageCount: 0, isActive: true, expiresAt
        });
        res.status(201).json({ success: true, message: "API key created — copy now, hashed storage", key, keyPreview, keyHash, id: result.insertedId, name, expiresAt });
    } catch (e) {
        if (e.code === 11000) return res.status(409).json({ success: false, message: "Key collision, retry" });
        sendError(res, e);
    }
});

app.delete(`${normalizedAdminBase}/keys/:id`, requireAdminAuth, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidObjectId(id)) return res.status(400).json({ success: false, message: "Invalid key id" });
        const database = await getDB();
        const result = await database.collection("api_keys").deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) return res.status(404).json({ success: false, message: "Key not found" });
        res.json({ success: true, message: "Key deleted" });
    } catch (e) { sendError(res, e); }
});
app.patch(`${normalizedAdminBase}/keys/:id`, requireAdminAuth, async (req, res) => {
    try {
        const id = req.params.id;
        if (!isValidObjectId(id)) return res.status(400).json({ success: false, message: "Invalid key id" });
        const update = {};
        if (typeof req.body.isActive === "boolean") update.isActive = req.body.isActive;
        if (req.body.name) update.name = sanitizeString(String(req.body.name), 100);
        if (!Object.keys(update).length) return res.status(400).json({ success: false, message: "Nothing to update" });
        const database = await getDB();
        await database.collection("api_keys").updateOne({ _id: new ObjectId(id) }, { $set: update });
        res.json({ success: true, message: "Updated" });
    } catch (e) { sendError(res, e); }
});

// ==================== KIRA DYNAMIC PROXY (protected) ====================
// List models - dynamic
app.get("/api/kira/models", requireApiKey, apiLimiter, async (req, res) => {
    try {
        const clientK = getKiraClient();
        // Kira supports /models via OpenAI SDK or fetch
        try {
            const list = await clientK.models.list();
            return res.json({ success: true, models: list.data });
        } catch {
            // fallback fetch
            const fetchRes = await fetch(`${KIRA_BASE_URL}/models`, {
                headers: { Authorization: `Bearer ${KIRA_API_KEY}` }
            });
            const j = await fetchRes.json();
            return res.json({ success: true, models: j.data || j });
        }
    } catch (e) { sendError(res, e, "Failed to fetch Kira models"); }
});
app.get("/api/kira/voices", requireApiKey, apiLimiter, async (req, res) => {
    try {
        const r = await fetch(`${KIRA_BASE_URL}/audio/voices`, {
            headers: { Authorization: `Bearer ${KIRA_API_KEY}` }
        });
        const j = await r.json();
        res.json({ success: true, voices: j });
    } catch (e) { sendError(res, e, "Failed to fetch voices"); }
});
// Generic chat proxy - fully dynamic
app.post("/api/kira/chat", requireApiKey, apiLimiter, async (req, res) => {
    try {
        const { model, messages, temperature, max_tokens } = req.body || {};
        if (!Array.isArray(messages) || messages.length === 0) {
            return res.status(400).json({ success: false, message: "messages array required [{role, content}]" });
        }
        if (messages.length > 50) return res.status(400).json({ success: false, message: "Too many messages (max 50)" });
        const safeModel = sanitizeString(String(model || KIRA_MODEL), 100) || KIRA_MODEL;
        const safeMessages = messages.slice(0, 50).map(m => ({
            role: ["system","user","assistant","tool"].includes(m.role) ? m.role : "user",
            content: sanitizeString(String(m.content || ""), 12000)
        }));
        const opts = {
            model: safeModel,
            messages: safeMessages,
        };
        if (typeof temperature === "number") opts.temperature = Math.min(2, Math.max(0, temperature));
        if (typeof max_tokens === "number") opts.max_tokens = Math.min(8000, Math.max(1, max_tokens));

        const clientK = getKiraClient();
        const controller = new AbortController();
        const t = setTimeout(()=>controller.abort(), 25000);
        try {
            const completion = await clientK.chat.completions.create(opts, { signal: controller.signal });
            res.json({ success: true, model: safeModel, usage: completion.usage, choices: completion.choices, raw: completion });
        } finally { clearTimeout(t); }
    } catch (e) { sendError(res, e, isProd ? "Kira chat failed" : e.message, 500); }
});
// Image generation - dynamic
app.post("/api/kira/images", requireApiKey, apiLimiter, async (req, res) => {
    try {
        const prompt = sanitizeString(String(req.body?.prompt || ""), 3000);
        if (!prompt) return res.status(400).json({ success: false, message: "prompt required" });
        const model = sanitizeString(String(req.body?.model || KIRA_IMAGE_MODEL), 100) || KIRA_IMAGE_MODEL;
        const aspect_ratio = ["1:1","16:9","9:16","4:3","3:4"].includes(req.body?.aspect_ratio) ? req.body.aspect_ratio : "1:1";
        const r = await fetch(`${KIRA_BASE_URL}/images/generations`, {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${KIRA_API_KEY}` },
            body: JSON.stringify({ model, prompt, aspect_ratio })
        });
        const j = await r.json();
        if (!r.ok) return res.status(r.status).json({ success: false, message: j.error?.message || "Image generation failed", details: isProd ? undefined : j });
        res.json({ success: true, data: j });
    } catch (e) { sendError(res, e, "Image generation failed"); }
});
// TTS - dynamic
app.post("/api/kira/tts", requireApiKey, apiLimiter, async (req, res) => {
    try {
        const input = sanitizeString(String(req.body?.input || ""), 4000);
        if (!input) return res.status(400).json({ success: false, message: "input text required" });
        const model = sanitizeString(String(req.body?.model || KIRA_TTS_MODEL), 100) || KIRA_TTS_MODEL;
        const voice = sanitizeString(String(req.body?.voice || "alloy"), 50) || "alloy";
        const r = await fetch(`${KIRA_BASE_URL}/audio/speech`, {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${KIRA_API_KEY}` },
            body: JSON.stringify({ model, input, voice })
        });
        if (!r.ok) {
            const j = await r.json().catch(()=>({}));
            return res.status(r.status).json({ success: false, message: j.error?.message || "TTS failed" });
        }
        const arrayBuffer = await r.arrayBuffer();
        res.setHeader("Content-Type", "audio/mpeg");
        res.setHeader("Content-Length", arrayBuffer.byteLength);
        res.send(Buffer.from(arrayBuffer));
    } catch (e) { sendError(res, e, "TTS failed"); }
});
// Video generation - dynamic (async)
app.post("/api/kira/videos", requireApiKey, apiLimiter, async (req, res) => {
    try {
        const prompt = sanitizeString(String(req.body?.prompt || ""), 2000);
        if (!prompt) return res.status(400).json({ success: false, message: "prompt required" });
        const model = sanitizeString(String(req.body?.model || "kira-3.0-video"), 100);
        const r = await fetch(`${KIRA_BASE_URL}/videos/generations`, {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${KIRA_API_KEY}` },
            body: JSON.stringify({ model, prompt })
        });
        const j = await r.json();
        if (!r.ok) return res.status(r.status).json({ success: false, message: j.error?.message || "Video generation failed", details: isProd?undefined:j });
        res.json({ success: true, data: j });
    } catch (e) { sendError(res, e, "Video generation failed"); }
});
app.get("/api/kira/videos/:id", requireApiKey, apiLimiter, async (req, res) => {
    try {
        const id = sanitizeString(String(req.params.id), 100);
        const r = await fetch(`${KIRA_BASE_URL}/videos/operations/${encodeURIComponent(id)}`, {
            headers: { Authorization: `Bearer ${KIRA_API_KEY}` }
        });
        const j = await r.json();
        res.status(r.status).json(j);
    } catch (e) { sendError(res, e, "Video status failed"); }
});

// ==================== DYNAMIC CRUD (protected, fixed vulnerabilities) ====================

// Helper to build pagination
function parsePagination(req) {
    let limit = parseInt(req.query.limit || "20", 10);
    let page = parseInt(req.query.page || "1", 10);
    let skip = parseInt(req.query.skip || "0", 10);
    if (isNaN(limit) || limit < 1) limit = 20;
    if (limit > 100) limit = 100;
    if (isNaN(page) || page < 1) page = 1;
    if (isNaN(skip) || skip < 0) skip = 0;
    if (req.query.skip === undefined) skip = (page - 1) * limit;
    // sort: e.g., ?sort=-timestamp or ?sort=timestamp
    let sort = { _id: -1 };
    if (req.query.sort) {
        const s = String(req.query.sort).trim();
        if (s.startsWith("-")) sort = { [s.slice(1)]: -1 };
        else sort = { [s]: 1 };
        // whitelist sort fields to prevent abuse
        const allowedSort = ["timestamp","createdAt","sync_timestamp","_id","name"];
        const field = Object.keys(sort)[0];
        if (!allowedSort.includes(field)) sort = { _id: -1 };
    }
    return { limit, skip, sort, page };
}

// 1. CREATE with Kira auto-tag+analysis (dynamic, sanitized, mass-assignment fixed) - hourlyhealthreport is public for Tally webhook (hobby)
app.post("/api/:collection", globalLimiter, async (req, res, next) => {
    const colCheck = req.params.collection;
    if (colCheck === "hourlyhealthreport") {
        // Try API key if provided (query/header), but allow Tally webhook without key (has eventType/data.fields)
        const hasKey = req.headers["x-api-key"] || req.headers["authorization"] || req.query.api_key;
        const isTally = req.body && (req.body.eventType === "FORM_RESPONSE" || req.body.data);
        if (hasKey) return requireApiKey(req, res, next);
        if (isTally) return next(); // allow Tally without key
        // For hobby: allow hourlyhealthreport without key (rate limited), but log
        console.warn(`⚠️ public POST hourlyhealthreport from ${getClientIp(req)} without key - allowed for Tally`);
        return next();
    }
    return requireApiKey(req, res, next);
}, apiLimiter, async (req, res) => {
    try {
        const collection = req.params.collection;
        if (!isValidCollection(collection)) return res.status(400).json({ success: false, message: "Invalid collection name" });
        // Prevent accessing internal collections
        if (["api_keys","otps","admin_sessions"].includes(collection)) {
            return res.status(403).json({ success: false, message: "Forbidden collection" });
        }
        // Whitelist: only allow `data` field from client, ignore everything else (fixes mass assignment)
        if (!req.body || typeof req.body.data === "undefined") {
            return res.status(400).json({ success: false, message: "data field required in body {data: ...}" });
        }
        // Validate data size after sanitization
        const rawData = req.body.data;
        // quick size check
        const jsonLen = JSON.stringify(rawData).length;
        if (jsonLen > 20000) return res.status(400).json({ success: false, message: "data too large (max 20kb stringified)" });

        const extractedText = extractNotes(rawData);
        if (!extractedText) return res.status(400).json({ success: false, message: "No extractable notes found" });

        // Kira dynamic: allow per-request model override via headers or body._kira
        const tagModel = sanitizeString(String(req.body._kiraModel || req.headers["x-kira-model"] || KIRA_MODEL), 100) || KIRA_MODEL;
        const customTagPrompt = req.body._kiraTagPrompt ? sanitizeString(String(req.body._kiraTagPrompt), 3000) : null;
        const customAnalysisPrompt = req.body._kiraAnalysisPrompt ? sanitizeString(String(req.body._kiraAnalysisPrompt), 5000) : null;

        let aiTags = "";
        let aiAnalysis = "";

        // Only call Kira if key configured, else save without AI
        if (KIRA_API_KEY) {
            try {
                const tagSystem = customTagPrompt || DEFAULT_TAG_PROMPT;
                const analysisSystem = customAnalysisPrompt || DEFAULT_ANALYSIS_PROMPT;
                const tagPromise = callKiraChat([
                    { role: "system", content: tagSystem },
                    { role: "user", content: `Log: ${extractedText}` }
                ], tagModel);
                const analysisPromise = callKiraChat([
                    { role: "system", content: analysisSystem },
                    { role: "user", content: `Log: ${extractedText}` }
                ], tagModel);

                const [tagsResult, analysisResult] = await Promise.allSettled([tagPromise, analysisPromise]);
                if (tagsResult.status === "fulfilled") aiTags = xss(String(tagsResult.value).slice(0, 500));
                else console.error("Kira tag failed:", tagsResult.reason?.message);

                if (analysisResult.status === "fulfilled") aiAnalysis = xss(String(analysisResult.value).slice(0, 8000));
                else console.error("Kira analysis failed:", analysisResult.reason?.message);
            } catch (aiError) {
                console.error("Critical Kira failure (saving anyway):", aiError.message);
            }
        } else {
            console.warn("Skipping Kira AI - KIRA_API_KEY missing");
        }

        // Sanitized save - no spread, whitelist only
        const sanitizedData = JSON.parse(JSON.stringify(rawData)); // deep clone
        sanitizeMongo(sanitizedData);

        const dataToSave = {
            data: sanitizedData,
            tags: aiTags,
            ai_analysis: aiAnalysis,
            timestamp: new Date(),
            createdByKey: req.apiKeyDoc ? String(req.apiKeyDoc._id) : (req.body?.eventType ? "tally-webhook" : "public"),
            createdBy: req.apiKeyDoc ? req.apiKeyDoc.name : "public",
            // keep original requested collection for audit
        };

        const database = await getDB();
        const result = await database.collection(collection).insertOne(dataToSave);

        // Generate 25kb webp + Telegram at NEW ENTRY time (await, not fire-and-forget - Vercel kills background)
        let thumbResult = null;
        try {
            // 4s timeout so Tally webhook doesn't hang
            thumbResult = await Promise.race([
                processThumbnailsForDoc(collection, result.insertedId, sanitizedData),
                new Promise((_, rej) => setTimeout(() => rej(new Error("thumb timeout 4s")), 4000))
            ]);
            if (thumbResult?.processed) console.log(`✅ thumbnails at insert for ${collection}/${result.insertedId}:`, thumbResult.results);
        } catch (e) {
            console.warn(`⚠️ thumb at insert failed/timeout for ${result.insertedId}:`, e.message);
            // fallback: fire-and-forget for remaining (if timeout)
            setImmediate(() => processThumbnailsForDoc(collection, result.insertedId, sanitizedData).catch(()=>{}));
        }

        res.status(201).json({
            success: true,
            insertedId: result.insertedId,
            tags: aiTags,
            ai_analysis: aiAnalysis ? "Generated" : (KIRA_API_KEY ? "Failed" : "Skipped (no KIRA_API_KEY)"),
            modelUsed: tagModel,
            thumbnails: thumbResult?.results || []
        });
    } catch (err) { sendError(res, err, "Failed to create", 500); }
});

// 1.5 Burp Journal Sync - strict validation
app.post("/api/burp-journal/sync", requireApiKey, apiLimiter, async (req, res) => {
    try {
        const database = await getDB();
        const collection = "burp_journal_logs";
        // Validate body shape, limit arrays
        const body = req.body || {};
        if (typeof body !== "object" || Array.isArray(body)) return res.status(400).json({ success: false, message: "Invalid body" });
        // sanitize and limit
        const sanitized = {};
        // Only allow known keys, strip others
        const allowedTop = ["events","states","meta","data"];
        for (const k of allowedTop) if (body[k] !== undefined) sanitized[k] = body[k];
        // limit array lengths
        if (Array.isArray(sanitized.events) && sanitized.events.length > 1000) return res.status(400).json({ success: false, message: "events too many (max 1000)" });
        if (Array.isArray(sanitized.states) && sanitized.states.length > 1000) return res.status(400).json({ success: false, message: "states too many (max 1000)" });
        sanitizeMongo(sanitized);

        const dataToSave = {
            ...sanitized,
            sync_timestamp: new Date(),
            createdByKey: String(req.apiKeyDoc._id)
        };
        const result = await database.collection(collection).insertOne(dataToSave);
        res.status(201).json({ success: true, message: "Burp journal synced", insertedId: result.insertedId });
    } catch (err) { sendError(res, err, "Burp sync failed"); }
});

// 2. Manual Analysis Generator - Kira
app.post("/api/:collection/analyze/:id", requireApiKey, apiLimiter, async (req, res) => {
    try {
        const collection = req.params.collection;
        const id = req.params.id;
        if (!isValidCollection(collection)) return res.status(400).json({ success: false, message: "Invalid collection name" });
        if (!isValidObjectId(id)) return res.status(400).json({ success: false, message: "Invalid id format" });
        if (["api_keys","otps","admin_sessions"].includes(collection)) return res.status(403).json({ success: false, message: "Forbidden" });

        const database = await getDB();
        const record = await database.collection(collection).findOne({ _id: new ObjectId(id) });
        if (!record) return res.status(404).json({ success: false, message: "Record not found" });

        const extractedText = extractNotes(record.data);
        if (!extractedText) return res.status(400).json({ success: false, message: "No notes to analyze" });

        const model = sanitizeString(String(req.body?.model || req.headers["x-kira-model"] || KIRA_MODEL), 100) || KIRA_MODEL;
        const newAnalysis = await callKiraChat([
            { role: "system", content: sanitizeString(String(req.body?.systemPrompt || DEFAULT_ANALYSIS_PROMPT), 5000) || DEFAULT_ANALYSIS_PROMPT },
            { role: "user", content: `Here is the health log: ${extractedText}` }
        ], model);

        if (!newAnalysis) return res.status(502).json({ success: false, message: "Kira returned empty" });

        const safeAnalysis = xss(String(newAnalysis).slice(0, 8000));
        await database.collection(collection).updateOne({ _id: new ObjectId(id) }, { $set: { ai_analysis: safeAnalysis, ai_reanalyzed_at: new Date() } });

        res.json({ success: true, message: "Analysis generated", ai_analysis: safeAnalysis, model });
    } catch (err) { sendError(res, err, isProd ? "Analysis failed" : err.message); }
});

// Fix route order: comment patch BEFORE generic patch
// 6. UPDATE COMMENT (specific - must be before generic /:id)
app.patch("/api/:collection/comment/:id", requireApiKey, apiLimiter, async (req, res) => {
    try {
        const collection = req.params.collection;
        const id = req.params.id;
        if (!isValidCollection(collection)) return res.status(400).json({ success: false, message: "Invalid collection name" });
        if (!isValidObjectId(id)) return res.status(400).json({ success: false, message: "Invalid id format" });
        const comment = sanitizeString(String(req.body?.comment || ""), 2000);
        if (!comment) return res.status(400).json({ success: false, message: "comment required (max 2000 chars)" });

        const database = await getDB();
        const result = await database.collection(collection).updateOne(
            { _id: new ObjectId(id) },
            { $set: { comment, comment_updated_at: new Date() } }
        );
        if (result.matchedCount === 0) return res.status(404).json({ success: false, message: "Record not found" });
        res.json({ success: true, message: "Comment updated", result });
    } catch (err) { sendError(res, err); }
});

// 3. READ ALL with pagination (fixes DoS) - hourlyhealthreport is public for Health Journal (hobby), others need API key
app.get("/api/:collection", globalLimiter, async (req, res, next) => {
    const colCheck = req.params.collection;
    if (colCheck === "hourlyhealthreport") return next();
    return requireApiKey(req, res, next);
}, apiLimiter, async (req, res) => {
    try {
        const collection = req.params.collection;
        if (!isValidCollection(collection)) return res.status(400).json({ success: false, message: "Invalid collection name" });
        if (["api_keys","otps","admin_sessions"].includes(collection)) return res.status(403).json({ success: false, message: "Forbidden" });

        const { limit, skip, sort, page } = parsePagination(req);
        const database = await getDB();
        const col = database.collection(collection);

        // Date filter for Health Journal: ?date=YYYY-MM-DD (IST) or ?from=&to= ISO
        let filter = {};
        const dateParam = String(req.query.date || "").trim();
        const fromParam = String(req.query.from || "").trim();
        const toParam = String(req.query.to || "").trim();
        if (dateParam && /^\d{4}-\d{2}-\d{2}$/.test(dateParam)) {
            // IST day 00:00 to 23:59:59.999 => UTC = IST -5:30
            const istOffsetMs = 5.5 * 60 * 60 * 1000;
            const startIst = new Date(dateParam + "T00:00:00.000+05:30");
            const endIst = new Date(dateParam + "T23:59:59.999+05:30");
            if (!isNaN(startIst.getTime()) && !isNaN(endIst.getTime())) {
                filter = { $or: [
                    { createdAt: { $gte: startIst, $lte: endIst } },
                    { timestamp: { $gte: startIst, $lte: endIst } },
                    // fallback: also match data.fields Date value == dateParam (string match for tally)
                    { "data.fields": { $elemMatch: { type: { $in: ["INPUT_DATE", "DATE"] }, value: dateParam } } }
                ]};
            }
        } else if (fromParam || toParam) {
            const gte = fromParam ? new Date(fromParam) : null;
            const lte = toParam ? new Date(toParam) : null;
            const range = {};
            if (gte && !isNaN(gte.getTime())) range.$gte = gte;
            if (lte && !isNaN(lte.getTime())) range.$lte = lte;
            if (Object.keys(range).length) filter = { createdAt: range };
        }

        const total = await col.countDocuments(filter);
        const data = await col.find(filter).sort(sort).skip(skip).limit(limit).toArray();

        // enrich with thumbUrls for frontend (non-blocking, ignore errors)
        try { await enrichWithThumbUrls(data, collection); } catch {}

        res.json({
            success: true,
            data,
            pagination: { total, page, limit, skip, pages: Math.ceil(total / limit) }
        });
    } catch (err) { sendError(res, err); }
});

// 4. READ ONE - hourlyhealthreport public, others protected
app.get("/api/:collection/:id", globalLimiter, async (req, res, next) => {
    const colCheck = req.params.collection;
    if (colCheck === "hourlyhealthreport") return next();
    return requireApiKey(req, res, next);
}, apiLimiter, async (req, res) => {
    try {
        const collection = req.params.collection;
        const id = req.params.id;
        if (!isValidCollection(collection)) return res.status(400).json({ success: false, message: "Invalid collection name" });
        if (!isValidObjectId(id)) return res.status(400).json({ success: false, message: "Invalid id format" });
        const database = await getDB();
        const data = await database.collection(collection).findOne({ _id: new ObjectId(id) });
        if (!data) return res.status(404).json({ success: false, message: "Not found" });
        try { await enrichWithThumbUrls([data], collection); } catch {}
        res.json({ success: true, data });
    } catch (err) { sendError(res, err); }
});

// 5. UPDATE (General) - whitelist, no $set: req.body
app.patch("/api/:collection/:id", requireApiKey, apiLimiter, async (req, res) => {
    try {
        const collection = req.params.collection;
        const id = req.params.id;
        if (!isValidCollection(collection)) return res.status(400).json({ success: false, message: "Invalid collection name" });
        if (!isValidObjectId(id)) return res.status(400).json({ success: false, message: "Invalid id format" });
        if (["api_keys","otps","admin_sessions"].includes(collection)) return res.status(403).json({ success: false, message: "Forbidden" });

        // Whitelist update: only allow `data` field (and maybe comment via dedicated route)
        const allowed = {};
        if (req.body.data !== undefined) {
            const jsonLen = JSON.stringify(req.body.data).length;
            if (jsonLen > 20000) return res.status(400).json({ success: false, message: "data too large" });
            const clone = JSON.parse(JSON.stringify(req.body.data));
            sanitizeMongo(clone);
            allowed.data = clone;
        } else {
            return res.status(400).json({ success: false, message: "Nothing to update. Send {data: ...}" });
        }
        // Optional: allow updating tags? no, restrict
        allowed.updatedAt = new Date();
        allowed.updatedByKey = String(req.apiKeyDoc._id);

        const database = await getDB();
        const result = await database.collection(collection).updateOne(
            { _id: new ObjectId(id) },
            { $set: allowed }
        );
        if (result.matchedCount === 0) return res.status(404).json({ success: false, message: "Not found" });
        res.json({ success: true, result });
    } catch (err) { sendError(res, err); }
});

// ==================== THUMBNAIL PROXY (25kb webp, public for frontend) ====================
// Frontend: <img src="https://dynamicapi.rohits.online/api/hourlyhealthreport/<id>/thumb?idx=0">
// No API key required for thumbs (rate limited) - thumbs are small & cacheable 1d
// Also supports /thumb/:idx
async function serveThumb(req, res) {
    try {
        const collection = req.params.collection;
        const id = req.params.id;
        let idx = req.params.idx !== undefined ? parseInt(req.params.idx, 10) : parseInt(req.query.idx || req.query.i || "0", 10);
        if (!isValidCollection(collection)) return res.status(400).json({ success: false, message: "Invalid collection" });
        if (!isValidObjectId(id)) return res.status(400).json({ success: false, message: "Invalid id" });
        if (isNaN(idx) || idx < 0) idx = 0;
        if (["api_keys","otps","admin_sessions","thumbnails"].includes(collection)) return res.status(403).json({ success: false, message: "Forbidden" });
        const database = await getDB();
        // try cache first
        let thumb = await database.collection("thumbnails").findOne({ collection, docId: new ObjectId(id), idx });
        // on-demand generate if missing (backfill for old docs)
        if (!thumb) {
            const doc = await database.collection(collection).findOne({ _id: new ObjectId(id) });
            if (!doc) return res.status(404).json({ success: false, message: "Document not found" });
            const images = extractTallyImages(doc.data);
            if (!images[idx]) return res.status(404).json({ success: false, message: "No image at idx " + idx });
            if (!sharp) return res.status(503).json({ success: false, message: "Thumbnail service unavailable (sharp missing)" });
            // generate now (sync, ~300ms) - handles image/video/pdf/other via placeholder
            try {
                const r = await fetch(images[idx].url);
                if (!r.ok) return res.status(502).json({ success: false, message: "Failed to fetch original" });
                const buf = Buffer.from(await r.arrayBuffer());
                const ct = r.headers.get("content-type") || images[idx].mimeType || "";
                const { buffer: webpBuf, size, quality, kind, placeholder } = await generateWebpThumbnail(buf, images[idx].name, ct);
                thumb = { buffer: webpBuf, mimeType: "image/webp", thumbSize: size, quality, kind };
                const tg = await uploadToTelegram(webpBuf, `${collection}/${id} #${idx} [${kind}] on-demand ${size}B${placeholder?" placeholder":""}`);
                await database.collection("thumbnails").updateOne(
                    { collection, docId: new ObjectId(id), idx },
                    { $set: { collection, docId: new ObjectId(id), idx, origUrl: images[idx].url, origName: images[idx].name, origMime: ct, kind, isPlaceholder: !!placeholder, createdAt: new Date(), thumbSize: size, thumbWidth: THUMB_WIDTH, quality, mimeType: "image/webp", buffer: webpBuf, telegram: tg ? { file_id: tg.file_id, file_unique_id: tg.file_unique_id } : null } },
                    { upsert: true }
                );
            } catch (e) {
                return res.status(500).json({ success: false, message: "Thumb generation failed: " + e.message });
            }
        }
        const buf = thumb.buffer?.buffer ? Buffer.from(thumb.buffer.buffer || thumb.buffer) : thumb.buffer;
        // Extract actual Buffer (stored as BSON Binary)
        let outBuf = buf;
        if (thumb.buffer && thumb.buffer.buffer) outBuf = Buffer.from(thumb.buffer.buffer);
        else if (Buffer.isBuffer(thumb.buffer)) outBuf = thumb.buffer;
        else if (thumb.buffer && typeof thumb.buffer === "object" && thumb.buffer.type === "Buffer") outBuf = Buffer.from(thumb.buffer.data);
        else outBuf = Buffer.from(thumb.buffer);
        res.setHeader("Content-Type", thumb.mimeType || "image/webp");
        res.setHeader("Cache-Control", "public, max-age=86400, immutable");
        res.setHeader("Content-Length", outBuf.length);
        res.setHeader("ETag", `"${collection}-${id}-${idx}-${outBuf.length}"`);
        res.setHeader("X-Thumb-Size", String(outBuf.length));
        res.setHeader("X-Thumb-Quality", String(thumb.quality || ""));
        // Tiny CORS for frontend <img>
        res.setHeader("Access-Control-Allow-Origin", "*");
        return res.send(outBuf);
    } catch (e) {
        console.error("serveThumb error:", e);
        res.status(500).json({ success: false, message: isProd ? "Thumb failed" : e.message });
    }
}
// two routes: ?idx=0 and /:idx
app.get("/api/:collection/:id/thumb", globalLimiter, serveThumb);
app.get("/api/:collection/:id/thumb/:idx", globalLimiter, serveThumb);

// helper to inject thumbUrls into list/detail responses (optional, for frontend convenience)
async function enrichWithThumbUrls(docs, collection) {
    if (!Array.isArray(docs) || !docs.length) return;
    const database = await getDB();
    const ids = docs.map(d => d._id);
    const thumbs = await database.collection("thumbnails").find({ collection, docId: { $in: ids } }).project({ docId: 1, idx: 1 }).toArray();
    const map = {};
    for (const t of thumbs) {
        const k = String(t.docId);
        if (!map[k]) map[k] = [];
        map[k].push(t.idx);
    }
    const base = process.env.PUBLIC_BASE_URL || "";
    for (const d of docs) {
        const k = String(d._id);
        const idxs = map[k];
        if (idxs && idxs.length) {
            d.thumbUrls = idxs.sort((a,b)=>a-b).map(i => `/api/${collection}/${d._id}/thumb?idx=${i}`);
            d.thumbCount = idxs.length;
        } else {
            // fallback pattern - frontend can try anyway (on-demand will generate)
            const imgs = extractTallyImages(d.data);
            if (imgs.length) {
                d.thumbUrls = imgs.map((_, i) => `/api/${collection}/${d._id}/thumb?idx=${i}`);
                d.thumbCount = imgs.length;
                d.thumbPending = true;
            }
        }
        // full proxy URLs for convenience
        if (d.thumbUrls) d.thumbBase = base;
    }
}

// 7. DELETE
app.delete("/api/:collection/:id", requireApiKey, apiLimiter, async (req, res) => {
    try {
        const collection = req.params.collection;
        const id = req.params.id;
        if (!isValidCollection(collection)) return res.status(400).json({ success: false, message: "Invalid collection name" });
        if (!isValidObjectId(id)) return res.status(400).json({ success: false, message: "Invalid id format" });
        if (["api_keys","otps","admin_sessions"].includes(collection)) return res.status(403).json({ success: false, message: "Forbidden" });

        const database = await getDB();
        const result = await database.collection(collection).deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) return res.status(404).json({ success: false, message: "Not found" });
        res.json({ success: true, result });
    } catch (err) { sendError(res, err); }
});

// ==================== 404 & GLOBAL ERROR ====================
app.use((req, res) => {
    res.status(404).json({ success: false, message: "Route not found" });
});
app.use((err, req, res, next) => {
    console.error("Unhandled error:", err);
    if (err.message === "CORS blocked") return res.status(403).json({ success: false, message: "CORS not allowed" });
    if (err.type === "entity.too.large" || err.status === 413) {
        return res.status(413).json({ success: false, message: "Payload too large (max 1mb)" });
    }
    const code = err.status || 500;
    const msg = isProd ? "Internal server error" : (err.message || "Internal server error");
    res.status(code).json({ success: false, message: msg });
});

// ==================== START ====================
let server = null;
async function start() {
    try {
        // Attempt DB connect early - but don't crash if DB unreachable (allows health check in dev)
        if (process.env.MONGODB_URI && !process.env.MONGODB_URI.includes("user:pass")) {
            try { await getDB(); } catch (dbErr) {
                console.warn("⚠️  Initial DB connect failed (will retry on request):", dbErr.message);
            }
        } else if (process.env.MONGODB_URI?.includes("user:pass")) {
            console.warn("⚠️  MONGODB_URI is placeholder - set real URI in .env. DB will connect on first request.");
        }
        server = app.listen(PORT, () => {
            console.log(`🚀 Secure Dynamic API v2 running on port ${PORT}`);
            console.log(`🔐 Admin panel: http://localhost:${PORT}${normalizedAdminBase}`);
            console.log(`🤖 Kira AI: ${KIRA_BASE_URL} (model: ${KIRA_MODEL})`);
            console.log(`🛡️  Env: ${NODE_ENV} | CORS: ${CORS_ORIGIN || (isProd ? "DENY" : "open(dev)")} | BodyLimit: 1mb | RateLimit: 60/min | Helmet: on`);
        });
        // Graceful shutdown
        const shut = async () => {
            console.log("\n🛑 Shutting down...");
            try { await client.close(); } catch {}
            server.close(()=>process.exit(0));
            setTimeout(()=>process.exit(0), 5000);
        };
        process.on("SIGINT", shut);
        process.on("SIGTERM", shut);
    } catch (e) {
        console.error("Startup failed:", e);
        process.exit(1);
    }
}
if (require.main === module) start();

module.exports = app;
