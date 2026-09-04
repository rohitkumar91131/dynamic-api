#!/usr/bin/env node
// Bulk backfill 25kb webp thumbnails for existing docs that have FILE_UPLOAD but no thumbnails
// Usage: MONGODB_URI=... DATABASE_NAME=... node scripts/backfill-thumbnails.js [limit]
// Or via admin panel: POST /admin-secure-xyz123/backfill-thumbnails {limit:20, collection:"hourlyhealthreport"} with X-Admin-Token
require("dotenv").config();
const { MongoClient, ObjectId } = require("mongodb");
let sharp = null;
try { sharp = require("sharp"); } catch (e) { console.error("sharp missing - npm install"); process.exit(1); }
const crypto = require("crypto");

const THUMB_MAX_KB = parseInt(process.env.THUMB_MAX_KB || "25", 10);
const THUMB_WIDTH = parseInt(process.env.THUMB_WIDTH || "320", 10);
const THUMB_QUALITY = parseInt(process.env.THUMB_QUALITY || "65", 10);
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || "";

function detectFileKind(buf, fileName, mimeHint) {
    const name = String(fileName||"").toLowerCase();
    const mime = String(mimeHint||"").toLowerCase();
    if (mime.startsWith("image/") || /\.(jpe?g|png|webp|gif|bmp|tiff|heic|avif)$/i.test(name)) return "image";
    if (mime.startsWith("video/") || /\.(mp4|mov|avi|webm|mkv|m4v|3gp)$/i.test(name)) return "video";
    if (mime === "application/pdf" || /\.pdf$/i.test(name)) return "pdf";
    if (mime.startsWith("audio/") || /\.(mp3|wav|ogg|m4a|aac|flac)$/i.test(name)) return "audio";
    if (buf && buf.length >= 4) {
        if (buf[0]===0xFF && buf[1]===0xD8) return "image";
        if (buf[0]===0x89 && buf[1]===0x50) return "image";
        if (buf[0]===0x25 && buf[1]===0x50) return "pdf";
        if (buf.slice(4,8).toString()==="ftyp") return "video";
    }
    return "other";
}
async function generatePlaceholderWebp(label, subLabel) {
    const w = THUMB_WIDTH, h = Math.round(w * 0.66);
    const bg = label==="video" ? "#0f172a" : label==="pdf" ? "#451a03" : label==="audio" ? "#14532d" : "#1e293b";
    const accent = label==="video" ? "#38bdf8" : label==="pdf" ? "#f87171" : label==="audio" ? "#4ade80" : "#94a3b8";
    const icon = label==="video" ? "▶" : label==="pdf" ? "PDF" : label==="audio" ? "♫" : "FILE";
    const svg = `<svg width="${w}" height="${h}" xmlns="http://www.w3.org/2000/svg"><rect width="100%" height="100%" rx="12" fill="${bg}"/><rect x="12" y="12" width="${w-24}" height="${h-24}" rx="10" fill="none" stroke="${accent}" stroke-opacity="0.3" stroke-width="1.5" stroke-dasharray="6 4"/><text x="50%" y="42%" dominant-baseline="middle" text-anchor="middle" font-family="Inter,Arial,sans-serif" font-size="42" font-weight="800" fill="${accent}">${icon}</text><text x="50%" y="62%" dominant-baseline="middle" text-anchor="middle" font-family="Inter,Arial,sans-serif" font-size="11" font-weight="700" fill="#e2e8f0">${String(subLabel||label).slice(0,24).toUpperCase()}</text></svg>`;
    const buf = await sharp(Buffer.from(svg)).webp({ quality: THUMB_QUALITY, effort: 6 }).toBuffer();
    return { buffer: buf, quality: THUMB_QUALITY, size: buf.length, placeholder: true, kind: label };
}
async function generateWebpThumbnail(inputBuffer, fileNameHint, mimeHint) {
    const kind = detectFileKind(inputBuffer, fileNameHint, mimeHint);
    if (kind !== "image") return generatePlaceholderWebp(kind, fileNameHint ? fileNameHint.split('.').pop() : kind);
    const targetBytes = THUMB_MAX_KB * 1024;
    const qualities = [THUMB_QUALITY, 60, 50, 40, 30, 20];
    let best = null;
    for (const q of qualities) {
        try {
            const buf = await sharp(inputBuffer).rotate().resize({ width: THUMB_WIDTH, withoutEnlargement: true }).webp({ quality: q, effort: 6 }).toBuffer();
            best = buf;
            if (buf.length <= targetBytes) return { buffer: buf, quality: q, size: buf.length, kind: "image" };
        } catch (e) { return generatePlaceholderWebp("image", "image"); }
    }
    if (best && best.length > targetBytes) {
        try {
            const smaller = await sharp(inputBuffer).rotate().resize({ width: 240, withoutEnlargement: true }).webp({ quality: 30, effort: 6 }).toBuffer();
            return { buffer: smaller, quality: 30, size: smaller.length, kind: "image" };
        } catch { return generatePlaceholderWebp("image", "image"); }
    }
    return { buffer: best, quality: qualities[qualities.length-1], size: best.length, kind: "image" };
}
async function uploadToTelegram(webpBuffer, caption="") {
    if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return null;
    try {
        const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendPhoto`;
        const form = new FormData();
        form.append("chat_id", TELEGRAM_CHAT_ID);
        form.append("photo", new Blob([webpBuffer], { type: "image/webp" }), "thumb.webp");
        if (caption) form.append("caption", String(caption).slice(0,900));
        const controller = new AbortController();
        const t = setTimeout(()=>controller.abort(), 15000);
        try {
            const res = await fetch(url, { method: "POST", body: form, signal: controller.signal });
            const j = await res.json().catch(()=>null);
            if (!res.ok || !j?.ok) { console.warn("Telegram upload failed", j?.description); return null; }
            const photos = j.result?.photo || [];
            const largest = photos[photos.length-1];
            return { file_id: largest?.file_id, file_unique_id: largest?.file_unique_id, message_id: j.result?.message_id };
        } finally { clearTimeout(t); }
    } catch(e){ console.warn("uploadToTelegram error",e.message); return null; }
}
function extractTallyImages(data) {
    const urls = [];
    try {
        if (data && data.fields && Array.isArray(data.fields)) {
            for (const f of data.fields) {
                if (f.type === "FILE_UPLOAD" && Array.isArray(f.value)) {
                    for (const file of f.value) {
                        if (file && file.url) urls.push({ url: String(file.url), name: String(file.name||"file"), id: String(file.id||""), mimeType: String(file.mimeType||""), size: file.size||0 });
                    }
                }
            }
        }
    } catch {}
    return urls;
}

async function backfill(limit = 20, collection = "hourlyhealthreport") {
    const uri = process.env.MONGODB_URI;
    const dbName = process.env.DATABASE_NAME || undefined;
    if (!uri || uri.includes("user:pass")) { console.error("MONGODB_URI not set"); process.exit(1); }
    const client = new MongoClient(uri, { serverSelectionTimeoutMS: 8000 });
    await client.connect();
    const db = dbName ? client.db(dbName) : client.db();
    const col = db.collection(collection);
    const thumbCol = db.collection("thumbnails");
    await thumbCol.createIndex({ collection:1, docId:1, idx:1 }, { unique:true }).catch(()=>{});
    const candidates = await col.find({
        $and: [
            { "data.fields": { $elemMatch: { type: "FILE_UPLOAD" } } },
            { $or: [ { thumbnails: { $exists: false } }, { thumbnails: { $size: 0 } }, { thumbnailAt: { $exists: false } } ] }
        ]
    }).sort({ createdAt: -1 }).limit(limit).toArray();
    console.log(`Found ${candidates.length} docs to backfill (limit ${limit})`);
    let ok=0, fail=0;
    for (const doc of candidates) {
        const images = extractTallyImages(doc.data);
        if (!images.length) { console.log(`skip ${doc._id} no images`); continue; }
        console.log(`\nProcessing ${doc._id} (${images.length} files) ...`);
        const results = [];
        for (let idx=0; idx < images.length; idx++) {
            const img = images[idx];
            try {
                const controller = new AbortController();
                const t = setTimeout(()=>controller.abort(), 15000);
                let buf, ct = img.mimeType;
                try {
                    const r = await fetch(img.url, { signal: controller.signal });
                    if (!r.ok) throw new Error(`fetch ${r.status}`);
                    ct = r.headers.get("content-type") || ct;
                    buf = Buffer.from(await r.arrayBuffer());
                } finally { clearTimeout(t); }
                const { buffer: webpBuf, quality, size, kind, placeholder } = await generateWebpThumbnail(buf, img.name, ct);
                console.log(`  [${idx}] ${kind} ${buf.length} -> ${size}B q=${quality}${placeholder?" placeholder":""}`);
                const tg = await uploadToTelegram(webpBuf, `${collection}/${doc._id} #${idx} [${kind}] ${img.name} backfill`);
                await thumbCol.updateOne({ collection, docId: doc._id, idx }, { $set: { collection, docId: doc._id, idx, origUrl: img.url, origName: img.name, origMime: ct, kind, isPlaceholder: !!placeholder, createdAt: new Date(), thumbSize: size, thumbWidth: THUMB_WIDTH, quality, mimeType: "image/webp", buffer: webpBuf, telegram: tg ? { file_id: tg.file_id, file_unique_id: tg.file_unique_id } : null } }, { upsert: true });
                results.push({ idx, size, quality, kind });
            } catch(e) { console.warn(`  [${idx}] fail`, e.message); results.push({ idx, error: e.message }); }
        }
        await col.updateOne({ _id: doc._id }, { $set: { thumbnails: results, thumbnailAt: new Date() } });
        ok++;
        await new Promise(r=>setTimeout(r, 400));
    }
    const remaining = await col.countDocuments({ "data.fields": { $elemMatch: { type: "FILE_UPLOAD" } }, $or: [ { thumbnails: { $exists: false } }, { thumbnails: { $size: 0 } }, { thumbnailAt: { $exists: false } } ] });
    console.log(`\n✅ Backfill done: ok=${ok} fail=${fail} remaining=${remaining}`);
    await client.close();
}

if (require.main === module) {
    const limit = parseInt(process.argv[2] || "20", 10);
    const collection = process.argv[3] || "hourlyhealthreport";
    backfill(limit, collection).catch(e=>{ console.error(e); process.exit(1); });
}
module.exports = { backfill };
