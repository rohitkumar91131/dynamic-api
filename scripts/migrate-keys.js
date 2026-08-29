#!/usr/bin/env node
// Build-time migration: hash existing plaintext API keys (dyn_...) to SHA-256
// Idempotent — safe to run on every build/start
require("dotenv").config();
const crypto = require("crypto");
const { MongoClient, ObjectId } = require("mongodb");

function hashApiKey(key) {
  return crypto.createHash("sha256").update(String(key)).digest("hex");
}
function isHashedKey(str) {
  return typeof str === "string" && /^[a-f0-9]{64}$/.test(str);
}
function maskKey(key) {
  const s = String(key);
  if (s.length <= 12) return s.slice(0, 4) + "****";
  return s.slice(0, 8) + "••••••••" + s.slice(-4);
}

async function run() {
  const uri = process.env.MONGODB_URI;
  if (!uri || uri.includes("user:pass")) {
    console.log("⏭️  migrate-keys: MONGODB_URI not set or placeholder — skipping");
    return;
  }
  const dbName = process.env.DATABASE_NAME || undefined;
  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 8000 });
  try {
    await client.connect();
    const db = dbName ? client.db(dbName) : client.db();
    const col = db.collection("api_keys");
    const all = await col.find({}).toArray();
    if (!all.length) {
      console.log("✅ migrate-keys: no keys to migrate");
      return;
    }
    let migrated = 0, skipped = 0, failed = 0;
    for (const doc of all) {
      try {
        const rawKey = doc.key; // may be plaintext or already hash
        const hasHash = doc.keyHash && isHashedKey(doc.keyHash);
        // If already hashed (keyHash exists and key is hash or preview exists), skip
        if (hasHash && isHashedKey(rawKey)) {
          // Ensure keyPreview exists
          if (!doc.keyPreview) {
            await col.updateOne({ _id: doc._id }, { $set: { keyPreview: maskKey(rawKey) } });
          }
          skipped++;
          continue;
        }
        // If key is plaintext (dyn_...) or not hashed
        if (rawKey && !isHashedKey(rawKey)) {
          // This is plaintext — hash it
          const hashed = hashApiKey(rawKey);
          const preview = doc.keyPreview || maskKey(rawKey);
          // Check if hash already exists (collision due to re-run)
          const exists = await col.findOne({ keyHash: hashed, _id: { $ne: doc._id } });
          if (exists) {
            console.warn(`⚠️  migrate-keys: hash collision for ${doc._id}, skipping`);
            failed++;
            continue;
          }
          await col.updateOne(
            { _id: doc._id },
            {
              $set: {
                keyHash: hashed,
                key: hashed, // overwrite plaintext with hash (legacy field kept as hash)
                keyPreview: preview,
                migratedAt: new Date(),
              },
            }
          );
          console.log(`🔐 migrated ${doc._id} (${doc.name || "unnamed"}) ${preview}`);
          migrated++;
        } else if (rawKey && isHashedKey(rawKey) && !hasHash) {
          // key is already hash but keyHash missing — backfill
          await col.updateOne(
            { _id: doc._id },
            { $set: { keyHash: rawKey, keyPreview: doc.keyPreview || maskKey(rawKey) } }
          );
          skipped++;
        } else {
          skipped++;
        }
      } catch (e) {
        console.error(`❌ migrate-keys failed for ${doc._id}:`, e.message);
        failed++;
      }
    }
    // Ensure indexes
    try {
      await col.createIndex({ keyHash: 1 }, { unique: true, sparse: true });
      await col.createIndex({ key: 1 }, { unique: true, sparse: true });
    } catch {}
    console.log(`✅ migrate-keys done: migrated=${migrated}, skipped=${skipped}, failed=${failed}, total=${all.length}`);
  } catch (e) {
    console.error("❌ migrate-keys error:", e.message);
    // Don't crash build — log and continue
    if (process.env.NODE_ENV === "production") process.exit(0);
  } finally {
    try { await client.close(); } catch {}
  }
}

if (require.main === module) run();
module.exports = { run, hashApiKey, isHashedKey, maskKey };
