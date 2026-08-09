require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const Groq = require("groq-sdk"); 

const app = express();

app.use(cors());
app.use(express.json({ limit: "50mb" }));

// MongoDB and Groq Clients
const client = new MongoClient(process.env.MONGODB_URI);
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

let db = null;

// Serverless-friendly MongoDB Connection
async function getDB() {
    if (!db) {
        await client.connect();
        db = client.db();
        console.log("✅ MongoDB Connected");
    }
    return db;
}

// Collection name validation
function isValidCollection(name) {
    return /^[a-zA-Z0-9_-]+$/.test(name);
}

// 🌟 REUSABLE PROMPT LOGIC 🌟
const systemPrompt = `You are an empathetic and smart health assistant. Your task is to analyze daily health logs.
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

function extractNotes(data) {
    if (data && data.fields && Array.isArray(data.fields)) {
        return data.fields.map(f => `${f.label}: ${f.value}`).join(", ");
    }
    return JSON.stringify(data);
}


// 1. CREATE with Failsafe AI Analysis
app.post("/api/:collection", async (req, res) => {
    try {
        const collection = req.params.collection;

        if (!isValidCollection(collection)) {
            return res.status(400).json({ success: false, message: "Invalid collection name" });
        }

        const extractedText = extractNotes(req.body.data);
        const userPrompt = `Here is the health log: ${extractedText}`;
        
        let groqAnalysis = ""; // Default empty string

        // AI CALL IN SEPARATE TRY-CATCH (Taki fail ho toh app crash na kare)
        try {
            const chatCompletion = await groq.chat.completions.create({
                messages: [
                    { role: "system", content: systemPrompt },
                    { role: "user", content: userPrompt }
                ],
                model: "groq/compound", 
            });
            groqAnalysis = chatCompletion.choices[0]?.message?.content || "";
        } catch (aiError) {
            console.error("⚠️ Groq AI API Failed, but saving data anyway:", aiError.message);
            // groqAnalysis will remain ""
        }

        // Original data ke saath Groq ka analysis jodna
        const dataToSave = {
            ...req.body,
            ai_analysis: groqAnalysis,
            timestamp: new Date()
        };

        // Database connect aur save karna
        const database = await getDB();
        const result = await database
            .collection(collection)
            .insertOne(dataToSave);

        res.status(201).json({
            success: true,
            insertedId: result.insertedId,
            analysis: groqAnalysis
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: err.message });
    }
});


// 2. NEW ROUTE: MANUAL AI ANALYSIS GENERATOR
app.post("/api/:collection/analyze/:id", async (req, res) => {
    try {
        const collection = req.params.collection;
        const id = req.params.id;

        if (!isValidCollection(collection)) {
            return res.status(400).json({ success: false, message: "Invalid collection name" });
        }

        const database = await getDB();
        const record = await database.collection(collection).findOne({ _id: new ObjectId(id) });

        if (!record) {
            return res.status(404).json({ success: false, message: "Record not found" });
        }

        // Extract clean notes from the DB record
        const extractedText = extractNotes(record.data);
        const userPrompt = `Here is the health log: ${extractedText}`;

        // Call Groq AI
        const chatCompletion = await groq.chat.completions.create({
            messages: [
                { role: "system", content: systemPrompt },
                { role: "user", content: userPrompt }
            ],
            model: "groq/compound", 
        });

        const newAnalysis = chatCompletion.choices[0]?.message?.content || "";

        if (!newAnalysis) {
            return res.status(500).json({ success: false, message: "AI returned empty response" });
        }

        // Update DB with the new analysis
        await database.collection(collection).updateOne(
            { _id: new ObjectId(id) },
            { $set: { ai_analysis: newAnalysis } }
        );

        res.json({
            success: true,
            message: "Analysis generated and saved",
            ai_analysis: newAnalysis
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: err.message });
    }
});


// 3. READ ALL
app.get("/api/:collection", async (req, res) => {
    try {
        const collection = req.params.collection;
        if (!isValidCollection(collection)) return res.status(400).json({ success: false, message: "Invalid collection name" });

        const database = await getDB();
        const data = await database.collection(collection).find({}).toArray();
        res.json(data);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// 4. READ ONE
app.get("/api/:collection/:id", async (req, res) => {
    try {
        const collection = req.params.collection;
        if (!isValidCollection(collection)) return res.status(400).json({ success: false, message: "Invalid collection name" });

        const database = await getDB();
        const data = await database.collection(collection).findOne({ _id: new ObjectId(req.params.id) });
        res.json(data);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// 5. UPDATE
app.patch("/api/:collection/:id", async (req, res) => {
    try {
        const collection = req.params.collection;
        if (!isValidCollection(collection)) return res.status(400).json({ success: false, message: "Invalid collection name" });

        const database = await getDB();
        const result = await database.collection(collection).updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: req.body }
        );
        res.json(result);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// 6. DELETE
app.delete("/api/:collection/:id", async (req, res) => {
    try {
        const collection = req.params.collection;
        if (!isValidCollection(collection)) return res.status(400).json({ success: false, message: "Invalid collection name" });

        const database = await getDB();
        const result = await database.collection(collection).deleteOne({ _id: new ObjectId(req.params.id) });
        res.json(result);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// 7. UPDATE COMMENT FOR A SPECIFIC REPORT
app.patch("/api/:collection/comment/:id", async (req, res) => {
    try {
        const collection = req.params.collection;
        const { comment } = req.body;
        if (!isValidCollection(collection)) return res.status(400).json({ success: false, message: "Invalid collection name" });

        const database = await getDB();
        const result = await database.collection(collection).updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { comment: comment, comment_updated_at: new Date() } }
        );
        res.json({ success: true, message: "Comment updated successfully", result });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// Local environment ke liye listen karna
if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`🚀 Server running on port ${PORT}`);
    });
}

// Vercel serverless functions ke liye app export karna zaroori hai
module.exports = app;
