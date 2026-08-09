require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const Groq = require("groq-sdk"); 

const app = express();

app.use(cors());
app.use(express.json({ limit: "50mb" }));

const client = new MongoClient(process.env.MONGODB_URI);
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

let db = null;

async function getDB() {
    if (!db) {
        await client.connect();
        db = client.db();
        console.log("✅ MongoDB Connected");
    }
    return db;
}

function isValidCollection(name) {
    return /^[a-zA-Z0-9_-]+$/.test(name);
}

// 🌟 SMART AI TAGGING PROMPT (For initial creation) 🌟
const tagSystemPrompt = `You are a medical categorization AI. Read the user's daily health log (which might be in Hinglish/Hindi/English) and generate 1 to 3 highly relevant, concise medical/symptom hashtags. 
CRITICAL RULES:
- Output ONLY the hashtags separated by spaces (e.g., #Headache #Acidity #Fatigue).
- If the log is about eating too much and bloating, output tags like #Bloating #Overeating.
- Do NOT write any other text, no explanations, no formatting. Just the hashtags.`;

// 🌟 DETAILED AI ANALYSIS PROMPT (For Modal) 🌟
const analysisSystemPrompt = `You are an empathetic and smart health assistant. Your task is to analyze daily health logs.
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

// 1. CREATE ROUTE WITH AI TAGS
app.post("/api/:collection", async (req, res) => {
    try {
        const collection = req.params.collection;

        if (!isValidCollection(collection)) {
            return res.status(400).json({ success: false, message: "Invalid collection name" });
        }

        const extractedText = extractNotes(req.body.data);
        const userPrompt = `Log: ${extractedText}`;
        
        let aiTags = "";

        // AI CALL FOR TAGS
        try {
            const chatCompletion = await groq.chat.completions.create({
                messages: [
                    { role: "system", content: tagSystemPrompt },
                    { role: "user", content: userPrompt }
                ],
                model: "llama3-8b-8192", // Fast model for simple tags
            });
            aiTags = chatCompletion.choices[0]?.message?.content?.trim() || "";
        } catch (aiError) {
            console.error("⚠️ Groq AI Tagging Failed:", aiError.message);
        }

        // Save data with generated tags (ai_analysis left empty initially)
        const dataToSave = {
            ...req.body,
            tags: aiTags,
            ai_analysis: "",
            timestamp: new Date()
        };

        const database = await getDB();
        const result = await database.collection(collection).insertOne(dataToSave);

        res.status(201).json({
            success: true,
            insertedId: result.insertedId,
            tags: aiTags
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// 2. 🌟 NEW: GENERATE DETAILED AI ANALYSIS (For Modal) 🌟
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

        const extractedText = extractNotes(record.data);
        const userPrompt = `Here is the health log: ${extractedText}`;

        const chatCompletion = await groq.chat.completions.create({
            messages: [
                { role: "system", content: analysisSystemPrompt },
                { role: "user", content: userPrompt }
            ],
            model: "groq/compound", // Or whatever model you prefer for long text
        });

        const newAnalysis = chatCompletion.choices[0]?.message?.content || "";

        if (!newAnalysis) {
            return res.status(500).json({ success: false, message: "AI returned empty response" });
        }

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

// 5. UPDATE (General)
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

// 6. 🌟 NEW: UPDATE COMMENT (For Modal) 🌟
app.patch("/api/:collection/comment/:id", async (req, res) => {
    try {
        const collection = req.params.collection;
        const { comment } = req.body;

        if (!isValidCollection(collection)) {
            return res.status(400).json({ success: false, message: "Invalid collection name" });
        }

        const database = await getDB();
        const result = await database.collection(collection).updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { comment: comment, comment_updated_at: new Date() } }
        );

        res.json({
            success: true,
            message: "Comment updated successfully",
            result
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// 7. DELETE
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

if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => { console.log(`🚀 Server running on port ${PORT}`); });
}

module.exports = app;
