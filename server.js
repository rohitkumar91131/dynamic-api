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

// 🌟 SMART AI TAGGING PROMPT 🌟
const systemPrompt = `You are a medical categorization AI. Read the user's daily health log (which might be in Hinglish/Hindi/English) and generate 1 to 3 highly relevant, concise medical/symptom hashtags. 
CRITICAL RULES:
- Output ONLY the hashtags separated by spaces (e.g., #Headache #Acidity #Fatigue).
- If the log is about eating too much and bloating, output tags like #Bloating #Overeating.
- Do NOT write any other text, no explanations, no formatting. Just the hashtags.`;

function extractNotes(data) {
    if (data && data.fields && Array.isArray(data.fields)) {
        return data.fields.map(f => `${f.label}: ${f.value}`).join(", ");
    }
    return JSON.stringify(data);
}

// CREATE ROUTE WITH AI TAGS
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
                    { role: "system", content: systemPrompt },
                    { role: "user", content: userPrompt }
                ],
                model: "llama3-8b-8192", // Using a faster model for simple tagging
            });
            aiTags = chatCompletion.choices[0]?.message?.content?.trim() || "";
        } catch (aiError) {
            console.error("⚠️ Groq AI Tagging Failed:", aiError.message);
        }

        // Save data with generated tags
        const dataToSave = {
            ...req.body,
            tags: aiTags,
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

// READ ALL
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

// READ ONE
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

// DELETE
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
