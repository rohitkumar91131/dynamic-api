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

// CREATE with Improved AI Analysis
app.post("/api/:collection", async (req, res) => {
    try {
        const collection = req.params.collection;

        if (!isValidCollection(collection)) {
            return res.status(400).json({
                success: false,
                message: "Invalid collection name"
            });
        }

        // 🌟 IMPROVED AI PROMPT SECTION 🌟
        
        // 1. System Prompt: Directing the AI to be a smart health assistant
        const systemPrompt = `You are an empathetic and smart health assistant. Your task is to analyze daily health logs provided in JSON format.
        CRITICAL RULES:
        - IGNORE all technical metadata (like formId, submissionId, URLs, timestamps, respondent ID).
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

        // 2. User Prompt: Passing the raw data
        const userPrompt = `Here is the raw health log data. Please extract the symptoms and analyze:\n\n${JSON.stringify(req.body, null, 2)}`;
        
        // Groq API Call
        const chatCompletion = await groq.chat.completions.create({
            messages: [
                { role: "system", content: systemPrompt },
                { role: "user", content: userPrompt }
            ],
            model: "groq/compound", 
        });

        const groqAnalysis = chatCompletion.choices[0]?.message?.content || "No analysis generated.";

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
        res.status(500).json({
            success: false,
            message: err.message
        });
    }
});

// READ ALL
app.get("/api/:collection", async (req, res) => {
    try {
        const collection = req.params.collection;

        if (!isValidCollection(collection)) {
            return res.status(400).json({
                success: false,
                message: "Invalid collection name"
            });
        }

        const database = await getDB();
        const data = await database
            .collection(collection)
            .find({})
            .toArray();

        res.json(data);

    } catch (err) {
        res.status(500).json({
            success: false,
            message: err.message
        });
    }
});

// READ ONE
app.get("/api/:collection/:id", async (req, res) => {
    try {
        const collection = req.params.collection;

        if (!isValidCollection(collection)) {
            return res.status(400).json({
                success: false,
                message: "Invalid collection name"
            });
        }

        const database = await getDB();
        const data = await database
            .collection(collection)
            .findOne({
                _id: new ObjectId(req.params.id)
            });

        res.json(data);

    } catch (err) {
        res.status(500).json({
            success: false,
            message: err.message
        });
    }
});

// UPDATE
app.patch("/api/:collection/:id", async (req, res) => {
    try {
        const collection = req.params.collection;

        if (!isValidCollection(collection)) {
            return res.status(400).json({
                success: false,
                message: "Invalid collection name"
            });
        }

        const database = await getDB();
        const result = await database
            .collection(collection)
            .updateOne(
                {
                    _id: new ObjectId(req.params.id)
                },
                {
                    $set: req.body
                }
            );

        res.json(result);

    } catch (err) {
        res.status(500).json({
            success: false,
            message: err.message
        });
    }
});

// DELETE
app.delete("/api/:collection/:id", async (req, res) => {
    try {
        const collection = req.params.collection;

        if (!isValidCollection(collection)) {
            return res.status(400).json({
                success: false,
                message: "Invalid collection name"
            });
        }

        const database = await getDB();
        const result = await database
            .collection(collection)
            .deleteOne({
                _id: new ObjectId(req.params.id)
            });

        res.json(result);

    } catch (err) {
        res.status(500).json({
            success: false,
            message: err.message
        });
    }
});

// Local environment ke liye listen karna (Vercel apne aap handle karega isko)
if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`🚀 Server running on port ${PORT}`);
    });
}

// Vercel serverless functions ke liye app export karna zaroori hai
module.exports = app;
