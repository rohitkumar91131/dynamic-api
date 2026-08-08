require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const Groq = require("groq-sdk"); // 1. Groq import kiya

const app = express();

app.use(cors());
app.use(express.json({ limit: "50mb" }));

const client = new MongoClient(process.env.MONGODB_URI);

// 2. Groq client initialize kiya
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

let db;

// MongoDB Connection
async function connectDB() {
    await client.connect();
    console.log("✅ MongoDB Connected");
}

// Collection name validation
function isValidCollection(name) {
    return /^[a-zA-Z0-9_-]+$/.test(name);
}

// CREATE with Groq Analysis
app.post("/api/:collection", async (req, res) => {
    try {
        const collection = req.params.collection;

        if (!isValidCollection(collection)) {
            return res.status(400).json({
                success: false,
                message: "Invalid collection name"
            });
        }

        // 3. Groq API ko prompt bhejna analysis ke liye
        // Yahan aap prompt ko apne hisaab se change kar sakte ho
        const prompt = `Please analyze the following health report submission and provide a short summary or insights: ${JSON.stringify(req.body)}`;
        
        const chatCompletion = await groq.chat.completions.create({
            messages: [
                {
                    role: "user",
                    content: prompt,
                },
            ],
           model: "groq/compound",// Aap koi aur model bhi use kar sakte ho
        });

        const groqAnalysis = chatCompletion.choices[0]?.message?.content || "No analysis generated.";

        // 4. Original data ke saath Groq ka analysis jodna
        const dataToSave = {
            ...req.body,
            ai_analysis: groqAnalysis,
            timestamp: new Date()
        };

        // 5. Database mein save karna
        const result = await db
            .collection(collection)
            .insertOne(dataToSave);

        res.status(201).json({
            success: true,
            insertedId: result.insertedId,
            analysis: groqAnalysis // Postman/frontend me dekhne ke liye response me bhi bhej diya
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

        const data = await db
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

        const data = await db
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

        const result = await db
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

        const result = await db
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

connectDB()
    .then(() => {
        app.listen(process.env.PORT, () => {
            console.log(`🚀 Server running on port ${process.env.PORT}`);
        });
    })
    .catch(err => {
        console.error(err);
    });
