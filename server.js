require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");

const app = express();

app.use(cors());
app.use(express.json({ limit: "50mb" }));

const client = new MongoClient(process.env.MONGODB_URI);

let db;

// MongoDB Connection
async function connectDB() {
    await client.connect();

    // Database URI se automatically select ho jayega
    db = client.db();

    console.log("✅ MongoDB Connected");
}

// Collection name validation
function isValidCollection(name) {
    return /^[a-zA-Z0-9_-]+$/.test(name);
}

// CREATE
app.post("/api/:collection", async (req, res) => {
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
            .insertOne(req.body);

        res.status(201).json({
            success: true,
            insertedId: result.insertedId
        });

    } catch (err) {
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
