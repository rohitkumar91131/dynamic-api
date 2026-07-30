require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");

const app = express();

app.use(cors());
app.use(express.json({ limit: "50mb" }));

const client = new MongoClient(process.env.MONGODB_URI);

let db;

async function connectDB() {
    await client.connect();
    db = client.db(process.env.DATABASE_NAME);

    console.log("MongoDB Connected");
}

const isValidCollection = (name) => {
    return /^[a-zA-Z0-9_-]+$/.test(name);
};

// CREATE
app.post("/api/:collection", async (req, res) => {

    const collection = req.params.collection;

    if (!isValidCollection(collection))
        return res.status(400).json({ error: "Invalid collection name" });

    const result = await db
        .collection(collection)
        .insertOne(req.body);

    res.json(result);

});

// READ ALL
app.get("/api/:collection", async (req, res) => {

    const collection = req.params.collection;

    if (!isValidCollection(collection))
        return res.status(400).json({ error: "Invalid collection name" });

    const data = await db
        .collection(collection)
        .find({})
        .toArray();

    res.json(data);

});

// READ ONE
app.get("/api/:collection/:id", async (req, res) => {

    const collection = req.params.collection;

    if (!isValidCollection(collection))
        return res.status(400).json({ error: "Invalid collection name" });

    const data = await db
        .collection(collection)
        .findOne({
            _id: new ObjectId(req.params.id)
        });

    res.json(data);

});

// UPDATE
app.patch("/api/:collection/:id", async (req, res) => {

    const collection = req.params.collection;

    if (!isValidCollection(collection))
        return res.status(400).json({ error: "Invalid collection name" });

    const result = await db
        .collection(collection)
        .updateOne(
            { _id: new ObjectId(req.params.id) },
            {
                $set: req.body
            }
        );

    res.json(result);

});

// DELETE
app.delete("/api/:collection/:id", async (req, res) => {

    const collection = req.params.collection;

    if (!isValidCollection(collection))
        return res.status(400).json({ error: "Invalid collection name" });

    const result = await db
        .collection(collection)
        .deleteOne({
            _id: new ObjectId(req.params.id)
        });

    res.json(result);

});

connectDB().then(() => {

    app.listen(process.env.PORT, () => {

        console.log(`Server Running On ${process.env.PORT}`);

    });

});
