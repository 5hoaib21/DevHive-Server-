import dns from "node:dns";
dns.setServers(["1.1.1.1", "1.0.0.1"]);
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";
import { jwtVerify, createRemoteJWKSet } from "jose-cjs";
dotenv.config();
const uri = process.env.MONGODB_URI;
if (!uri) {
    throw new Error("MONGODB_URI environment variable is not set");
}
const app = express();
const PORT = process.env.PORT || 5005;
app.use(cors({
    credentials: true,
    origin: [process.env.CLIENT_URL || "http://localhost:3000"],
}));
app.use(express.json());
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});
const JWKS = createRemoteJWKSet(new URL(`${process.env.CLIENT_URL || "http://localhost:3000"}/api/auth/jwks`));
const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ message: "Unauthorized" });
    }
    const token = authHeader.split(" ")[1];
    if (!token) {
        return res.status(401).json({ message: "Unauthorized" });
    }
    try {
        const { payload } = await jwtVerify(token, JWKS);
        req.user = payload;
        next();
    }
    catch (error) {
        return res.status(401).json({ message: "Unauthorized" });
    }
};
const creatorVerifyToken = async (req, res, next) => {
    const user = req.user;
    if (!user || user.role !== "creator") {
        return res.status(403).json({ message: "Forbidden" });
    }
    next();
};
const adminVerifyToken = async (req, res, next) => {
    const user = req.user;
    if (!user || user.role !== "admin") {
        return res.status(403).json({ message: "Forbidden" });
    }
    next();
};
async function run() {
    try {
        await client.connect();
        const db = client.db("tech-bazaar");
        const usersCollection = db.collection("user");
        const promptsCollection = db.collection("prompts");
        const reportsCollection = db.collection("reports");
        app.post("/api/prompts", verifyToken, async (req, res) => {
            try {
                const data = req.body;
                if (!req.user?.id) {
                    return res.status(401).json({
                        success: false,
                        error: "Unauthorized access: Missing user session entity context.",
                    });
                }
                const userId = req.user.id;
                const userObjectId = new ObjectId(userId);
                const user = await usersCollection.findOne({ _id: userObjectId });
                if (!user) {
                    return res.status(404).json({
                        success: false,
                        error: "user account context not found in database",
                    });
                }
                const authorName = user.name || user.displayName || "Anonymous Creator";
                const authorEmail = user.email || "No Email";
                const authorImage = user.image || user.photoURL || "https://placeholder.com/user.png";
                const promptDocument = {
                    ...data,
                    userId: req.user.id,
                    authorName,
                    authorEmail,
                    authorImage,
                    createdAt: new Date(),
                };
                const result = await promptsCollection.insertOne(promptDocument);
                return res.status(201).json({
                    success: true,
                    message: "Prompt entity securely committed to target dataset context.",
                    insertedId: result.insertedId,
                });
            }
            catch (error) {
                return res.status(500).json({
                    success: false,
                    error: "Internal server processing failure while mapping database document.",
                });
            }
        });
        app.post("/api/prompts/:id/review", verifyToken, async (req, res) => {
            try {
                const promptId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const { rating, comment } = req.body;
                const userId = req.user.id;
                const userName = req.user.name || "Anonymous";
                if (!rating || rating < 1 || rating > 5) {
                    return res.status(400).json({
                        success: false,
                        message: "Invalid rating. Must be between 1 and 5.",
                    });
                }
                const newReview = {
                    userId: new ObjectId(userId),
                    userName,
                    rating: Number(rating),
                    comment: comment || "",
                    createdAt: new Date(),
                };
                const prompt = await promptsCollection.findOne({
                    _id: new ObjectId(promptId),
                });
                if (!prompt) {
                    return res
                        .status(404)
                        .json({ success: false, message: "Prompt not found." });
                }
                const currentReviews = prompt.reviews || [];
                const totalReviewsCount = currentReviews.length + 1;
                const currentRatingSum = currentReviews.reduce((sum, rev) => sum + rev.rating, 0);
                const newAverageRating = (currentRatingSum + Number(rating)) / totalReviewsCount;
                await promptsCollection.updateOne({ _id: new ObjectId(promptId) }, {
                    $push: { reviews: newReview },
                    $set: { rating: newAverageRating },
                    $inc: { ratingCount: 1, totalReviews: 1 },
                });
                return res.status(200).json({
                    success: true,
                    message: "Review added successfully.",
                    newReview,
                });
            }
            catch (error) {
                return res.status(500).json({
                    success: false,
                    error: "Internal server error during review submission.",
                });
            }
        });
        app.post("/api/prompts/:id/report", verifyToken, async (req, res) => {
            try {
                const promptId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const userId = req.user.id;
                const { reason, description } = req.body;
                if (!reason) {
                    return res
                        .status(400)
                        .json({ success: false, message: "Reason is required." });
                }
                const targetedPrompt = await promptsCollection.findOne({
                    _id: new ObjectId(promptId),
                });
                if (!targetedPrompt) {
                    return res
                        .status(404)
                        .json({ success: false, message: "prompt not found" });
                }
                const reporterUser = await usersCollection.findOne({
                    _id: new ObjectId(userId),
                });
                const newReport = {
                    _id: new ObjectId(),
                    promptId: new ObjectId(promptId),
                    promptTitle: targetedPrompt.title || "UnTitled Prompt",
                    userId: new ObjectId(userId),
                    reason,
                    description: description || "",
                    status: "pending",
                    createdAt: new Date(),
                    reporter: {
                        name: reporterUser?.name || "Anonymous",
                        email: reporterUser?.email || "No Email",
                        image: reporterUser?.image || "",
                    },
                };
                await reportsCollection.insertOne(newReport);
                return res.status(201).json({
                    success: true,
                    message: "Prompt reported successfully. Admin will review it.",
                });
            }
            catch (error) {
                return res.status(500).json({
                    success: false,
                    error: "Internal server error during reporting.",
                });
            }
        });
        app.post("/admin/reports/warn-creator", verifyToken, adminVerifyToken, async (req, res) => {
            try {
                const { creatorEmail, reportId } = req.body;
                if (!creatorEmail) {
                    return res
                        .status(400)
                        .json({ success: false, message: "Creator email is required!" });
                }
                await usersCollection.updateOne({ email: creatorEmail }, { $inc: { warningCount: 1 } });
                if (reportId) {
                    await reportsCollection.updateOne({ _id: new ObjectId(reportId) }, { $set: { status: "warned" } });
                }
                res.json({
                    success: true,
                    message: `Warning successfully sent to creator (${creatorEmail})!`,
                });
            }
            catch (error) {
                res
                    .status(500)
                    .json({ success: false, message: "Internal Server Error" });
            }
        });
        app.patch("/api/prompts/:id/copy", verifyToken, async (req, res) => {
            try {
                const promptId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const result = await promptsCollection.updateOne({ _id: new ObjectId(promptId) }, { $inc: { copyCount: 1 } });
                if (result.matchedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: "Prompt not found.",
                    });
                }
                return res.status(200).json({
                    success: true,
                    message: "Copy count updated successfully.",
                });
            }
            catch (error) {
                return res.status(500).json({
                    success: false,
                    error: "Internal server error during copy update.",
                });
            }
        });
        app.patch("/api/prompts/:id", verifyToken, async (req, res) => {
            try {
                const promptId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const updatedData = req.body;
                if (!req.user?.id) {
                    return res.status(401).json({
                        success: false,
                        error: "Unauthorized access.",
                    });
                }
                const { title, content, aiTool, difficulty, category, visibility, tags, } = updatedData;
                const updateDoc = {
                    $set: {
                        ...(title && { title }),
                        ...(content && { content }),
                        ...(aiTool && { aiTool }),
                        ...(difficulty && { difficulty }),
                        ...(category && { category }),
                        ...(visibility && { visibility }),
                        ...(Array.isArray(tags) && { tags }),
                        updatedAt: new Date(),
                    },
                };
                const query = {
                    _id: new ObjectId(promptId),
                    userId: req.user.id,
                };
                const result = await promptsCollection.updateOne(query, updateDoc);
                if (result.matchedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: "Prompt not found or you don't have permission to update.",
                    });
                }
                return res.status(200).json({
                    success: true,
                    message: "Prompt updated successfully.",
                });
            }
            catch (error) {
                return res.status(500).json({
                    success: false,
                    error: "Internal server error during update.",
                });
            }
        });
        app.patch("/api/prompts/:id/bookmark", verifyToken, async (req, res) => {
            try {
                const promptId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const userId = req.user.id;
                const prompt = await promptsCollection.findOne({
                    _id: new ObjectId(promptId),
                    bookmarks: new ObjectId(userId),
                });
                let updateQuery;
                let isSavedNow;
                if (prompt) {
                    updateQuery = { $pull: { bookmarks: new ObjectId(userId) } };
                    isSavedNow = false;
                }
                else {
                    updateQuery = { $addToSet: { bookmarks: new ObjectId(userId) } };
                    isSavedNow = true;
                }
                await promptsCollection.updateOne({ _id: new ObjectId(promptId) }, updateQuery);
                return res.status(200).json({
                    success: true,
                    isSaved: isSavedNow,
                    message: isSavedNow
                        ? "Added to bookmarks."
                        : "Removed from bookmarks.",
                });
            }
            catch (error) {
                return res.status(500).json({
                    success: false,
                    error: "Internal server error during bookmark toggle.",
                });
            }
        });
        app.patch("/admin/users/role/:id", verifyToken, adminVerifyToken, async (req, res) => {
            try {
                const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const { role } = req.body;
                const allowedRoles = ["user", "creator", "admin"];
                if (!allowedRoles.includes(role)) {
                    return res.status(400).json({ message: "Invalid role type!" });
                }
                const query = { _id: new ObjectId(id) };
                const updateDoc = {
                    $set: { role: role },
                };
                const result = await usersCollection.updateOne(query, updateDoc);
                if (result.modifiedCount === 0) {
                    return res
                        .status(404)
                        .json({ message: "User not found or role is already the same!" });
                }
                res.json({
                    success: true,
                    message: `User role updated to ${role} successfully!`,
                });
            }
            catch (error) {
                res.status(500).json({ message: "Internal Server Error" });
            }
        });
        app.patch("/admin/prompts/status/:id", verifyToken, adminVerifyToken, async (req, res) => {
            try {
                const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const { status } = req.body;
                const allowedStatuses = ["pending", "approved", "rejected"];
                if (!allowedStatuses.includes(status)) {
                    return res
                        .status(400)
                        .json({ success: false, message: "Invalid status type!" });
                }
                const query = { _id: new ObjectId(id) };
                const updateDoc = {
                    $set: { status: status },
                };
                const result = await promptsCollection.updateOne(query, updateDoc);
                if (result.matchedCount === 0) {
                    return res
                        .status(404)
                        .json({ success: false, message: "Prompt not found!" });
                }
                res.json({
                    success: true,
                    message: `Prompt status updated to '${status}' successfully!`,
                });
            }
            catch (error) {
                res
                    .status(500)
                    .json({ success: false, message: "Internal Server Error" });
            }
        });
        app.delete("/admin/reports/dismiss/:id", verifyToken, adminVerifyToken, async (req, res) => {
            try {
                const reportId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const query = { _id: new ObjectId(reportId) };
                const result = await reportsCollection.deleteOne(query);
                if (result.deletedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: "Report not found or already dismissed!",
                    });
                }
                res.json({
                    success: true,
                    message: "Report dismissed and cleared successfully!",
                });
            }
            catch (error) {
                res
                    .status(500)
                    .json({ success: false, message: "Internal Server Error" });
            }
        });
        app.delete("/admin/reports/remove-prompt", verifyToken, adminVerifyToken, async (req, res) => {
            try {
                const { reportId, promptId } = req.body;
                if (!reportId || !promptId) {
                    return res.status(400).json({
                        success: false,
                        message: "Report ID and Prompt ID are required!",
                    });
                }
                const promptResult = await promptsCollection.deleteOne({
                    _id: new ObjectId(promptId),
                });
                const reportResult = await reportsCollection.deleteOne({
                    _id: new ObjectId(reportId),
                });
                if (promptResult.deletedCount === 0 &&
                    reportResult.deletedCount === 0) {
                    return res
                        .status(404)
                        .json({ success: false, message: "Prompt or Report not found!" });
                }
                res.json({
                    success: true,
                    message: "Prompt permanently removed and report cleared!",
                });
            }
            catch (error) {
                res
                    .status(500)
                    .json({ success: false, message: "Internal Server Error" });
            }
        });
        app.delete("/admin/prompts/:id", verifyToken, adminVerifyToken, async (req, res) => {
            try {
                const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const query = { _id: new ObjectId(id) };
                const result = await promptsCollection.deleteOne(query);
                if (result.deletedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: "Prompt not found or already deleted!",
                    });
                }
                res.json({
                    success: true,
                    message: "Prompt deleted successfully from database!",
                });
            }
            catch (error) {
                res
                    .status(500)
                    .json({ success: false, message: "Internal Server Error" });
            }
        });
        app.delete("/admin/users/:id", verifyToken, adminVerifyToken, async (req, res) => {
            try {
                const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const query = { _id: new ObjectId(id) };
                const result = await usersCollection.deleteOne(query);
                if (result.deletedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: "User not found or already deleted!",
                    });
                }
                res.json({
                    success: true,
                    message: "User account deleted successfully!",
                });
            }
            catch (error) {
                res.status(500).json({
                    success: false,
                    message: "Internal Server Error",
                });
            }
        });
        app.delete("/api/prompts/:id", verifyToken, async (req, res) => {
            try {
                const promptId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                if (!req.user?.id) {
                    return res
                        .status(401)
                        .json({ success: false, error: "Unauthorized access." });
                }
                const query = {
                    _id: new ObjectId(promptId),
                    userId: req.user.id,
                };
                const result = await promptsCollection.deleteOne(query);
                if (result.deletedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: "Prompt not found or you don't have permission to delete.",
                    });
                }
                return res.status(200).json({
                    success: true,
                    message: "Prompt deleted successfully.",
                });
            }
            catch (error) {
                return res.status(500).json({
                    success: false,
                    error: "Internal server error during deletion.",
                });
            }
        });
        app.get("/api/top-creators", async (req, res) => {
            try {
                const topCreators = (await promptsCollection
                    .aggregate([
                    { $match: { status: "approved" } },
                    {
                        $group: {
                            _id: "$userId",
                            totalPrompts: { $sum: 1 },
                            authorName: { $last: "$authorName" },
                            authorImage: { $last: "$authorImage" },
                            authorEmail: { $last: "$authorEmail" },
                        },
                    },
                    { $sort: { totalPrompts: -1 } },
                    { $limit: 5 },
                ])
                    .toArray());
                res.json({ success: true, data: topCreators });
            }
            catch (error) {
                res
                    .status(500)
                    .json({ success: false, message: "Internal Server Error" });
            }
        });
        app.get("/admin/analytics", verifyToken, adminVerifyToken, async (req, res) => {
            try {
                const totalUsers = await usersCollection.countDocuments();
                const totalPrompts = await promptsCollection.countDocuments();
                const totalReviews = await reportsCollection.countDocuments();
                const copyAggregation = await promptsCollection
                    .aggregate([
                    { $group: { _id: null, totalCopies: { $sum: "$copyCount" } } },
                ])
                    .toArray();
                const totalCopies = copyAggregation[0]?.totalCopies || 0;
                const aiToolStats = await promptsCollection
                    .aggregate([
                    {
                        $group: {
                            _id: "$aiTool",
                            Prompts: { $sum: 1 },
                            Copies: { $sum: "$copyCount" },
                        },
                    },
                ])
                    .toArray();
                const engineData = aiToolStats.map((stat) => {
                    const rawName = stat._id || "unknown";
                    return {
                        name: rawName.charAt(0).toUpperCase() + rawName.slice(1),
                        Copies: stat.Copies || 0,
                        Prompts: stat.Prompts || 0,
                    };
                });
                res.json({
                    success: true,
                    stats: {
                        totalUsers,
                        totalPrompts,
                        totalReviews,
                        totalCopies,
                    },
                    engineData,
                });
            }
            catch (error) {
                res
                    .status(500)
                    .json({ success: false, message: "Internal Server Error" });
            }
        });
        app.get("/api/prompts", verifyToken, async (req, res) => {
            const { page = 1, limit = 10 } = req.query;
            const skip = (Number(page) - 1) * Number(limit);
            const result = await promptsCollection
                .find({ userId: req.user.id })
                .skip(skip)
                .limit(Number(limit))
                .toArray();
            const totalData = await promptsCollection.countDocuments({
                userId: req.user.id,
            });
            const totalPages = Math.ceil(totalData / Number(limit));
            res.json({ data: result, page: Number(page), totalPages });
        });
        app.get("/admin/prompts", verifyToken, adminVerifyToken, async (req, res) => {
            const query = {};
            const result = await promptsCollection.find(query).toArray();
            res.json(result);
        });
        app.get("/admin/users", verifyToken, adminVerifyToken, async (req, res) => {
            const query = {};
            const result = await usersCollection.find(query).toArray();
            res.json(result);
        });
        app.get("/admin/reports", verifyToken, adminVerifyToken, async (req, res) => {
            try {
                const reports = await reportsCollection.find().toArray();
                return res.json({ success: true, data: reports });
            }
            catch (error) {
                return res
                    .status(500)
                    .json({ success: false, message: "Internal Server Error" });
            }
        });
        app.get("/prompts", async (req, res) => {
            try {
                const { search, category, aiTool, difficulty, sort } = req.query;
                const query = {};
                if (req.query.status) {
                    query.status = req.query.status;
                }
                if (search && search !== "undefined" && search !== "") {
                    query.$or = [
                        { title: { $regex: search, $options: "i" } },
                        { tags: { $regex: search, $options: "i" } },
                        { aiTool: { $regex: search, $options: "i" } },
                    ];
                }
                if (category && category !== "all" && category !== "undefined") {
                    query.category = category;
                }
                if (aiTool && aiTool !== "all" && aiTool !== "undefined") {
                    query.aiTool = aiTool;
                }
                if (difficulty &&
                    difficulty !== "all" &&
                    difficulty !== "undefined" &&
                    difficulty !== "") {
                    query.difficulty = difficulty;
                }
                let sortOptions = { createdAt: -1 };
                if (sort === "popular") {
                    sortOptions = { ratingCount: -1 };
                }
                else if (sort === "copied") {
                    sortOptions = { copyCount: -1 };
                }
                const result = await promptsCollection
                    .find(query)
                    .sort(sortOptions)
                    .toArray();
                res.json(result);
            }
            catch (error) {
                res.status(500).json({
                    success: false,
                    message: error instanceof Error ? error.message : "Internal Server Error",
                });
            }
        });
        app.get("/prompts/featured", async (req, res) => {
            try {
                const query = { status: "approved" };
                const result = await promptsCollection
                    .find(query)
                    .sort({ _id: -1 })
                    .limit(6)
                    .toArray();
                return res.json({ success: true, data: result });
            }
            catch (error) {
                return res.json({ success: true, data: [] });
            }
        });
        app.get("/prompts/:id", async (req, res) => {
            const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
            const result = await promptsCollection.findOne({ _id: new ObjectId(id) });
            res.json(result);
        });
        app.get("/api/my-bookmarks", verifyToken, async (req, res) => {
            try {
                const userId = req.user.id;
                const savedPrompts = await promptsCollection
                    .find({
                    bookmarks: new ObjectId(userId),
                })
                    .toArray();
                return res.status(200).json({
                    success: true,
                    data: savedPrompts,
                });
            }
            catch (error) {
                return res
                    .status(500)
                    .json({ success: false, error: "Internal server error." });
            }
        });
        app.get("/api/my-reviews", verifyToken, async (req, res) => {
            try {
                const userId = req.user.id;
                const userObjectId = new ObjectId(userId);
                const promptsWithMyReviews = await promptsCollection
                    .find({
                    "reviews.userId": userObjectId,
                })
                    .toArray();
                const myReviews = promptsWithMyReviews.map((prompt) => {
                    const userSpecificReview = prompt.reviews.find((rev) => rev.userId.toString() === userId);
                    return {
                        _id: prompt._id,
                        promptTitle: prompt.title,
                        aiTool: prompt.aiTool,
                        category: prompt.category,
                        myRating: userSpecificReview?.rating || 0,
                        myComment: userSpecificReview?.comment || "",
                        reviewedAt: userSpecificReview?.createdAt || new Date(),
                    };
                });
                return res.status(200).json({
                    success: true,
                    data: myReviews,
                });
            }
            catch (error) {
                return res
                    .status(500)
                    .json({ success: false, error: "Internal server error." });
            }
        });
        app.get("/api/my-profile", verifyToken, async (req, res) => {
            try {
                const userId = req.user.id;
                const user = await usersCollection.findOne({
                    _id: new ObjectId(userId),
                });
                if (!user) {
                    return res
                        .status(404)
                        .json({ success: false, error: "User not found." });
                }
                const totalPrompts = await promptsCollection.countDocuments({
                    $or: [{ userId: new ObjectId(userId) }, { userId: userId }],
                });
                const profileData = {
                    name: user.name || "",
                    email: user.email,
                    image: user.image || "",
                    role: user.role || "user",
                    totalPrompts: totalPrompts || 0,
                };
                return res.status(200).json({
                    success: true,
                    data: profileData,
                });
            }
            catch (error) {
                return res
                    .status(500)
                    .json({ success: false, error: "Internal server error." });
            }
        });
        app.get("/api/creator-analytics", verifyToken, async (req, res) => {
            try {
                const creatorId = req.user.id;
                if (!creatorId) {
                    return res
                        .status(400)
                        .json({ success: false, error: "User ID missing from token." });
                }
                const creatorObjectId = new ObjectId(creatorId);
                const totalPrompts = await promptsCollection.countDocuments({
                    $or: [{ userId: creatorObjectId }, { userId: creatorId }],
                });
                const stats = await promptsCollection
                    .aggregate([
                    {
                        $match: {
                            $or: [{ userId: creatorObjectId }, { userId: creatorId }],
                        },
                    },
                    {
                        $group: {
                            _id: null,
                            totalCopies: { $sum: { $ifNull: ["$copyCount", 0] } },
                            totalBookmarks: {
                                $sum: {
                                    $cond: {
                                        if: { $isArray: "$bookmarks" },
                                        then: { $size: "$bookmarks" },
                                        else: 0,
                                    },
                                },
                            },
                        },
                    },
                ])
                    .toArray();
                const analytics = {
                    totalPrompts: totalPrompts || 0,
                    totalCopies: stats[0]?.totalCopies || 0,
                    totalBookmarks: stats[0]?.totalBookmarks || 0,
                };
                return res.status(200).json({
                    success: true,
                    analytics,
                });
            }
            catch (error) {
                return res
                    .status(500)
                    .json({ success: false, error: "Internal server error." });
            }
        });
        app.get("/api/user-analytics", verifyToken, async (req, res) => {
            try {
                const userId = req.user.id;
                const userObjectId = new ObjectId(userId);
                const totalBookmarks = await promptsCollection.countDocuments({
                    bookmarks: { $in: [userId, userObjectId] },
                });
                const totalReviews = await promptsCollection.countDocuments({
                    "reviews.userId": userObjectId,
                });
                const analytics = {
                    totalBookmarks: totalBookmarks || 0,
                    totalReviews: totalReviews || 0,
                    totalCopies: 0,
                };
                return res.status(200).json({
                    success: true,
                    analytics,
                });
            }
            catch (error) {
                return res
                    .status(500)
                    .json({ success: false, error: "Internal server error." });
            }
        });
        app.get("/prompts/:id/reviews", async (req, res) => {
            try {
                const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const query = { _id: new ObjectId(id) };
                const options = {
                    projection: { reviews: 1, totalReviews: 1, rating: 1 },
                };
                const promptData = await promptsCollection.findOne(query, options);
                if (!promptData) {
                    return res
                        .status(404)
                        .json({ success: false, message: "Prompt not found" });
                }
                res.json({
                    success: true,
                    reviews: promptData.reviews || [],
                    totalReviews: promptData.totalReviews || 0,
                    rating: promptData.rating || 0,
                });
            }
            catch (error) {
                res
                    .status(500)
                    .json({ success: false, message: "Internal Server Error" });
            }
        });
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    }
    finally {
    }
}
run().catch(console.dir);
app.get("/", (req, res) => {
    res.send("Server is running fine!");
});
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
//# sourceMappingURL=index.js.map