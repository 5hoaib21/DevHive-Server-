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
const publisherVerifyToken = async (req, res, next) => {
    const user = req.user;
    if (!user || user.role !== "publisher") {
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
        // await client.connect();
        const db = client.db("devhive");
        const usersCollection = db.collection("user");
        const resourcesCollection = db.collection("resources");
        const reportsCollection = db.collection("reports");
        app.post("/api/resources", verifyToken, async (req, res) => {
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
                const resourceDocument = {
                    ...data,
                    userId: req.user.id,
                    authorName,
                    authorEmail,
                    authorImage,
                    createdAt: new Date(),
                };
                const result = await resourcesCollection.insertOne(resourceDocument);
                return res.status(201).json({
                    success: true,
                    message: "Resource entity securely committed to target dataset context.",
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
        app.post("/api/resources/:id/review", verifyToken, async (req, res) => {
            try {
                const resourceId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
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
                const resource = await resourcesCollection.findOne({
                    _id: new ObjectId(resourceId),
                });
                if (!resource) {
                    return res
                        .status(404)
                        .json({ success: false, message: "Resource not found." });
                }
                const currentReviews = resource.reviews || [];
                const totalReviewsCount = currentReviews.length + 1;
                const currentRatingSum = currentReviews.reduce((sum, rev) => sum + rev.rating, 0);
                const newAverageRating = (currentRatingSum + Number(rating)) / totalReviewsCount;
                await resourcesCollection.updateOne({ _id: new ObjectId(resourceId) }, {
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
        app.post("/api/resources/:id/report", verifyToken, async (req, res) => {
            try {
                const resourceId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const userId = req.user.id;
                const { reason, description } = req.body;
                if (!reason) {
                    return res
                        .status(400)
                        .json({ success: false, message: "Reason is required." });
                }
                const targetedResource = await resourcesCollection.findOne({
                    _id: new ObjectId(resourceId),
                });
                if (!targetedResource) {
                    return res
                        .status(404)
                        .json({ success: false, message: "resource not found" });
                }
                const reporterUser = await usersCollection.findOne({
                    _id: new ObjectId(userId),
                });
                const newReport = {
                    _id: new ObjectId(),
                    resourceId: new ObjectId(resourceId),
                    resourceTitle: targetedResource.title || "Untitled Resource",
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
        app.patch("/api/resources/:id/copy", verifyToken, async (req, res) => {
            try {
                const resourceId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const result = await resourcesCollection.updateOne({ _id: new ObjectId(resourceId) }, { $inc: { usageCount: 1 } });
                if (result.matchedCount === 0) {
                    return res.status(404).json({
                        success: false,
                        message: "Resource not found.",
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
        app.patch("/api/resources/:id", verifyToken, async (req, res) => {
            try {
                const resourceId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const updatedData = req.body;
                if (!req.user?.id) {
                    return res.status(401).json({
                        success: false,
                        error: "Unauthorized access.",
                    });
                }
                const { title, content, language, difficulty, category, visibility, tags, } = updatedData;
                const updateDoc = {
                    $set: {
                        ...(title && { title }),
                        ...(content && { content }),
                        ...(language && { language }),
                        ...(difficulty && { difficulty }),
                        ...(category && { category }),
                        ...(visibility && { visibility }),
                        ...(Array.isArray(tags) && { tags }),
                        updatedAt: new Date(),
                    },
                };
                const query = {
                    _id: new ObjectId(resourceId),
                    userId: req.user.id,
                };
                const result = await resourcesCollection.updateOne(query, updateDoc);
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
        app.patch("/api/resources/:id/bookmark", verifyToken, async (req, res) => {
            try {
                const resourceId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const userId = req.user.id;
                const resource = await resourcesCollection.findOne({
                    _id: new ObjectId(resourceId),
                    bookmarks: new ObjectId(userId),
                });
                let updateQuery;
                let isSavedNow;
                if (resource) {
                    updateQuery = { $pull: { bookmarks: new ObjectId(userId) } };
                    isSavedNow = false;
                }
                else {
                    updateQuery = { $addToSet: { bookmarks: new ObjectId(userId) } };
                    isSavedNow = true;
                }
                await resourcesCollection.updateOne({ _id: new ObjectId(resourceId) }, updateQuery);
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
                const allowedRoles = ["explorer", "publisher", "admin"];
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
        app.patch("/admin/resources/status/:id", verifyToken, adminVerifyToken, async (req, res) => {
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
                const result = await resourcesCollection.updateOne(query, updateDoc);
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
        app.delete("/admin/reports/remove-resource", verifyToken, adminVerifyToken, async (req, res) => {
            try {
                const { reportId, resourceId } = req.body;
                if (!reportId || !resourceId) {
                    return res.status(400).json({
                        success: false,
                        message: "Report ID and Resource ID are required!",
                    });
                }
                const resourceResult = await resourcesCollection.deleteOne({
                    _id: new ObjectId(resourceId),
                });
                const reportResult = await reportsCollection.deleteOne({
                    _id: new ObjectId(reportId),
                });
                if (resourceResult.deletedCount === 0 &&
                    reportResult.deletedCount === 0) {
                    return res
                        .status(404)
                        .json({ success: false, message: "Resource or Report not found!" });
                }
                res.json({
                    success: true,
                    message: "Resource permanently removed and report cleared!",
                });
            }
            catch (error) {
                res
                    .status(500)
                    .json({ success: false, message: "Internal Server Error" });
            }
        });
        app.delete("/admin/resources/:id", verifyToken, adminVerifyToken, async (req, res) => {
            try {
                const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const query = { _id: new ObjectId(id) };
                const result = await resourcesCollection.deleteOne(query);
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
        app.delete("/api/resources/:id", verifyToken, async (req, res) => {
            try {
                const resourceId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                if (!req.user?.id) {
                    return res
                        .status(401)
                        .json({ success: false, error: "Unauthorized access." });
                }
                const query = {
                    _id: new ObjectId(resourceId),
                    userId: req.user.id,
                };
                const result = await resourcesCollection.deleteOne(query);
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
        app.get("/api/top-publishers", async (req, res) => {
            try {
                const topPublishers = (await resourcesCollection
                    .aggregate([
                    { $match: { status: "approved" } },
                    {
                        $group: {
                            _id: "$userId",
                            totalResources: { $sum: 1 },
                            authorName: { $last: "$authorName" },
                            authorImage: { $last: "$authorImage" },
                            authorEmail: { $last: "$authorEmail" },
                        },
                    },
                    { $sort: { totalResources: -1 } },
                    { $limit: 5 },
                ])
                    .toArray());
                res.json({ success: true, data: topPublishers });
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
                const totalResources = await resourcesCollection.countDocuments();
                const totalReviews = await reportsCollection.countDocuments();
                const usageAggregation = await resourcesCollection
                    .aggregate([
                    { $group: { _id: null, totalUsage: { $sum: "$usageCount" } } },
                ])
                    .toArray();
                const totalUsage = usageAggregation[0]?.totalUsage || 0;
                const languageStats = await resourcesCollection
                    .aggregate([
                    {
                        $group: {
                            _id: "$language",
                            Resources: { $sum: 1 },
                            Usage: { $sum: "$usageCount" },
                        },
                    },
                ])
                    .toArray();
                const languageData = languageStats.map((stat) => {
                    const rawName = stat._id || "unknown";
                    return {
                        name: rawName.charAt(0).toUpperCase() + rawName.slice(1),
                        Usage: stat.Usage || 0,
                        Resources: stat.Resources || 0,
                    };
                });
                res.json({
                    success: true,
                    stats: {
                        totalUsers,
                        totalResources,
                        totalReviews,
                        totalUsage,
                    },
                    languageData,
                });
            }
            catch (error) {
                res
                    .status(500)
                    .json({ success: false, message: "Internal Server Error" });
            }
        });
        app.get("/api/resources", verifyToken, async (req, res) => {
            const { page = 1, limit = 10 } = req.query;
            const skip = (Number(page) - 1) * Number(limit);
            const result = await resourcesCollection
                .find({ userId: req.user.id })
                .skip(skip)
                .limit(Number(limit))
                .toArray();
            const totalData = await resourcesCollection.countDocuments({
                userId: req.user.id,
            });
            const totalPages = Math.ceil(totalData / Number(limit));
            res.json({ data: result, page: Number(page), totalPages });
        });
        app.get("/admin/resources", verifyToken, adminVerifyToken, async (req, res) => {
            const query = {};
            const result = await resourcesCollection.find(query).toArray();
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
        app.get("/resources", async (req, res) => {
            try {
                const { search, category, language, difficulty, sort, page = "1", limit = "12" } = req.query;
                const query = {};
                if (req.query.status) {
                    query.status = req.query.status;
                }
                if (search && search !== "undefined" && search !== "") {
                    query.$or = [
                        { title: { $regex: search, $options: "i" } },
                        { tags: { $regex: search, $options: "i" } },
                        { language: { $regex: search, $options: "i" } },
                    ];
                }
                if (category && category !== "all" && category !== "undefined") {
                    query.category = category;
                }
                if (language && language !== "all" && language !== "undefined") {
                    query.language = language;
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
                    sortOptions = { usageCount: -1 };
                }
                else if (sort === "most_used") {
                    sortOptions = { usageCount: -1 };
                }
                else if (sort === "highest_rated") {
                    sortOptions = { rating: -1 };
                }
                else if (sort === "most_bookmarked") {
                    sortOptions = { bookmarks: -1 };
                }
                const pageNum = Math.max(1, parseInt(page, 10) || 1);
                const limitNum = Math.min(50, Math.max(1, parseInt(limit, 10) || 12));
                const skip = (pageNum - 1) * limitNum;
                const [result, total] = await Promise.all([
                    resourcesCollection.find(query).sort(sortOptions).skip(skip).limit(limitNum).toArray(),
                    resourcesCollection.countDocuments(query),
                ]);
                res.json({
                    data: result,
                    page: pageNum,
                    totalPages: Math.ceil(total / limitNum),
                    total,
                });
            }
            catch (error) {
                res.status(500).json({
                    success: false,
                    message: error instanceof Error ? error.message : "Internal Server Error",
                });
            }
        });
        app.get("/resources/featured", async (req, res) => {
            try {
                const query = { status: "approved" };
                const result = await resourcesCollection
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
        app.get("/resources/:id", async (req, res) => {
            const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
            const result = await resourcesCollection.findOne({ _id: new ObjectId(id) });
            res.json(result);
        });
        app.get("/resources/related/:id", async (req, res) => {
            try {
                const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const resource = await resourcesCollection.findOne({ _id: new ObjectId(id) });
                if (!resource) {
                    return res.json({ success: true, data: [] });
                }
                const related = await resourcesCollection
                    .find({
                    _id: { $ne: new ObjectId(id) },
                    status: "approved",
                    $or: [
                        { category: resource.category },
                        { language: resource.language },
                        { tags: { $in: resource.tags || [] } },
                    ],
                })
                    .limit(4)
                    .toArray();
                return res.json({ success: true, data: related });
            }
            catch (error) {
                return res.json({ success: true, data: [] });
            }
        });
        app.get("/api/my-bookmarks", verifyToken, async (req, res) => {
            try {
                const userId = req.user.id;
                const savedResources = await resourcesCollection
                    .find({
                    bookmarks: new ObjectId(userId),
                })
                    .toArray();
                return res.status(200).json({
                    success: true,
                    data: savedResources,
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
                const resourcesWithMyReviews = await resourcesCollection
                    .find({
                    "reviews.userId": userObjectId,
                })
                    .toArray();
                const myReviews = resourcesWithMyReviews.map((resource) => {
                    const userSpecificReview = resource.reviews.find((rev) => rev.userId.toString() === userId);
                    return {
                        _id: resource._id,
                        resourceTitle: resource.title,
                        language: resource.language,
                        category: resource.category,
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
                const totalResources = await resourcesCollection.countDocuments({
                    $or: [{ userId: new ObjectId(userId) }, { userId: userId }],
                });
                const profileData = {
                    name: user.name || "",
                    email: user.email,
                    image: user.image || "",
                    role: user.role || "explorer",
                    totalResources: totalResources || 0,
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
        app.get("/api/publisher-analytics", verifyToken, async (req, res) => {
            try {
                const publisherId = req.user.id;
                if (!publisherId) {
                    return res
                        .status(400)
                        .json({ success: false, error: "User ID missing from token." });
                }
                const publisherObjectId = new ObjectId(publisherId);
                const totalResources = await resourcesCollection.countDocuments({
                    $or: [{ userId: publisherObjectId }, { userId: publisherId }],
                });
                const stats = await resourcesCollection
                    .aggregate([
                    {
                        $match: {
                            $or: [{ userId: publisherObjectId }, { userId: publisherId }],
                        },
                    },
                    {
                        $group: {
                            _id: null,
                            totalUsage: { $sum: { $ifNull: ["$usageCount", 0] } },
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
                    totalResources: totalResources || 0,
                    totalUsage: stats[0]?.totalUsage || 0,
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
        app.get("/api/explorer-analytics", verifyToken, async (req, res) => {
            try {
                const userId = req.user.id;
                const userObjectId = new ObjectId(userId);
                const totalBookmarks = await resourcesCollection.countDocuments({
                    bookmarks: { $in: [userId, userObjectId] },
                });
                const totalReviews = await resourcesCollection.countDocuments({
                    "reviews.userId": userObjectId,
                });
                const analytics = {
                    totalBookmarks: totalBookmarks || 0,
                    totalReviews: totalReviews || 0,
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
        app.get("/resources/:id/reviews", async (req, res) => {
            try {
                const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
                const query = { _id: new ObjectId(id) };
                const options = {
                    projection: { reviews: 1, totalReviews: 1, rating: 1 },
                };
                const resourceData = await resourcesCollection.findOne(query, options);
                if (!resourceData) {
                    return res
                        .status(404)
                        .json({ success: false, message: "Prompt not found" });
                }
                res.json({
                    success: true,
                    reviews: resourceData.reviews || [],
                    totalReviews: resourceData.totalReviews || 0,
                    rating: resourceData.rating || 0,
                });
            }
            catch (error) {
                res
                    .status(500)
                    .json({ success: false, message: "Internal Server Error" });
            }
        });
        // await client.db("admin").command({ ping: 1 });
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