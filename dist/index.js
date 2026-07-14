"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const express_1 = __importDefault(require("express"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const db_1 = require("./DB/db");
const auth_1 = require("./auth/auth");
const app = (0, express_1.default)();
app.use(express_1.default.json());
app.use((0, cookie_parser_1.default)());
const PORT = process.env.PORT || 3000;
// ---------- Public routes ----------
app.post("/register", async (req, res) => {
    const { email, password } = req.body ?? {};
    if (typeof email !== "string" || typeof password !== "string") {
        return res.status(400).json({ error: "Email and password are required." });
    }
    if (password.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters." });
    }
    try {
        const user = await (0, db_1.createUser)(email, password);
        return res.status(201).json({ user: (0, db_1.toPublicUser)(user) });
    }
    catch (err) {
        if (err instanceof Error && err.message === "EMAIL_TAKEN") {
            return res.status(409).json({ error: "An account with that email already exists." });
        }
        console.error(err);
        return res.status(500).json({ error: "Something went wrong." });
    }
});
app.post("/login", async (req, res) => {
    const { email, password } = req.body ?? {};
    if (typeof email !== "string" || typeof password !== "string") {
        return res.status(400).json({ error: "Email and password are required." });
    }
    const user = (0, db_1.findUserByEmail)(email);
    // Deliberately vague error message: don't reveal whether the email
    // exists or the password was wrong — that distinction helps attackers.
    if (!user || !(await (0, db_1.verifyPassword)(user, password))) {
        return res.status(401).json({ error: "Invalid email or password." });
    }
    const token = (0, auth_1.signToken)(user);
    // Send the token both ways so you can test with curl (Authorization header)
    // or a browser (httpOnly cookie) without changing anything.
    res.cookie("token", token, {
        httpOnly: true,
        sameSite: "lax",
        maxAge: 60 * 60 * 1000, // 1 hour
    });
    return res.json({ token, user: (0, db_1.toPublicUser)(user) });
});
app.post("/logout", (_req, res) => {
    res.clearCookie("token");
    return res.json({ message: "Logged out." });
});
// ---------- Protected routes ----------
// Only answers for a logged-in user (401 otherwise).
app.get("/me", auth_1.requireAuth, (req, res) => {
    const user = (0, db_1.findUserById)(req.user.sub);
    if (!user) {
        return res.status(401).json({ error: "Not authenticated. Please log in." });
    }
    return res.json({ user: (0, db_1.toPublicUser)(user) });
});
// Bonus: shows the 403 case. Logged in, but wrong role.
app.get("/admin", auth_1.requireAuth, (0, auth_1.requireRole)("admin"), (_req, res) => {
    return res.json({ message: "Welcome, admin. This route is role-gated." });
});
app.listen(PORT, () => {
    console.log(`Auth server listening on http://localhost:${PORT}`);
});
