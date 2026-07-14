"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.signToken = signToken;
exports.requireAuth = requireAuth;
exports.requireRole = requireRole;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const db_1 = require("../DB/db");
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-do-not-use-in-prod";
const TOKEN_EXPIRY = "1h";
function signToken(user) {
    const payload = { sub: user.id, role: user.role };
    return jsonwebtoken_1.default.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
}
function extractToken(req) {
    // Support both an Authorization header (typical for APIs/Postman)
    // and an httpOnly cookie (typical for browser clients).
    const header = req.headers.authorization;
    if (header?.startsWith("Bearer ")) {
        return header.slice("Bearer ".length);
    }
    if (req.cookies?.token) {
        return req.cookies.token;
    }
    return null;
}
/**
 * Requires a valid, logged-in user.
 * - No token / bad token / expired token -> 401 Unauthorized
 *   (we don't know who you are)
 */
function requireAuth(req, res, next) {
    const token = extractToken(req);
    if (!token) {
        return res.status(401).json({ error: "Not authenticated. Please log in." });
    }
    try {
        const payload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        // Confirm the user still exists (e.g. wasn't deleted after the token was issued).
        const user = (0, db_1.findUserById)(payload.sub);
        if (!user) {
            return res.status(401).json({ error: "Not authenticated. Please log in." });
        }
        req.user = payload;
        next();
    }
    catch {
        return res.status(401).json({ error: "Invalid or expired token." });
    }
}
/**
 * Requires the logged-in user to have a specific role.
 * - Not logged in -> 401 (handled by requireAuth, run first)
 * - Logged in but wrong role -> 403 Forbidden
 *   (we know who you are, you're just not allowed)
 */
function requireRole(role) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: "Not authenticated. Please log in." });
        }
        if (req.user.role !== role) {
            return res.status(403).json({ error: "You don't have permission to do that." });
        }
        next();
    };
}
