"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createUser = createUser;
exports.findUserByEmail = findUserByEmail;
exports.findUserById = findUserById;
exports.verifyPassword = verifyPassword;
exports.toPublicUser = toPublicUser;
const bcryptjs_1 = __importDefault(require("bcryptjs"));
// In-memory "database". Swap this for a real DB (Postgres, SQLite, etc.)
// once you're comfortable with the auth flow — the shape of the code
// around it barely changes.
const users = [];
let nextId = 1;
async function createUser(email, plainPassword, role = "user") {
    const existing = findUserByEmail(email);
    if (existing) {
        throw new Error("EMAIL_TAKEN");
    }
    // 10 salt rounds is a reasonable default: strong enough, not too slow.
    const passwordHash = await bcryptjs_1.default.hash(plainPassword, 10);
    const user = {
        id: String(nextId++),
        email: email.toLowerCase(),
        passwordHash,
        role,
    };
    users.push(user);
    return user;
}
function findUserByEmail(email) {
    return users.find((u) => u.email === email.toLowerCase());
}
function findUserById(id) {
    return users.find((u) => u.id === id);
}
async function verifyPassword(user, plainPassword) {
    return bcryptjs_1.default.compare(plainPassword, user.passwordHash);
}
// Never send passwordHash back to the client.
function toPublicUser(user) {
    return { id: user.id, email: user.email, role: user.role };
}
