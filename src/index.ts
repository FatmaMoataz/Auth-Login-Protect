import "dotenv/config";
import express, { Request, Response } from "express";
import cookieParser from "cookie-parser";
import {
  createUser,
  findUserByEmail,
  verifyPassword,
  toPublicUser,
  findUserById,
} from "./DB/db";
import { signToken, requireAuth, requireRole } from "./auth/auth";

const app = express();
app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 3000;

// ---------- Public routes ----------

app.post("/register", async (req: Request, res: Response) => {
  const { email, password } = req.body ?? {};

  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Email and password are required." });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters." });
  }

  try {
    const user = await createUser(email, password);
    return res.status(201).json({ user: toPublicUser(user) });
  } catch (err) {
    if (err instanceof Error && err.message === "EMAIL_TAKEN") {
      return res.status(409).json({ error: "An account with that email already exists." });
    }
    console.error(err);
    return res.status(500).json({ error: "Something went wrong." });
  }
});

app.post("/login", async (req: Request, res: Response) => {
  const { email, password } = req.body ?? {};

  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Email and password are required." });
  }

  const user = findUserByEmail(email);
  // Deliberately vague error message: don't reveal whether the email
  // exists or the password was wrong — that distinction helps attackers.
  if (!user || !(await verifyPassword(user, password))) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  const token = signToken(user);

  // Send the token both ways so you can test with curl (Authorization header)
  // or a browser (httpOnly cookie) without changing anything.
  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
    maxAge: 60 * 60 * 1000, // 1 hour
  });

  return res.json({ token, user: toPublicUser(user) });
});

app.post("/logout", (_req: Request, res: Response) => {
  res.clearCookie("token");
  return res.json({ message: "Logged out." });
});

// ---------- Protected routes ----------

// Only answers for a logged-in user (401 otherwise).
app.get("/me", requireAuth, (req: Request, res: Response) => {
  const user = findUserById(req.user!.sub);
  if (!user) {
    return res.status(401).json({ error: "Not authenticated. Please log in." });
  }
  return res.json({ user: toPublicUser(user) });
});

// Bonus: shows the 403 case. Logged in, but wrong role.
app.get("/admin", requireAuth, requireRole("admin"), (_req: Request, res: Response) => {
  return res.json({ message: "Welcome, admin. This route is role-gated." });
});

app.listen(PORT, () => {
  console.log(`Auth server listening on http://localhost:${PORT}`);
});