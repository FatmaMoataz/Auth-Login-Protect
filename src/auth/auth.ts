import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { User, findUserById } from "../DB/db";

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-do-not-use-in-prod";
const TOKEN_EXPIRY = "1h";

export interface TokenPayload {
  sub: string; // user id
  role: User["role"];
}

// Extend Express's Request type so `req.user` is typed everywhere.
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: TokenPayload;
    }
  }
}

export function signToken(user: User): string {
  const payload: TokenPayload = { sub: user.id, role: user.role };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
}

function extractToken(req: Request): string | null {
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
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = extractToken(req);

  if (!token) {
    return res.status(401).json({ error: "Not authenticated. Please log in." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET) as TokenPayload;

    // Confirm the user still exists (e.g. wasn't deleted after the token was issued).
    const user = findUserById(payload.sub);
    if (!user) {
      return res.status(401).json({ error: "Not authenticated. Please log in." });
    }

    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}

/**
 * Requires the logged-in user to have a specific role.
 * - Not logged in -> 401 (handled by requireAuth, run first)
 * - Logged in but wrong role -> 403 Forbidden
 *   (we know who you are, you're just not allowed)
 */
export function requireRole(role: User["role"]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: "Not authenticated. Please log in." });
    }
    if (req.user.role !== role) {
      return res.status(403).json({ error: "You don't have permission to do that." });
    }
    next();
  };
}