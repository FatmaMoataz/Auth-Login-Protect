import bcrypt from "bcryptjs";

export interface User {
  id: string;
  email: string;
  passwordHash: string;
  role: "user" | "admin";
}

// In-memory "database". Swap this for a real DB (Postgres, SQLite, etc.)
// once you're comfortable with the auth flow — the shape of the code
// around it barely changes.
const users: User[] = [];
let nextId = 1;

export async function createUser(
  email: string,
  plainPassword: string,
  role: User["role"] = "user"
): Promise<User> {
  const existing = findUserByEmail(email);
  if (existing) {
    throw new Error("EMAIL_TAKEN");
  }

  // 10 salt rounds is a reasonable default: strong enough, not too slow.
  const passwordHash = await bcrypt.hash(plainPassword, 10);

  const user: User = {
    id: String(nextId++),
    email: email.toLowerCase(),
    passwordHash,
    role,
  };
  users.push(user);
  return user;
}

export function findUserByEmail(email: string): User | undefined {
  return users.find((u) => u.email === email.toLowerCase());
}

export function findUserById(id: string): User | undefined {
  return users.find((u) => u.id === id);
}

export async function verifyPassword(
  user: User,
  plainPassword: string
): Promise<boolean> {
  return bcrypt.compare(plainPassword, user.passwordHash);
}

// Never send passwordHash back to the client.
export function toPublicUser(user: User) {
  return { id: user.id, email: user.email, role: user.role };
}