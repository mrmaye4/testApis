import { Handler, Hono, MiddlewareHandler } from "hono";
import { serve } from "@hono/node-server";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

const { sign, verify } = jwt;

dotenv.config();

const app = new Hono();

// ⚙️ Секрет для подписи токенов
const JWT_SECRET = process.env.JWT_SECRET!;

// 🚪 Публичный маршрут (логин)
app.post("/login", async (c) => {
  const { username, password } = await c.req.json();

  // 🔒 Здесь должна быть реальная проверка
  if (username === "admin" && password === "password") {
    const token =
      "Bearer " +
      sign({ username }, JWT_SECRET, {
        expiresIn: "1h",
      });

    return c.json({ token });
  }

  return c.json({ error: "Invalid credentials" }, 401);
});

// 🔐 Middleware для проверки токена
const authMiddleware: MiddlewareHandler = async (c, next) => {
  const authHeader = c.req.header("Authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return c.json({ error: "Unauthorized" }, 401);
  }

  const token = authHeader.split(" ")[1];

  try {
    const payload = verify(token, JWT_SECRET);
    c.set("user", payload);
    await next();
  } catch {
    return c.json({ error: "Invalid token" }, 403);
  }
};

const getProfile: Handler = async (c) => {
  const user = c.get("user");
  return c.json({ message: "Protected data", user });
};

// 🔒 Приватный маршрут
app.get("/profile", authMiddleware, getProfile);

serve(
  {
    fetch: app.fetch,
    port: 3000,
  },
  (info) => {
    console.log(`Server is running on http://localhost:${info.port}`);
  },
);
