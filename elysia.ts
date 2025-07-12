import { Elysia } from "elysia";
import { SignJWT, jwtVerify } from "jose";

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const REDIRECT_URI = "http://localhost:3000/callback";
const JWT_SECRET = new TextEncoder().encode("super-secret");

const app = new Elysia();

// 🔐 Защищённый маршрут
app.get("/profile", async ({ request, set }) => {
  const auth = request.headers.get("authorization");
  if (!auth?.startsWith("Bearer ")) {
    set.status = 401;
    return { error: "Unauthorized" };
  }

  try {
    const token = auth.split(" ")[1];
    const payload = await jwtVerify(token, JWT_SECRET);
    return { user: payload };
  } catch {
    set.status = 403;
    return { error: "Invalid token" };
  }
});

// 🔗 Логин → редирект на Google
app.get("/login", () => {
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");

  return new Response(null, {
    status: 302,
    headers: { Location: url.toString() },
  });
});

// 🎯 Callback от Google
app.get("/callback", async ({ query, set }) => {
  const code = query.code;

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      grant_type: "authorization_code",
    }),
  });

  const data = await res.json();
  const userInfo = await fetch(
    "https://www.googleapis.com/oauth2/v2/userinfo",
    {
      headers: { Authorization: `Bearer ${data.access_token}` },
    },
  );

  const user = await userInfo.json();

  // Создание JWT токена
  const jwt = await new SignJWT({ email: user.email })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime("1h")
    .sign(JWT_SECRET);

  return { token: jwt };
});

app.listen(3000);
console.log("🦊 Elysia + OAuth2 listening on http://localhost:3000");
