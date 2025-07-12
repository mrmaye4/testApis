import express from "express";
import * as openid from "openid-client";
import * as dotenv from "dotenv";

dotenv.config();

const app = express();
const port = 3000;

const issuerUrl = new URL("https://accounts.google.com");
const clientId = process.env.GOOGLE_CLIENT_ID!;
const clientSecret = process.env.GOOGLE_CLIENT_SECRET!;
const redirectUri = "http://localhost:3000/callback";
const codeVerifier = openid.randomPKCECodeVerifier();
const state = openid.randomState();

let config: openid.Configuration;

// 🔗 Начало авторизации
app.get("/login", async (req, res) => {
  const codeChallenge = await openid.calculatePKCECodeChallenge(codeVerifier);

  let parameters: Record<string, string> = {
    redirect_uri: redirectUri,
    scope: "openid email profile",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  };

  // if (!config.serverMetadata().supportsPKCE()) {
  //   parameters.state = state;
  // }

  const authUrl = openid.buildAuthorizationUrl(config, parameters);

  res.redirect(authUrl.href);
});

// 🎯 Callback от провайдера
app.get("/callback", async (req, res) => {
  const currentUrl = new URL(req.originalUrl, `http://localhost:${port}`);

  try {
    const tokenSet = await openid.authorizationCodeGrant(config, currentUrl, {
      pkceCodeVerifier: codeVerifier,
    });

    const expectedSubject = tokenSet.claims()?.sub || "";

    const userinfo = await openid.fetchUserInfo(
      config,
      tokenSet.access_token,
      expectedSubject,
    );

    res.send(`
    <h1>Добро пожаловать</h1>
    <pre>${JSON.stringify(userinfo, null, 2)}</pre>
  `);
  } catch (err: any) {
    console.error("❌ Ошибка при обмене кода на токен:", err);
    res.status(500).send(`<pre>${JSON.stringify(err, null, 2)}</pre>`);
  }
});

app.listen(port, async () => {
  console.log(`🟢 Сервер запущен: http://localhost:${port}`);
  config = await openid.discovery(
    issuerUrl,
    clientId,
    clientSecret,
    openid.ClientSecretPost(),
  );
});
