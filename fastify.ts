import Fastify from "fastify";
import fastifyOauth2 from "@fastify/oauth2";
import dotenv from "dotenv";

dotenv.config();

const fastify = Fastify({
  logger: true,
});

fastify.register(fastifyOauth2, {
  name: "githubOAuth",
  scope: ["user:email"],
  credentials: {
    client: {
      id: process.env.GITHUB_CLIENT_ID!,
      secret: process.env.GITHUB_CLIENT_SECRET!,
    },
    auth: {
      authorizeHost: "https://github.com",
      authorizePath: "/login/oauth/authorize",
      tokenHost: "https://github.com",
      tokenPath: "/login/oauth/access_token",
    },
  },
  startRedirectPath: "/login/github",
  callbackUri: "http://localhost:3000/login/github/callback",
});

fastify.get("/login/github/callback", async (request, reply) => {
  const token =
    await fastify?.githubOAuth?.getAccessTokenFromAuthorizationCodeFlow(
      request,
    );

  console.log("GitHub Access Token:", token);

  // Можно получить данные пользователя
  const userRes = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `token ${token.token.access_token}`,
    },
  });
  const user = await userRes.json();

  reply.send(user);
});

fastify.listen({ port: 3000 }, (err, address) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  console.log(`🚀 Server running at ${address}`);
});
