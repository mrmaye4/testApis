import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as SamlStrategy } from "passport-saml";
import bodyParser from "body-parser";
import * as dotenv from "dotenv";

dotenv.config();

const app = express();

console.log(process.env.KEYKCLOAK_CERF);

// 🔐 Конфигурация SAML
passport.use(
  new SamlStrategy(
    {
      path: "/login/callback",
      entryPoint: "http://localhost:8080/realms/demo/protocol/saml",
      issuer: "express-saml",
      cert: process.env.KEYKCLOAK_CERF!, // Сюда вставь cert из Keycloak (X.509)
      identifierFormat: null,
    },
    (profile, done) => {
      // @ts-ignore
      return done(null, profile);
    },
  ),
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(
  session({ secret: "samlSecret", resave: false, saveUninitialized: true }),
);
app.use(passport.initialize());
app.use(passport.session());

// 🔗 Запускаем SAML логин
app.get(
  "/login",
  passport.authenticate("saml", { failureRedirect: "/", failureFlash: true }),
  (req, res) => {
    res.redirect("/");
  },
);

// 🔄 Обратный вызов от Keycloak
app.post(
  "/login/callback",
  passport.authenticate("saml", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect("/profile");
  },
);

// 🔐 Приватный маршрут
app.get("/profile", (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).send("Not authenticated");
  res.json(req.user);
});

app.listen(3000, () =>
  console.log("🟢 SAML SP running on http://localhost:3000"),
);
