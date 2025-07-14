import { Elysia, t } from "elysia";
import bcrypt from "bcrypt";
import sqlite3 from 'sqlite3';

sqlite3.verbose();

const db = new sqlite3.Database('./mydb.sqlite');

const app = new Elysia()

type TUser = {
    id: number,
    email: string,
    password: string
}

function getAsync<T = any>(sql: string, params: any[] = []): Promise<T | undefined> {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else { // @ts-ignore
                resolve(row);
            }
        });
    });
}

// Регистрация
app.post(
    "/register",
    async ({ body }) => {
        const hashed = await bcrypt.hash(body.password, 10);
        try {
            const insertUser = db.prepare("INSERT INTO users (email, password) VALUES (?, ?)");
            insertUser.run(body.email, hashed);

            return { ok: true };
        } catch(e) {
            console.error(e);
            return { error: "Email already exists" };
        }
    },
    {
        body: t.Object({
            email: t.String({ format: "email" }),
            password: t.String({ minLength: 6 })
        })
    }
);

// Логин
app.post(
    "/login",
    async ({ body, cookie }) => {
        const user = await getAsync<TUser>("SELECT * FROM users WHERE email = ?", [body.email]);

        if (!user) return { error: "User not found" };

        const valid = await bcrypt.compare(body.password, user.password);
        if (!valid) return { error: "Invalid password" };

        cookie.session.set({
            value: String(user.id),
            httpOnly: true,
            path: "/",
            maxAge: 60 * 60 * 24, // 1 день
            sameSite: "lax"
        })

        return { ok: true };
    },
    {
        body: t.Object({
            email: t.String(),
            password: t.String()
        })
    }
);

// Приватный маршрут
app.get("/profile", async ({ cookie }) => {
    const user = await getAsync<TUser>("SELECT * FROM users WHERE id = ?", [cookie.session?.value]);
    if (!user) return { error: "Unauthorized" };
    return { id: user.id, email: user.email };
});

// Логаут
app.post("/logout", ({ cookie }) => {
    cookie.session.set({
        path: "/",
        maxAge: 0
    })

    return { ok: true };
});

// Запуск
app.listen(3000, () => {
    console.log("🧁 Elysia + Bun running on http://localhost:3000");
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT)");
});
