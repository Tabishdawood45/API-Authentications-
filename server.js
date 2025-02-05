require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const app = express();
const PORT = 3000;

app.use(bodyParser.json());

const users = {
    user1: { password: "password1", role: "user" },
    admin: { password: "adminpass", role: "admin" },
};

const SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

let refreshTokens = [];

// Route: Sign In
app.post("/signin", (req, res) => {
    const { username, password } = req.body;

    if (!users[username] || users[username].password !== password) {
        return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = { username, role: users[username].role };
    const accessToken = jwt.sign(user, SECRET, { expiresIn: "15m" });
    const refreshToken = jwt.sign(user, REFRESH_SECRET);

    refreshTokens.push(refreshToken);
    res.json({ accessToken, refreshToken });
});

// Middleware: Authenticate JWT
function authenticateJWT(req, res, next) {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Middleware: Role-Based Authorization
function authorizeRole(role) {
    return (req, res, next) => {
        if (req.user.role !== role) return res.sendStatus(403);
        next();
    };
}

// Protected Route: Fetch Posts
app.get("/posts", authenticateJWT, (req, res) => {
    res.json([{ title: "Post 1", content: "This is a protected post" }]);
});

// Protected Route: Admin Only
app.post("/admin", authenticateJWT, authorizeRole("admin"), (req, res) => {
    res.json({ message: "Admin action performed" });
});

//  Route: Refresh Token
app.post("/refresh", (req, res) => {
    const { token } = req.body;
    if (!token || !refreshTokens.includes(token)) return res.sendStatus(403);

    jwt.verify(token, REFRESH_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        const newAccessToken = jwt.sign({ username: user.username, role: user.role }, SECRET, { expiresIn: "15m" });
        res.json({ accessToken: newAccessToken });
    });
});

// Route: Logout
app.post("/logout", (req, res) => {
    refreshTokens = refreshTokens.filter(t => t !== req.body.token);
    res.sendStatus(204);
});

// Start Server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
app.get("/", (req, res) => {
    res.send("Welcome to the JWT Auth API!");
});


