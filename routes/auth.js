const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/user");

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

let refreshTokens = []; // in-memory store for demo

// --- SIGNUP ---
router.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) return res.status(400).json({ error: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ username, email, password: hashedPassword });
    res.json({ user: { id: newUser._id, username: newUser.username, email: newUser.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Signup failed" });
  }
});

// --- LOGIN ---
router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "User not found" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: "Invalid password" });

        // Access token expires in 3 minutes
    const accessTokenExpiry = 3 * 60; // seconds
    const expiresAt = new Date(Date.now() + accessTokenExpiry * 1000); // timestamp in ISO format
    const accessToken = jwt.sign({ userId: user._id }, ACCESS_TOKEN_SECRET, { expiresIn: `${accessTokenExpiry}s` });
    const refreshToken = jwt.sign({ userId: user._id }, REFRESH_TOKEN_SECRET, { expiresIn: "7d" });

    refreshTokens.push(refreshToken);

    res.cookie("refreshToken", refreshToken, { httpOnly: true, path: "/api/auth/refresh-token" });
    res.json({ accessToken, refreshToken: refreshToken, expiresIn: expiresAt.toISOString() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// --- GET ME ---
router.get("/me", async (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  try {
    const payload = jwt.verify(token, ACCESS_TOKEN_SECRET);
    const user = await User.findById(payload.userId).select("-password");
    res.json(user);
  } catch (err) {
    res.sendStatus(403);
  }
});

// --- REFRESH TOKEN ---
router.post("/refresh-token", (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.sendStatus(401);
  if (!refreshTokens.includes(token)) return res.sendStatus(403);

  try {
    const payload = jwt.verify(token, REFRESH_TOKEN_SECRET);
    const accessToken = jwt.sign({ userId: payload.userId }, ACCESS_TOKEN_SECRET, { expiresIn: "2m" });
    res.json({ accessToken });
  } catch (err) {
    res.sendStatus(403);
  }
});

// --- LOGOUT ---
router.post("/logout", (req, res) => {
  const token = req.cookies.refreshToken;
  refreshTokens = refreshTokens.filter(t => t !== token);
  res.clearCookie("refreshToken", { path: "/api/auth/refresh-token" });
  res.sendStatus(200);
});

module.exports = router;
