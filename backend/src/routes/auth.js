const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { User } = require("../models");
const { protect } = require("../middleware/auth");

const sign = user => jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET || "development-secret-change-me", { expiresIn: process.env.JWT_EXPIRES_IN || "1d" });

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email: String(email || "").toLowerCase() });
  if (!user || !user.active || !(await bcrypt.compare(password || "", user.password)))
    return res.status(401).json({ message: "Invalid email or password" });
  res.json({ token: sign(user), user: { id: user._id, name: user.name, email: user.email, role: user.role } });
});
router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || password.length < 8) return res.status(400).json({ message: "Name, email and password (minimum 8 characters) are required" });
  if (await User.exists({ email: email.toLowerCase() })) return res.status(409).json({ message: "Email already registered" });
  const user = await User.create({ name, email, password: await bcrypt.hash(password, 12), role: "analyst" });
  res.status(201).json({ token: sign(user), user: { id: user._id, name: user.name, email: user.email, role: user.role } });
});
router.get("/me", protect, (req, res) => res.json({ user: req.user }));
module.exports = router;
