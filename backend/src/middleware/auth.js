const jwt = require("jsonwebtoken");
const { User } = require("../models");

async function protect(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    if (!token) return res.status(401).json({ message: "Authentication required" });
    const payload = jwt.verify(token, process.env.JWT_SECRET || "development-secret-change-me");
    const user = await User.findById(payload.id).select("-password");
    if (!user || !user.active) return res.status(401).json({ message: "Account unavailable" });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ message: "Invalid or expired token" });
  }
}
const adminOnly = (req, res, next) => req.user?.role === "admin"
  ? next() : res.status(403).json({ message: "Administrator access required" });
module.exports = { protect, adminOnly };
