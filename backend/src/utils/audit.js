const { Audit } = require("../models");
module.exports = async (req, action, targetType, targetId, details = "") => {
  try {
    await Audit.create({ actor: req.user?.email || "system", action, targetType, targetId: String(targetId || ""), details, ip: req.ip });
  } catch (e) { console.error("Audit write failed:", e.message); }
};
