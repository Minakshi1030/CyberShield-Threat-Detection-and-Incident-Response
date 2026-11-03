const router = require("express").Router();
const { Log } = require("../models");
const { protect } = require("../middleware/auth");
const { analyzeLog } = require("../utils/detect");
const audit = require("../utils/audit");
router.use(protect);

router.get("/", async (req,res) => {
  const page = Math.max(1, Number(req.query.page) || 1), limit = Math.min(100, Number(req.query.limit) || 50);
  const q = {};
  if (req.query.search) q.$or = [{ message: new RegExp(req.query.search, "i") }, { sourceIp: new RegExp(req.query.search, "i") }, { eventType: new RegExp(req.query.search, "i") }];
  if (req.query.severity) q.severity = req.query.severity;
  const [items,total] = await Promise.all([Log.find(q).sort({timestamp:-1}).skip((page-1)*limit).limit(limit), Log.countDocuments(q)]);
  res.json({ items, total, page, pages: Math.ceil(total/limit) });
});
router.post("/", async (req,res) => {
  const { message, sourceIp, eventType, username, source } = req.body;
  if (!message) return res.status(400).json({message:"Log message is required"});
  const log = await Log.create({ message, sourceIp: sourceIp || "unknown", eventType: eventType || "system", username, source: source || "manual", raw: req.body });
  const alert = await analyzeLog(log, req.user._id);
  await audit(req, "LOG_INGESTED", "Log", log._id, alert ? `Detection: ${alert.ruleName}` : "No rule matched");
  res.status(201).json({ log, alert });
});
router.post("/bulk", async (req,res) => {
  if (!Array.isArray(req.body.logs) || req.body.logs.length > 500) return res.status(400).json({message:"Provide up to 500 logs"});
  const results = [];
  for (const item of req.body.logs) {
    if (!item.message) continue;
    const log = await Log.create({ message:item.message, sourceIp:item.sourceIp || "unknown", eventType:item.eventType || "system", source:item.source || "bulk", username:item.username, raw:item });
    const alert = await analyzeLog(log, req.user._id);
    results.push({ logId:log._id, alertId:alert?._id || null });
  }
  await audit(req, "BULK_LOG_INGESTED", "Log", "", `${results.length} logs`);
  res.status(201).json({ imported:results.length, results });
});
router.delete("/:id", async (req,res) => {
  const item = await Log.findByIdAndDelete(req.params.id);
  if (!item) return res.status(404).json({message:"Log not found"});
  await audit(req,"LOG_DELETED","Log",item._id);
  res.json({message:"Log deleted"});
});
module.exports = router;
