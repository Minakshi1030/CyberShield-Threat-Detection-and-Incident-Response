const router = require("express").Router();
const { Alert, Incident } = require("../models");
const { protect } = require("../middleware/auth");
const audit = require("../utils/audit");
router.use(protect);
router.get("/", async (req,res) => {
  const q = {};
  if (req.query.status) q.status = req.query.status;
  if (req.query.severity) q.severity = req.query.severity;
  const items = await Alert.find(q).populate("assignedTo","name email").sort({createdAt:-1}).limit(300);
  res.json(items);
});
router.patch("/:id", async (req,res) => {
  const allowed = ["status","assignedTo"];
  const update = Object.fromEntries(Object.entries(req.body).filter(([k])=>allowed.includes(k)));
  const item = await Alert.findByIdAndUpdate(req.params.id,update,{new:true}).populate("assignedTo","name email");
  if (!item) return res.status(404).json({message:"Alert not found"});
  await audit(req,"ALERT_UPDATED","Alert",item._id,JSON.stringify(update));
  res.json(item);
});
router.post("/:id/create-incident", async (req,res) => {
  const alert = await Alert.findById(req.params.id);
  if (!alert) return res.status(404).json({message:"Alert not found"});
  const incident = await Incident.create({ title:alert.title, description:alert.description, severity:alert.severity, alert:alert._id });
  alert.status = "investigating"; await alert.save();
  await audit(req,"INCIDENT_CREATED","Incident",incident._id,`From alert ${alert._id}`);
  res.status(201).json(incident);
});
module.exports = router;
