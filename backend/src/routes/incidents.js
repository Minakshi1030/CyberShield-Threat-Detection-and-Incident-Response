const router = require("express").Router();
const { Incident } = require("../models");
const { protect } = require("../middleware/auth");
const audit = require("../utils/audit");
router.use(protect);
router.get("/", async (req,res) => res.json(await Incident.find().populate("assignee","name email").populate("alert","title severity").sort({updatedAt:-1})));
router.post("/", async (req,res) => {
  if (!req.body.title) return res.status(400).json({message:"Incident title is required"});
  const item = await Incident.create(req.body);
  await audit(req,"INCIDENT_CREATED","Incident",item._id);
  res.status(201).json(item);
});
router.patch("/:id", async (req,res) => {
  const allowed = ["title","description","severity","status","priority","assignee","resolution"];
  const update = Object.fromEntries(Object.entries(req.body).filter(([k])=>allowed.includes(k)));
  if (update.status === "resolved" || update.status === "closed") update.resolvedAt = new Date();
  const item = await Incident.findByIdAndUpdate(req.params.id,update,{new:true}).populate("assignee","name email");
  if (!item) return res.status(404).json({message:"Incident not found"});
  await audit(req,"INCIDENT_UPDATED","Incident",item._id,JSON.stringify(update));
  res.json(item);
});
router.post("/:id/notes", async (req,res) => {
  if (!req.body.text) return res.status(400).json({message:"Note text is required"});
  const item = await Incident.findByIdAndUpdate(req.params.id,{$push:{notes:{author:req.user.name,text:req.body.text}}},{new:true});
  if (!item) return res.status(404).json({message:"Incident not found"});
  await audit(req,"INCIDENT_NOTE_ADDED","Incident",item._id);
  res.json(item);
});
module.exports = router;
