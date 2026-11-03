const router = require("express").Router();
const { Rule } = require("../models");
const { protect, adminOnly } = require("../middleware/auth");
const audit = require("../utils/audit");
router.use(protect);
router.get("/", async (req,res)=>res.json(await Rule.find().sort({isSystem:-1,name:1})));
router.post("/", async (req,res)=>{
  if (!req.body.name || !req.body.pattern) return res.status(400).json({message:"Rule name and regex pattern are required"});
  try { new RegExp(req.body.pattern); } catch { return res.status(400).json({message:"Invalid regular expression"}); }
  const item = await Rule.create({...req.body,isSystem:false});
  await audit(req,"RULE_CREATED","Rule",item._id);
  res.status(201).json(item);
});
router.patch("/:id", async (req,res)=>{
  const item = await Rule.findById(req.params.id);
  if (!item) return res.status(404).json({message:"Rule not found"});
  if (item.isSystem) return res.status(403).json({message:"System rules cannot be edited"});
  const allowed = ["name","description","pattern","severity","riskScore","mitre","enabled","eventTypes"];
  allowed.forEach(k=>{if(req.body[k]!==undefined)item[k]=req.body[k];});
  await item.save(); await audit(req,"RULE_UPDATED","Rule",item._id);
  res.json(item);
});
router.delete("/:id",adminOnly,async(req,res)=>{
  const item=await Rule.findById(req.params.id);
  if(!item)return res.status(404).json({message:"Rule not found"});
  if(item.isSystem)return res.status(403).json({message:"System rules cannot be deleted"});
  await item.deleteOne(); await audit(req,"RULE_DELETED","Rule",item._id); res.json({message:"Rule deleted"});
});
module.exports=router;
