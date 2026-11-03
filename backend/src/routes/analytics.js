const router = require("express").Router();
const { Log, Alert, Incident, Audit, User } = require("../models");
const { protect } = require("../middleware/auth");
router.use(protect);
router.get("/summary", async (req,res)=>{
  const [logs,alerts,openAlerts,incidents,openIncidents,users,severity,trend,recent] = await Promise.all([
    Log.countDocuments(), Alert.countDocuments(), Alert.countDocuments({status:{$in:["open","investigating"]}}),
    Incident.countDocuments(), Incident.countDocuments({status:{$nin:["resolved","closed"]}}),
    User.countDocuments({active:true}),
    Alert.aggregate([{$group:{_id:"$severity",count:{$sum:1}}}]),
    Log.aggregate([{$match:{timestamp:{$gte:new Date(Date.now()-6*86400000)}}},{$group:{_id:{$dateToString:{format:"%Y-%m-%d",date:"$timestamp"}},count:{$sum:1}}},{$sort:{_id:1}}]),
    Alert.find().sort({createdAt:-1}).limit(6).select("title severity riskScore status createdAt")
  ]);
  res.json({logs,alerts,openAlerts,incidents,openIncidents,users,severity:severity.map(x=>({name:x._id,value:x.count})),trend:trend.map(x=>({date:x._id,count:x.count})),recent});
});
router.get("/audit",async(req,res)=>res.json(await Audit.find().sort({createdAt:-1}).limit(300)));
router.get("/users",async(req,res)=>res.json(await User.find({active:true}).select("name email role")));
module.exports=router;
