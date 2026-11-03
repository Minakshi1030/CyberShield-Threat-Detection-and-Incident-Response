const router = require("express").Router();
const { protect } = require("../middleware/auth");
const { Log } = require("../models");
const { analyzeLog } = require("../utils/detect");
const audit = require("../utils/audit");
router.use(protect);
// Generates synthetic telemetry only; it does not send traffic or attack any host.
router.post("/",async(req,res)=>{
  const samples=[
    {message:"Failed login: invalid password for administrator",eventType:"authentication",sourceIp:"198.51.100.24",username:"admin"},
    {message:"Multiple failed login attempts detected for root account",eventType:"authentication",sourceIp:"203.0.113.18",username:"root"},
    {message:"GET /search?q=' UNION SELECT username,password FROM users",eventType:"web",sourceIp:"192.0.2.44"},
    {message:"GET /comment?text=<script>alert(1)</script>",eventType:"web",sourceIp:"192.0.2.51"},
    {message:"Path traversal attempt ../../etc/passwd",eventType:"web",sourceIp:"203.0.113.77"},
    {message:"Normal user session started",eventType:"authentication",sourceIp:"192.0.2.10"}
  ];
  const created=[];
  for(const s of samples){const log=await Log.create({...s,source:"simulation"});const alert=await analyzeLog(log,req.user._id);created.push({log,alert});}
  await audit(req,"SIMULATION_RUN","Simulation","",`${created.length} synthetic events`);
  res.status(201).json({message:"Synthetic security events generated",count:created.length,created});
});
module.exports=router;
