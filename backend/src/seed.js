require("dotenv").config();
const mongoose=require("mongoose"),bcrypt=require("bcryptjs");
const {User,Rule,Log}=require("./models");
(async()=>{
 await mongoose.connect(process.env.MONGO_URI||"mongodb://127.0.0.1:27017/cybershield");
 await User.updateOne({email:"admin@cybershield.local"},{$setOnInsert:{name:"CyberShield Admin",email:"admin@cybershield.local",password:await bcrypt.hash("CyberShield@123",12),role:"admin"}},{upsert:true});
 const rules=[
  {name:"Repeated Authentication Failures",description:"Detects failed authentication activity",pattern:"failed login|authentication failed|invalid password",severity:"high",riskScore:75,mitre:"T1110"},
  {name:"SQL Injection Indicator",description:"Detects common SQL injection strings in telemetry",pattern:"union\\s+select|or\\s+1=1|drop\\s+table",severity:"critical",riskScore:95,mitre:"T1190"},
  {name:"Cross-Site Scripting Indicator",description:"Detects script injection patterns",pattern:"<script|javascript:|onerror\\s*=",severity:"high",riskScore:85,mitre:"T1059"},
  {name:"Path Traversal Indicator",description:"Detects traversal attempts",pattern:"\\.\\./|etc/passwd",severity:"high",riskScore:82,mitre:"T1006"}
 ];
 for(const r of rules) await Rule.updateOne({name:r.name},{$setOnInsert:{...r,isSystem:true,enabled:true}},{upsert:true});
 if(await Log.countDocuments()===0) await Log.insertMany([
  {message:"Normal user login successful",eventType:"authentication",sourceIp:"192.0.2.10",source:"seed"},
  {message:"Failed login: invalid password for admin",eventType:"authentication",sourceIp:"198.51.100.24",source:"seed"},
  {message:"GET /search?q=' UNION SELECT username FROM users",eventType:"web",sourceIp:"203.0.113.18",source:"seed"}
 ]);
 console.log("Seed complete. Admin: admin@cybershield.local / CyberShield@123");
 await mongoose.disconnect();
})().catch(e=>{console.error(e);process.exit(1);});
