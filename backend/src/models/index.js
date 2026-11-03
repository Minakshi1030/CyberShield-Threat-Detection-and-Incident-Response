const mongoose = require("mongoose");
const { Schema, model } = mongoose;

const User = model("User", new Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["admin", "analyst"], default: "analyst" },
  active: { type: Boolean, default: true }
}, { timestamps: true }));

const Log = model("Log", new Schema({
  timestamp: { type: Date, default: Date.now, index: true },
  source: { type: String, default: "manual" },
  sourceIp: { type: String, default: "unknown", index: true },
  username: String,
  eventType: { type: String, default: "system" },
  message: { type: String, required: true },
  raw: Schema.Types.Mixed,
  severity: { type: String, enum: ["low","medium","high","critical"], default: "low" },
  processed: { type: Boolean, default: false }
}, { timestamps: true }));

const Alert = model("Alert", new Schema({
  title: { type: String, required: true },
  description: String,
  sourceIp: String,
  severity: { type: String, enum: ["low","medium","high","critical"], default: "medium" },
  riskScore: { type: Number, default: 30 },
  status: { type: String, enum: ["open","investigating","resolved","false-positive"], default: "open" },
  ruleName: String,
  mitre: String,
  logIds: [{ type: Schema.Types.ObjectId, ref: "Log" }],
  assignedTo: { type: Schema.Types.ObjectId, ref: "User" },
  createdBy: { type: Schema.Types.ObjectId, ref: "User" }
}, { timestamps: true }));

const Incident = model("Incident", new Schema({
  title: { type: String, required: true },
  description: String,
  severity: { type: String, enum: ["low","medium","high","critical"], default: "medium" },
  status: { type: String, enum: ["open","investigating","contained","resolved","closed"], default: "open" },
  priority: { type: String, enum: ["low","normal","high","urgent"], default: "normal" },
  alert: { type: Schema.Types.ObjectId, ref: "Alert" },
  assignee: { type: Schema.Types.ObjectId, ref: "User" },
  notes: [{ author: String, text: String, createdAt: { type: Date, default: Date.now } }],
  resolution: String,
  resolvedAt: Date
}, { timestamps: true }));

const Rule = model("Rule", new Schema({
  name: { type: String, required: true },
  description: String,
  pattern: { type: String, required: true },
  eventTypes: [String],
  severity: { type: String, enum: ["low","medium","high","critical"], default: "medium" },
  riskScore: { type: Number, min: 1, max: 100, default: 50 },
  mitre: String,
  enabled: { type: Boolean, default: true },
  isSystem: { type: Boolean, default: false }
}, { timestamps: true }));

const Audit = model("Audit", new Schema({
  actor: String, action: String, targetType: String, targetId: String,
  details: String, ip: String
}, { timestamps: true }));

module.exports = { User, Log, Alert, Incident, Rule, Audit };
