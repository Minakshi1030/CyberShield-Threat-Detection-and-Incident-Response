const { Rule, Alert } = require("../models");

function classify(message = "") {
  const text = String(message).toLowerCase();
  if (/union\s+select|or\s+1=1|drop\s+table|select.+from/.test(text)) return "sql-injection";
  if (/<script|javascript:|onerror\s*=|onload\s*=/.test(text)) return "xss";
  if (/(\.\.\/|%2e%2e%2f|etc\/passwd)/.test(text)) return "path-traversal";
  if (/failed login|authentication failed|invalid password/.test(text)) return "failed-login";
  if (/port scan|multiple ports|scan detected/.test(text)) return "port-scan";
  return null;
}
async function analyzeLog(log, actorId) {
  const kind = classify(log.message);
  const rules = await Rule.find({ enabled: true });
  const matched = rules.find(r => {
    const haystack = `${log.message} ${log.eventType} ${log.source}`;
    try { return new RegExp(r.pattern, "i").test(haystack); } catch { return false; }
  });
  const rule = matched || (kind ? {
    name: kind.replaceAll("-", " ").toUpperCase(),
    severity: kind === "failed-login" ? "high" : "critical",
    riskScore: kind === "failed-login" ? 72 : 90,
    mitre: kind === "failed-login" ? "T1110" : "T1190"
  } : null);
  if (!rule) return null;
  const exists = await Alert.findOne({ logIds: log._id, ruleName: rule.name });
  if (exists) return exists;
  const alert = await Alert.create({
    title: rule.name, description: `Detection rule matched event: ${log.message}`,
    sourceIp: log.sourceIp, severity: rule.severity, riskScore: rule.riskScore,
    ruleName: rule.name, mitre: rule.mitre, logIds: [log._id], createdBy: actorId
  });
  log.processed = true;
  await log.save();
  return alert;
}
module.exports = { analyzeLog, classify };
