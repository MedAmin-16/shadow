import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, timestamp, jsonb, serial, decimal, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

// =====================================================
// CREDITS SYSTEM - Persistent Database Tables
// =====================================================

// User Credits Table - stores current balance and plan level
export const userCreditsTable = pgTable("user_credits", {
  id: serial("id").primaryKey(),
  userId: varchar("user_id").notNull().unique(),
  balance: integer("balance").notNull().default(1000),
  planLevel: varchar("plan_level", { length: 20 }).notNull().default("STANDARD"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

// Credit Transaction Types
export type CreditTransactionType = 
  | "initial_grant"
  | "purchase"
  | "scan_deduction"
  | "agent_deduction"
  | "refund"
  | "bonus"
  | "plan_upgrade"
  | "admin_adjustment";

// Credit Transactions Table - full audit trail
export const creditTransactionsTable = pgTable("credit_transactions", {
  id: serial("id").primaryKey(),
  userId: varchar("user_id").notNull(),
  transactionType: varchar("transaction_type", { length: 50 }).notNull(),
  amount: integer("amount").notNull(),
  balanceBefore: integer("balance_before").notNull(),
  balanceAfter: integer("balance_after").notNull(),
  description: text("description"),
  metadata: jsonb("metadata"),
  agentType: varchar("agent_type", { length: 20 }),
  scanId: varchar("scan_id"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const insertCreditTransactionSchema = createInsertSchema(creditTransactionsTable);
export type InsertCreditTransaction = z.infer<typeof insertCreditTransactionSchema>;
export type CreditTransaction = typeof creditTransactionsTable.$inferSelect;
export type DbUserCredits = typeof userCreditsTable.$inferSelect;

// Plan levels for credit-based gating
export type PlanLevel = "BASIC" | "STANDARD" | "ELITE";

// Plan configuration with LLM models and costs
export interface PlanConfig {
  planLevel: PlanLevel;
  llmModel: string;
  creditCostPerTarget: number;
  osintAccess: "limited" | "standard" | "full";
  osintQueryCost: number;
}

export const PLAN_CONFIGS: Record<PlanLevel, PlanConfig> = {
  BASIC: {
    planLevel: "BASIC",
    llmModel: "gpt-4o-mini",
    creditCostPerTarget: 100,
    osintAccess: "limited",
    osintQueryCost: 1,
  },
  STANDARD: {
    planLevel: "STANDARD",
    llmModel: "gpt-4o",
    creditCostPerTarget: 500,
    osintAccess: "standard",
    osintQueryCost: 2,
  },
  ELITE: {
    planLevel: "ELITE",
    llmModel: "gpt-5",
    creditCostPerTarget: 1000,
    osintAccess: "full",
    osintQueryCost: 5,
  },
};

// Scope cost calculation for multi-target scans
export interface ScopeCostEstimate {
  targets: string[];
  targetCount: number;
  costPerTarget: number;
  totalCost: number;
  planLevel: PlanLevel;
  llmModel: string;
}

export function calculateScopeCost(targets: string[], planLevel: PlanLevel): ScopeCostEstimate {
  const planConfig = PLAN_CONFIGS[planLevel];
  const targetCount = targets.length;
  const totalCost = targetCount * planConfig.creditCostPerTarget;
  
  return {
    targets,
    targetCount,
    costPerTarget: planConfig.creditCostPerTarget,
    totalCost,
    planLevel,
    llmModel: planConfig.llmModel,
  };
}

// User credits interface
export interface UserCredits {
  userId: string;
  balance: number;
  planLevel: PlanLevel;
  lastUpdated: string;
}

// Agent types
export type AgentType = "recon" | "scanner" | "exploiter" | "reporter";
export type AgentStatus = "pending" | "running" | "complete" | "failed";
export type ScanStatus = "pending" | "running" | "complete" | "failed";

// Agent result structure
export interface AgentResult {
  agentType: AgentType;
  status: AgentStatus;
  startedAt?: string;
  completedAt?: string;
  error?: string;
  data: Record<string, unknown>;
}

// Single target recon findings
export interface SingleTargetReconFindings {
  target: string;
  ip?: string;
  hostname?: string;
  ports?: number[];
  services?: { port: number; service: string; version?: string }[];
  technologies?: string[];
  subdomains?: string[];
  credit_deduction: number;
  strategic_decision_log: string;
}

// Recon agent findings (output payload for Agent 2) - supports multi-target batch
export interface ReconFindings {
  ip?: string;
  hostname?: string;
  ports?: number[];
  services?: { port: number; service: string; version?: string }[];
  technologies?: string[];
  subdomains?: string[];
  credit_deduction_recon: number;
  strategic_decision_log: string;
  llm_model_used: string;
  plan_level: PlanLevel;
  osint_queries_made: number;
  remaining_credits: number;
  scope_summary?: {
    total_targets: number;
    targets_processed: string[];
    cumulative_cost: number;
    cost_per_target: number;
  };
  target_results?: SingleTargetReconFindings[];
}

// Scanner agent findings
export interface ScannerFindings {
  vulnerabilities: {
    id: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
    description: string;
    port?: number;
    service?: string;
    cve?: string;
  }[];
  openPorts: number[];
  sslIssues?: string[];
}

// Exploiter agent findings
export interface ExploiterFindings {
  exploitAttempts: {
    vulnerability: string;
    success: boolean;
    technique: string;
    evidence?: string;
  }[];
  accessGained: boolean;
  riskLevel: "critical" | "high" | "medium" | "low";
}

// =====================================================
// REPORTER AGENT (Agent 4) - ELITE Tier Strategic Intelligence
// =====================================================

// Target audience types for executive summary customization
export type ReportAudience = "executive" | "cfo" | "cto" | "development" | "compliance";

// Financial risk quantification for ELITE tier
export interface FinancialRiskAssessment {
  vulnerabilityId: string;
  vulnerabilityTitle: string;
  severity: "critical" | "high" | "medium" | "low";
  estimatedLossMin: number;
  estimatedLossMax: number;
  estimatedLossRange: string;
  downtimeProbability: number;
  assetValue: number;
  annualizedRiskExposure: number;
  riskCategory: "data_breach" | "service_disruption" | "regulatory_fine" | "reputation_damage" | "ransomware";
  businessImpactDescription: string;
}

// Industry benchmarking data for strategic comparison
export interface IndustryBenchmark {
  industryName: string;
  averageSecurityScore: number;
  companyPercentile: number;
  medianVulnerabilityCount: number;
  topPerformerScore: number;
  averageTimeToRemediate: string;
  complianceStandards: string[];
  commonWeaknesses: string[];
  bestPractices: string[];
}

// Evidence integration from exploitation attempts
export interface ExploitationEvidence {
  vulnerabilityId: string;
  exploitTechnique: string;
  success: boolean;
  screenshotPath?: string;
  logSnippet?: string;
  timestamp: string;
  accessLevel?: string;
  dataAccessed?: string;
}

// Remediation code snippets from Agent 2
export interface RemediationSnippet {
  vulnerabilityId: string;
  vulnerabilityTitle: string;
  language: string;
  codeSnippet: string;
  configSnippet?: string;
  implementation: string;
  estimatedEffort: string;
  priority: number;
}

// Liability log for temporal awareness
export interface LiabilityLogEntry {
  date: string;
  eventType: "scan_completed" | "remediation_verified" | "vulnerability_discovered" | "cve_alert" | "emergency_scan";
  description: string;
  affectedAssets: string[];
  remediationStatus: "pending" | "in_progress" | "completed" | "verified";
  responsibleParty?: string;
}

// Security Status History for executive summary
export interface SecurityStatusHistory {
  lastFullScanDate: string;
  lastVerificationScanDate?: string;
  confirmedRemediations: number;
  pendingRemediations: number;
  emergencyScansTriggered: number;
  newCvesMonitored: number;
  liabilityLog: LiabilityLogEntry[];
}

// Audience-specific executive summary
export interface AudienceSpecificSummary {
  audience: ReportAudience;
  title: string;
  summary: string;
  keyMetrics: { label: string; value: string; trend?: "up" | "down" | "stable" }[];
  actionItems: string[];
  roiInsights?: string[];
  liabilityWarnings?: string[];
  technicalDetails?: string[];
}

// Reporter Agent cost configuration per plan level
export interface ReporterCostConfig {
  baseCost: number;
  financialAnalysisCost: number;
  benchmarkingCost: number;
  pdfGenerationCost: number;
  llmModel: string;
}

export const REPORTER_COSTS: Record<PlanLevel, ReporterCostConfig> = {
  ELITE: {
    baseCost: 500,
    financialAnalysisCost: 300,
    benchmarkingCost: 200,
    pdfGenerationCost: 100,
    llmModel: "gpt-5.1",
  },
  STANDARD: {
    baseCost: 100,
    financialAnalysisCost: 0,
    benchmarkingCost: 0,
    pdfGenerationCost: 50,
    llmModel: "gpt-4o",
  },
  BASIC: {
    baseCost: 25,
    financialAnalysisCost: 0,
    benchmarkingCost: 0,
    pdfGenerationCost: 0,
    llmModel: "gpt-4o-mini",
  },
};

// Enhanced Reporter output with ELITE tier features
export interface EnhancedReporterOutput {
  summary: string;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  securityScore: number;
  recommendations: string[];
  executiveSummary: string;
  
  // Plan level metadata
  planLevel: PlanLevel;
  llmModelUsed: string;
  creditDeductionReporter: number;
  remainingCredits: number;
  generatedAt: string;
  
  // ELITE tier: Financial Risk Quantification
  financialRiskAssessments?: FinancialRiskAssessment[];
  totalEstimatedRiskMin?: number;
  totalEstimatedRiskMax?: number;
  annualizedRiskExposure?: number;
  
  // ELITE tier: Audience-specific summaries
  audienceSpecificSummaries?: AudienceSpecificSummary[];
  boardLevelExecutiveSummary?: string;
  
  // ELITE tier: Industry Benchmarking
  industryBenchmark?: IndustryBenchmark;
  
  // ELITE tier: Evidence Integration
  exploitationEvidence?: ExploitationEvidence[];
  remediationSnippets?: RemediationSnippet[];
  
  // Temporal Awareness & Liability
  securityStatusHistory?: SecurityStatusHistory;
  
  // Metadata for Agent 1 integration
  verificationScanRequired?: boolean;
  emergencyMicroScanTriggers?: string[];
  nextRecommendedScanDate?: string;
  
  // Export paths
  executivePdfPath?: string;
  technicalPdfPath?: string;
  rawDataExportPath?: string;
  csvExportPath?: string;
  
  // Formatted financial risk range (e.g., "$50K - $150K")
  formattedRiskRange?: string;
}

// Legacy Reporter agent output (for backwards compatibility)
export interface ReporterOutput {
  summary: string;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  securityScore: number;
  recommendations: string[];
  executiveSummary: string;
}

// Scan record
export interface Scan {
  id: string;
  target: string;
  userId: string;
  status: ScanStatus;
  currentAgent: AgentType | null;
  progress: number;
  startedAt: string;
  completedAt?: string;
  error?: string;
  agentResults: {
    recon?: AgentResult & { data: ReconFindings };
    scanner?: AgentResult & { data: ScannerFindings };
    exploiter?: AgentResult & { data: ExploiterFindings };
    reporter?: AgentResult & { data: ReporterOutput };
  };
}

// Insert scan schema for API validation
export const insertScanSchema = z.object({
  target: z.string().min(1, "Target is required").max(500),
  userId: z.string().min(1, "User ID is required"),
});

export type InsertScan = z.infer<typeof insertScanSchema>;

// Project type
export interface Project {
  id: string;
  name: string;
  assetCount: number;
  lastScanDate: string;
  securityScore: number;
  createdAt: string;
}

export const insertProjectSchema = z.object({
  name: z.string().min(1, "Project name is required").max(100),
});

export type InsertProject = z.infer<typeof insertProjectSchema>;

// Activity type - matches ActivityLog component types
export interface Activity {
  id: string;
  type: "scan_started" | "scan_completed" | "scan_failed" | "vulnerability_found" | "project_created" | "user_login";
  message: string;
  timestamp: string;
  projectId?: string;
  scanId?: string;
}

// Report type
export interface Report {
  id: string;
  projectName: string;
  scanId: string;
  date: string;
  score: number;
  vulnerabilities: number;
  details?: {
    securityScore: number;
    tls?: {
      valid: boolean;
      protocol: string;
      expiresIn: string;
    };
    headers?: {
      contentSecurityPolicy: boolean;
      xFrameOptions: boolean;
      xContentTypeOptions: boolean;
      strictTransportSecurity: boolean;
    };
    vulnerabilities: {
      id: string;
      title: string;
      severity: "critical" | "high" | "medium" | "low" | "info";
      description: string;
    }[];
    recommendations: string[];
  };
}

// Settings type
export interface UserSettings {
  userId: string;
  notifications: {
    email: boolean;
    criticalAlerts: boolean;
    weeklyReports: boolean;
    scanComplete: boolean;
  };
  profile: {
    name: string;
    email: string;
  };
  company: {
    name: string;
    website: string;
  };
}

export const updateSettingsSchema = z.object({
  notifications: z.object({
    email: z.boolean(),
    criticalAlerts: z.boolean(),
    weeklyReports: z.boolean(),
    scanComplete: z.boolean(),
  }).optional(),
  profile: z.object({
    name: z.string(),
    email: z.string().email(),
  }).optional(),
  company: z.object({
    name: z.string(),
    website: z.string().url(),
  }).optional(),
});

// =====================================================
// SCANNER AGENT (Agent 2) - Credit-Based Gating System
// =====================================================

// Scanner Agent cost configuration per plan level
export interface ScannerCostConfig {
  baseCost: number;
  rePlanningFee: number;
  selfRegulationThreshold: number;
  authenticatedScanEnabled: boolean;
}

export const SCANNER_COSTS: Record<PlanLevel, ScannerCostConfig> = {
  ELITE: {
    baseCost: 1500,
    rePlanningFee: 500,
    selfRegulationThreshold: 500,
    authenticatedScanEnabled: true,
  },
  STANDARD: {
    baseCost: 250,
    rePlanningFee: 0,
    selfRegulationThreshold: 0,
    authenticatedScanEnabled: false,
  },
  BASIC: {
    baseCost: 50,
    rePlanningFee: 0,
    selfRegulationThreshold: 0,
    authenticatedScanEnabled: false,
  },
};

// Exploit approval gate for Agent 3 integration
export type ApprovalStatus = "pending" | "approved" | "rejected" | "expired";

export interface ExploitApprovalRequest {
  id: string;
  scanId: string;
  vulnerabilityId: string;
  vulnerabilityTitle: string;
  severity: "critical" | "high";
  requiredCredits: number;
  exploitationType: string;
  riskDescription: string;
  potentialImpact: string;
  liabilityAcknowledged: boolean;
  status: ApprovalStatus;
  createdAt: string;
  respondedAt?: string;
  userId: string;
}

export const EXPLOIT_APPROVAL_COST = 1000;

// Scanner credential configuration for Gray Box scanning (ELITE only)
export interface ScanCredentials {
  type: "session_token" | "api_key" | "basic_auth" | "oauth_token";
  value: string;
  expiresAt?: string;
  scope?: string[];
}

// Scanner decision types for WebSocket logging
export type ScannerDecisionType = 
  | "financial_gate"
  | "credit_self_regulation"
  | "waf_ids_detected"
  | "replanning_triggered"
  | "authenticated_scan_start"
  | "vulnerability_discovered"
  | "attack_chain_identified"
  | "poc_generated"
  | "remediation_generated"
  | "approval_required";

export interface ScannerDecisionLog {
  timestamp: string;
  decisionType: ScannerDecisionType;
  description: string;
  creditsInvolved?: number;
  vulnerabilityId?: string;
  metadata?: Record<string, unknown>;
}

// Enhanced vulnerability with additional scanner metadata
export interface EnhancedVulnerability {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  port?: number;
  service?: string;
  cve?: string;
  owaspCategory?: string;
  sansTop25?: string;
  attackChain?: string[];
  pocCode?: string;
  remediationCode?: string;
  remediationConfig?: string;
  confidenceScore: number;
  requiresApproval: boolean;
  exploitDifficulty: "trivial" | "easy" | "moderate" | "hard" | "expert";
}

// Enhanced Scanner findings with full Agent 2 output
export interface EnhancedScannerFindings {
  vulnerabilities: EnhancedVulnerability[];
  openPorts: number[];
  sslIssues?: string[];
  credit_deduction_scanner: number;
  decision_log: ScannerDecisionLog[];
  llm_model_used: string;
  plan_level: PlanLevel;
  remaining_credits: number;
  scan_type: "passive" | "active" | "authenticated";
  waf_ids_detected: boolean;
  replanning_occurred: boolean;
  replanning_cost: number;
  self_regulation_stops: number;
  attack_chains_found: number;
  pocs_generated: number;
  remediations_generated: number;
  pending_approvals: string[];
  scan_summary: {
    total_tests_run: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    info_count: number;
    security_score: number;
  };
}

// Calculate scanner cost based on plan level
export function calculateScannerCost(planLevel: PlanLevel): number {
  return SCANNER_COSTS[planLevel].baseCost;
}

// Check if authenticated scanning is available for plan
export function canUseAuthenticatedScan(planLevel: PlanLevel): boolean {
  return SCANNER_COSTS[planLevel].authenticatedScanEnabled;
}

// Get self-regulation threshold for plan (ELITE only feature)
export function getSelfRegulationThreshold(planLevel: PlanLevel): number {
  return SCANNER_COSTS[planLevel].selfRegulationThreshold;
}
