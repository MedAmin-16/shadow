import type { Express } from "express";
import type { Server } from "http";
import { scanRateLimiter } from "./src/middlewares/rateLimiter";
import { apiKeyAuth } from "./src/middlewares/apiKeyAuth";
import {
  startScan,
  getScanStatus,
  getAllScans,
  getScanById,
  deleteScan,
  downloadReport,
  getScanHistory,
} from "./src/controllers/scanController";
import {
  createApiKey,
  listApiKeys,
  deleteApiKey,
  getSecurityLogs,
} from "./src/controllers/apiKeyController";
import {
  getAllProjects,
  getProject,
  createProject,
  deleteProject,
} from "./src/controllers/projectController";
import { getActivities } from "./src/controllers/activityController";
import { getReports, getReport, createReportFromScan } from "./src/controllers/reportController";
import { getSettings, updateSettings } from "./src/controllers/settingsController";
import { getDashboardMetrics, getRecentVulnerabilities } from "./src/controllers/dashboardController";
import {
  getUserCredits,
  addCredits,
  refundCredits,
  getTransactionHistory,
  checkCredits,
  setPlanLevel,
} from "./src/controllers/creditsController";
import {
  analyzeApiSpec,
  getAnalysisTypes,
  parseSpec,
} from "./src/controllers/apiSecurityController";
import {
  startCSPMScan,
  getCSPMCost,
  getProviderMisconfigurations,
} from "./src/controllers/cspmController";

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  
  app.post("/api/keys", createApiKey);
  app.get("/api/keys/:userId", listApiKeys);
  app.delete("/api/keys/:keyId", deleteApiKey);
  app.get("/api/security/logs", getSecurityLogs);

  app.post("/api/scan", scanRateLimiter, apiKeyAuth, startScan);
  app.get("/api/scan/status/:id", scanRateLimiter, apiKeyAuth, getScanStatus);
  app.get("/api/scan/report/:id", scanRateLimiter, apiKeyAuth, downloadReport);
  app.get("/api/scan/history/:userId", scanRateLimiter, apiKeyAuth, getScanHistory);

  app.post("/api/scans", startScan);
  app.get("/api/scans", getAllScans);
  app.get("/api/scans/:id", getScanById);
  app.delete("/api/scans/:id", deleteScan);
  
  app.get("/api/projects", getAllProjects);
  app.get("/api/projects/:id", getProject);
  app.post("/api/projects", createProject);
  app.delete("/api/projects/:id", deleteProject);
  
  app.get("/api/activity", getActivities);
  
  app.get("/api/reports", getReports);
  app.get("/api/reports/:id", getReport);
  app.post("/api/reports", createReportFromScan);
  
  app.get("/api/settings", getSettings);
  app.patch("/api/settings", updateSettings);
  
  app.get("/api/dashboard/metrics", getDashboardMetrics);
  app.get("/api/dashboard/vulnerabilities", getRecentVulnerabilities);

  // Credits System Routes
  app.get("/api/credits/:userId", getUserCredits);
  app.post("/api/credits/add", addCredits);
  app.post("/api/credits/refund", refundCredits);
  app.get("/api/credits/:userId/history", getTransactionHistory);
  app.get("/api/credits/:userId/check", checkCredits);
  app.post("/api/credits/plan", setPlanLevel);

  // API Security Analysis Routes
  app.post("/api/security/api/analyze", analyzeApiSpec);
  app.get("/api/security/api/types", getAnalysisTypes);
  app.post("/api/security/api/parse", parseSpec);

  // CSPM (Cloud Security Posture Management) Routes
  app.post("/api/cspm/scan", scanRateLimiter, apiKeyAuth, startCSPMScan);
  app.get("/api/cspm/cost", apiKeyAuth, getCSPMCost);
  app.get("/api/cspm/checks/:provider", getProviderMisconfigurations);

  return httpServer;
}
