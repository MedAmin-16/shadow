import type { 
  Scan, 
  AgentType, 
  ReconFindings, 
  ScannerFindings, 
  ExploiterFindings, 
  ReporterOutput,
  PlanLevel,
  EnhancedScannerFindings,
  EnhancedReporterOutput
} from "@shared/schema";
import type { ExploiterStealthFindings } from "@shared/stealth";
import { runReconAgent } from "./recon";
import { runScannerAgent } from "./scanner";
import { runExploiterAgent } from "./exploiter";
import { runStealthExploiterAgent } from "./stealthExploiter";
import { runReporterAgent } from "./reporter";
import { storage } from "../storage";
import { generateAllReportFormats } from "../src/services/reportService";

export { runStealthExploiterAgent } from "./stealthExploiter";

const AGENT_SEQUENCE: AgentType[] = ["recon", "scanner", "exploiter", "reporter"];

function getAgentProgress(agentIndex: number, agentProgress: number): number {
  const baseProgress = agentIndex * 25;
  return baseProgress + Math.round((agentProgress / 100) * 25);
}

export interface PipelineContext {
  userId?: string;
  planLevel?: PlanLevel;
}

export async function runAgentPipeline(scanId: string, context?: PipelineContext): Promise<void> {
  let scan = await storage.getScan(scanId);
  if (!scan) {
    throw new Error(`Scan ${scanId} not found`);
  }

  let reconData: ReconFindings | undefined;
  let scannerData: EnhancedScannerFindings | undefined;
  let exploiterData: ExploiterFindings | undefined;

  try {
    for (let i = 0; i < AGENT_SEQUENCE.length; i++) {
      const agentType = AGENT_SEQUENCE[i];
      
      // Fetch latest scan state before updating
      scan = await storage.getScan(scanId);
      if (!scan) throw new Error(`Scan ${scanId} not found`);
      
      await storage.updateScan(scanId, {
        currentAgent: agentType,
        status: "running",
        agentResults: {
          ...scan.agentResults,
          [agentType]: {
            agentType,
            status: "running",
            startedAt: new Date().toISOString(),
            data: {},
          },
        },
      });

      const onProgress = async (progress: number) => {
        const totalProgress = getAgentProgress(i, progress);
        await storage.updateScan(scanId, { progress: totalProgress });
      };

      let result: ReconFindings | ScannerFindings | ExploiterFindings | ReporterOutput;

      try {
        switch (agentType) {
          case "recon":
            const scanUserId = scan.userId;
            const userCredits = await storage.getUserCredits(scanUserId);
            reconData = await runReconAgent(scan.target, onProgress, {
              userId: scanUserId,
              planLevel: context?.planLevel || userCredits.planLevel,
            });
            result = reconData;
            break;
          
          case "scanner":
            if (!reconData) throw new Error("Recon data required for scanner");
            scannerData = await runScannerAgent(scan.target, reconData, {
              userId: scan.userId,
              scanId: scanId,
              onProgress,
            });
            result = scannerData;
            break;
          
          case "exploiter":
            if (!scannerData) throw new Error("Scanner data required for exploiter");
            exploiterData = await runExploiterAgent(scan.target, scannerData, onProgress);
            result = exploiterData;
            break;
          
          case "reporter":
            if (!reconData || !scannerData || !exploiterData) {
              throw new Error("All previous agent data required for reporter");
            }
            const reporterResult = await runReporterAgent(
              scan.target, 
              reconData, 
              scannerData, 
              exploiterData, 
              onProgress,
              {
                userId: scan.userId,
                scanId: scanId,
                planLevel: context?.planLevel,
                onProgress,
              }
            );
            result = reporterResult;
            
            if ('planLevel' in reporterResult && (reporterResult.planLevel === "ELITE" || reporterResult.planLevel === "STANDARD")) {
              try {
                const reportFormats = await generateAllReportFormats(
                  scanId,
                  reporterResult as EnhancedReporterOutput,
                  scan.target,
                  scannerData as unknown as Record<string, unknown>,
                  exploiterData as unknown as Record<string, unknown>
                );
                
                if (reportFormats.executivePdf) {
                  (result as EnhancedReporterOutput).executivePdfPath = reportFormats.executivePdf;
                }
                if (reportFormats.technicalPdf) {
                  (result as EnhancedReporterOutput).technicalPdfPath = reportFormats.technicalPdf;
                }
                if (reportFormats.jsonExport) {
                  (result as EnhancedReporterOutput).rawDataExportPath = reportFormats.jsonExport;
                }
                if (reportFormats.csvExport) {
                  (result as EnhancedReporterOutput).csvExportPath = reportFormats.csvExport;
                }
              } catch (pdfError) {
                console.log("[PIPELINE] PDF generation failed, continuing without PDFs:", pdfError);
              }
            }
            break;
          
          default:
            throw new Error(`Unknown agent type: ${agentType}`);
        }

        // Fetch latest scan state before updating to preserve all agent results
        const currentScan = await storage.getScan(scanId);
        if (!currentScan) throw new Error(`Scan ${scanId} not found`);
        
        await storage.updateScan(scanId, {
          agentResults: {
            ...currentScan.agentResults,
            [agentType]: {
              agentType,
              status: "complete",
              startedAt: currentScan.agentResults?.[agentType]?.startedAt,
              completedAt: new Date().toISOString(),
              data: result,
            },
          },
        });
        
      } catch (agentError) {
        // Mark specific agent as failed but continue to mark overall scan as failed
        const errorMessage = agentError instanceof Error ? agentError.message : "Unknown error";
        const currentScan = await storage.getScan(scanId);
        
        if (currentScan) {
          await storage.updateScan(scanId, {
            agentResults: {
              ...currentScan.agentResults,
              [agentType]: {
                agentType,
                status: "failed",
                startedAt: currentScan.agentResults?.[agentType]?.startedAt,
                completedAt: new Date().toISOString(),
                error: errorMessage,
                data: {},
              },
            },
          });
        }
        
        throw agentError;
      }
    }

    // Fetch final state and mark complete
    const finalScan = await storage.getScan(scanId);
    await storage.updateScan(scanId, {
      status: "complete",
      currentAgent: null,
      progress: 100,
      completedAt: new Date().toISOString(),
      agentResults: finalScan?.agentResults,
    });

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error occurred";
    
    // Preserve agent results when marking scan as failed
    const failedScan = await storage.getScan(scanId);
    await storage.updateScan(scanId, {
      status: "failed",
      error: errorMessage,
      completedAt: new Date().toISOString(),
      agentResults: failedScan?.agentResults,
    });
    
    throw error;
  }
}
