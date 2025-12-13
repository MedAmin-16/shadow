import { Server as SocketServer, Socket } from "socket.io";
import type { Server as HttpServer } from "http";
import type { NotificationPayload } from "../types";
import type { ScannerDecisionLog, ExploitApprovalRequest } from "@shared/schema";
import { createLogger } from "../utils/logger";

const logger = createLogger("socket");

let io: SocketServer | null = null;
const userSockets = new Map<string, Set<string>>();

export function initSocketServer(httpServer: HttpServer): SocketServer {
  io = new SocketServer(httpServer, {
    cors: {
      origin: "*",
      methods: ["GET", "POST"],
    },
    path: "/socket.io",
  });

  io.on("connection", (socket: Socket) => {
    logger.info(`Client connected: ${socket.id}`);

    socket.on("authenticate", (userId: string) => {
      if (!userId) return;

      if (!userSockets.has(userId)) {
        userSockets.set(userId, new Set());
      }
      userSockets.get(userId)!.add(socket.id);
      socket.join(`user:${userId}`);
      logger.info(`User ${userId} authenticated on socket ${socket.id}`);
    });

    socket.on("subscribe:scan", (jobId: string) => {
      socket.join(`scan:${jobId}`);
      logger.debug(`Socket ${socket.id} subscribed to scan ${jobId}`);
    });

    socket.on("unsubscribe:scan", (jobId: string) => {
      socket.leave(`scan:${jobId}`);
    });

    socket.on("disconnect", () => {
      logger.info(`Client disconnected: ${socket.id}`);
      const entries = Array.from(userSockets.entries());
      for (const [userId, sockets] of entries) {
        if (sockets.has(socket.id)) {
          sockets.delete(socket.id);
          if (sockets.size === 0) {
            userSockets.delete(userId);
          }
          break;
        }
      }
    });
  });

  logger.info("Socket.io server initialized");
  return io;
}

export function getSocketServer(): SocketServer | null {
  return io;
}

export function emitScanCompleted(payload: NotificationPayload): void {
  if (!io) {
    logger.warn("Socket server not initialized");
    return;
  }

  io.to(`scan:${payload.jobId}`).emit("scanCompleted", {
    jobId: payload.jobId,
    status: payload.status,
    result: payload.result,
    error: payload.error,
  });

  io.to(`user:${payload.userId}`).emit("scanCompleted", {
    jobId: payload.jobId,
    target: payload.target,
    status: payload.status,
    result: payload.result,
    error: payload.error,
  });

  logger.info(`Emitted scanCompleted for job ${payload.jobId}`);
}

export function emitScanProgress(jobId: string, progress: number): void {
  if (!io) return;

  io.to(`scan:${jobId}`).emit("scanProgress", {
    jobId,
    progress,
  });
}

export function emitToUser(userId: string, event: string, data: unknown): void {
  if (!io) return;

  io.to(`user:${userId}`).emit(event, data);
}

export function emitScannerDecision(scanId: string, decision: ScannerDecisionLog): void {
  if (!io) return;

  io.to(`scan:${scanId}`).emit("scanner:decision", {
    scanId,
    decision,
  });

  logger.debug(`Emitted scanner decision for scan ${scanId}: ${decision.decisionType}`);
}

export function emitScannerFinancialDecision(scanId: string, decision: ScannerDecisionLog): void {
  if (!io) return;

  io.to(`scan:${scanId}`).emit("scanner:financial_decision", {
    scanId,
    decision,
  });
}

export function emitScannerSecurityDecision(scanId: string, decision: ScannerDecisionLog): void {
  if (!io) return;

  io.to(`scan:${scanId}`).emit("scanner:security_decision", {
    scanId,
    decision,
  });
}

export function emitScannerReplanning(scanId: string, decision: ScannerDecisionLog): void {
  if (!io) return;

  io.to(`scan:${scanId}`).emit("scanner:replanning", {
    scanId,
    decision,
  });
}

export function emitApprovalRequired(userId: string, scanId: string, approval: ExploitApprovalRequest): void {
  if (!io) return;

  io.to(`user:${userId}`).emit("scanner:approval_required", {
    scanId,
    approval,
  });

  io.to(`scan:${scanId}`).emit("scanner:approval_required", {
    scanId,
    approval,
  });

  logger.info(`Emitted approval required for scan ${scanId}, vulnerability ${approval.vulnerabilityId}`);
}
