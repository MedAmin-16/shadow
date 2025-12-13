import { useState } from "react";
import { Button } from "@/components/ui/button";
import { SecurityScoreCard } from "@/components/SecurityScoreCard";
import { TwinStatusWidget } from "@/components/TwinStatusWidget";
import { ActiveScansList } from "@/components/ActiveScansList";
import { RecentVulnerabilities } from "@/components/RecentVulnerabilities";
import { ProjectCard } from "@/components/ProjectCard";
import { ActivityLog } from "@/components/ActivityLog";
import { CreateProjectDialog } from "@/components/CreateProjectDialog";
import { Plus, Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import type { Project, Activity, Scan } from "@shared/schema";

interface DashboardMetrics {
  securityScore: number;
  totalProjects: number;
  activeScans: number;
  completedScans: number;
  totalScans: number;
  totalVulnerabilities: number;
  totalReports: number;
}

interface Vulnerability {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  project: string;
  date: string;
}

function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);
  
  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? "s" : ""} ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? "s" : ""} ago`;
  return `${diffDays} day${diffDays > 1 ? "s" : ""} ago`;
}

export default function DashboardPage() {
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  const { data: metrics } = useQuery<DashboardMetrics>({
    queryKey: ["/api/dashboard/metrics"],
    refetchInterval: 5000,
  });

  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["/api/projects"],
  });

  const { data: scans = [] } = useQuery<Scan[]>({
    queryKey: ["/api/scans"],
    refetchInterval: 2000,
  });

  const { data: activities = [] } = useQuery<Activity[]>({
    queryKey: ["/api/activity"],
    refetchInterval: 5000,
  });

  const { data: vulnerabilities = [] } = useQuery<Vulnerability[]>({
    queryKey: ["/api/dashboard/vulnerabilities"],
  });

  const createProjectMutation = useMutation({
    mutationFn: async (data: { name: string }) => {
      const response = await apiRequest("POST", "/api/projects", data);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/projects"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/metrics"] });
      queryClient.invalidateQueries({ queryKey: ["/api/activity"] });
      setCreateDialogOpen(false);
    },
  });

  const displayProjects = projects.slice(0, 3);

  const displayScans = scans.slice(0, 5).map((scan) => ({
    id: scan.id,
    projectName: scan.target,
    status: scan.status === "running" ? "running" as const : 
            scan.status === "pending" ? "pending" as const : 
            scan.status === "complete" ? "complete" as const : "complete" as const,
    progress: scan.progress,
  }));

  const displayActivities = activities.map((a) => ({
    id: a.id,
    type: a.type,
    message: a.message,
    timestamp: formatTimestamp(a.timestamp),
  }));

  const displayVulnerabilities = vulnerabilities.map((v) => ({
    id: v.id,
    title: v.title,
    severity: v.severity,
    affectedAsset: v.project,
    cveId: undefined,
  }));

  return (
    <div className="p-6 space-y-6" data-testid="page-dashboard">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Dashboard</h1>
          <p className="text-muted-foreground">Monitor your security posture across all projects</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search projects..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 w-64"
              data-testid="input-search"
            />
          </div>
          <Button onClick={() => setCreateDialogOpen(true)} data-testid="button-new-project">
            <Plus className="h-4 w-4 mr-2" />
            New Project
          </Button>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <SecurityScoreCard 
          score={metrics?.securityScore || 0} 
          trend="up" 
          trendValue={5} 
          lastScan={displayProjects[0]?.lastScanDate || "Never"} 
        />
        <TwinStatusWidget
          projectName={displayProjects[0]?.name || "No Projects"}
          status={displayScans.some(s => s.status === "running") ? "active" : "pending"}
          lastScanTime={displayProjects[0]?.lastScanDate || "Never"}
          assetsCount={displayProjects[0]?.assetCount || 0}
        />
        <div className="md:col-span-2">
          <ActiveScansList scans={displayScans} />
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <RecentVulnerabilities
            vulnerabilities={displayVulnerabilities}
            onViewAll={() => console.log("View all vulnerabilities")}
          />
        </div>
        <ActivityLog activities={displayActivities} />
      </div>

      <div>
        <div className="flex items-center justify-between gap-4 mb-4">
          <h2 className="text-lg font-semibold">Your Projects</h2>
          <button
            className="text-sm text-primary hover:underline"
            onClick={() => console.log("View all projects")}
            data-testid="link-view-all-projects"
          >
            View all
          </button>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {displayProjects.map((project) => (
            <ProjectCard
              key={project.id}
              {...project}
              onClick={() => console.log("Project clicked:", project.id)}
            />
          ))}
        </div>
      </div>

      <CreateProjectDialog
        open={createDialogOpen}
        onOpenChange={setCreateDialogOpen}
        onSubmit={(data) => createProjectMutation.mutate(data)}
      />
    </div>
  );
}
