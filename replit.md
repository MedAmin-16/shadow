# ShadowTwin

## Overview

ShadowTwin is an AI-powered Cybersecurity Digital Twin SaaS platform. It creates complete digital replicas of company assets (web applications, APIs, cloud infrastructure, network services) and runs autonomous AI-driven security simulations to discover vulnerabilities before attackers do.

The platform features a multi-agent scanning pipeline that performs reconnaissance, vulnerability scanning, exploitation testing, and report generation. The frontend provides a dashboard for managing projects, monitoring scans, viewing vulnerabilities, and generating compliance reports.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React with TypeScript using Vite as the build tool
- **Routing**: Wouter for client-side routing (lightweight alternative to React Router)
- **State Management**: TanStack React Query for server state and caching
- **UI Components**: shadcn/ui component library built on Radix UI primitives
- **Styling**: Tailwind CSS with CSS custom properties for theming (light/dark mode support)
- **Design System**: Following Linear/Vercel aesthetic with Inter font for UI and JetBrains Mono for code

### Backend Architecture
- **Runtime**: Node.js with Express and TypeScript
- **API Pattern**: RESTful API endpoints under `/api/*` prefix
- **Build System**: esbuild for server bundling, Vite for client bundling
- **Development**: tsx for TypeScript execution in development
- **Rate Limiting**: express-rate-limit on all scan endpoints (100 req/15min)
- **Authentication**: API key-based auth via x-api-key header
- **Job Queue**: BullMQ with Redis (optional - falls back to synchronous processing)
- **Real-time**: Socket.io for scan completion notifications
- **Email**: Nodemailer for scan completion emails (requires SMTP config)
- **Reports**: PDFKit for generating downloadable PDF reports

### Multi-Agent Scanning Pipeline
The core security scanning system uses a sequential agent architecture:
1. **Recon Agent**: Strategic Planning Engine with credit-based gating and tiered LLM access
2. **Scanner Agent**: Identifies vulnerabilities based on recon findings with PoC and remediation code
3. **Exploiter Agent**: Attempts safe exploitation to validate vulnerabilities
4. **Reporter Agent (ELITE)**: Strategic Intelligence Engine with financial risk quantification

Each agent runs asynchronously and updates scan progress in real-time.

### Reporter Agent (Agent 4) - ELITE Tier Features
The Reporter Agent implements tiered pricing with ELITE tier using GPT-5.1:

| Plan Level | LLM Model   | Base Cost  | Financial Analysis | PDF Generation |
|------------|-------------|------------|-------------------|----------------|
| BASIC      | gpt-4o-mini | 25 credits | No                | No             |
| STANDARD   | gpt-4o      | 100 credits| No                | Executive PDF  |
| ELITE      | gpt-5.1     | 500 credits| Yes               | Both PDFs      |

ELITE Tier Capabilities:
- **Financial Risk Quantifier**: Estimated Loss Range (e.g., "$50K - $150K") per vulnerability
- **Audience-Specific Summaries**: Executive, CFO, CTO, Development, Compliance views
- **Industry Benchmarking**: Security posture vs industry standards and top performers
- **Evidence Integration**: Exploitation artifacts and remediation code snippets
- **Liability Log**: Security Status History with scan dates and remediation tracking
- **Board-Level Executive Summary**: Single-page branded summary for executives

Output Formats:
- **Executive PDF**: Branded, high-level decision document
- **Technical PDF**: Full detail with PoC code and remediation instructions  
- **Raw Data Export**: JSON and CSV for security systems integration

### Credit-Based Gating System (Recon Agent)
The Recon Agent implements a tiered pricing model based on PLAN_LEVEL:

| Plan Level | LLM Model     | Base Cost | OSINT Access | OSINT Query Cost |
|------------|---------------|-----------|--------------|------------------|
| BASIC      | gpt-4o-mini   | 5 credits | Limited      | 1 credit         |
| STANDARD   | gpt-4o        | 15 credits| Standard     | 2 credits        |
| ELITE      | gpt-5         | 50 credits| Full         | 5 credits        |

Key features:
- Credits are deducted BEFORE LLM execution (fail-fast for insufficient credits)
- Output payload includes `credit_deduction_recon`, `strategic_decision_log`, and `llm_model_used`
- Graceful fallback when OpenAI API key is not configured
- User plan level and credits stored per-user in storage

### Data Layer
- **ORM**: Drizzle ORM with PostgreSQL dialect
- **Schema**: Defined in `shared/schema.ts` with Zod validation via drizzle-zod
- **Storage Abstraction**: Interface-based storage pattern allowing swappable implementations (currently in-memory with database schema ready)

### Project Structure
```
client/           # React frontend application
  src/
    components/   # Reusable UI components
    pages/        # Route page components
    hooks/        # Custom React hooks
    lib/          # Utilities and query client
server/           # Express backend
  agents/         # Security scanning agent implementations
  src/
    controllers/  # Request handlers for API endpoints
    middlewares/  # Rate limiting, API key auth
    queues/       # BullMQ job queue setup
    workers/      # Background job processors
    services/     # Email, PDF report generation
    sockets/      # Socket.io real-time notifications
    utils/        # Logger and utilities
    types/        # TypeScript type definitions
shared/           # Shared types and database schema
reports/          # Generated PDF reports (auto-created)
```

### Environment Variables
```
# Required
DATABASE_URL      # PostgreSQL connection string

# Optional - AI/LLM Features
OPENAI_API_KEY    # OpenAI API key for AI-powered reconnaissance

# Optional - Job Queue (enables background processing)
REDIS_URL         # Redis connection URL for BullMQ
# OR
REDIS_HOST        # Redis host
REDIS_PORT        # Redis port (default: 6379)

# Optional - Email Notifications
SMTP_HOST         # SMTP server hostname
SMTP_PORT         # SMTP port (default: 587)
SMTP_USER         # SMTP username
SMTP_PASS         # SMTP password
SMTP_FROM         # From email address
```

### Key Design Decisions
- **Monorepo structure**: Single repository with shared types between frontend and backend
- **Type safety**: Full TypeScript coverage with shared schema definitions
- **Component architecture**: Presentational components with example files for documentation
- **Path aliases**: `@/` for client source, `@shared/` for shared code

## External Dependencies

### Database
- **PostgreSQL**: Primary database (configured via `DATABASE_URL` environment variable)
- **Drizzle Kit**: Database migrations and schema management (`npm run db:push`)

### UI Framework
- **Radix UI**: Headless component primitives (dialog, dropdown, tabs, etc.)
- **shadcn/ui**: Pre-styled components using Radix primitives
- **Lucide React**: Icon library

### Build & Development
- **Vite**: Frontend development server and build tool
- **esbuild**: Server-side bundling for production
- **Replit plugins**: Development banner and error overlay for Replit environment

### Data Fetching
- **TanStack Query**: Async state management and caching for API calls

### Fonts (Google Fonts)
- Inter: Primary UI font
- JetBrains Mono: Monospace for code/technical content
- DM Sans, Fira Code, Geist Mono: Additional typography options