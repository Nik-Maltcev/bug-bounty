/* TypeScript types matching backend Pydantic models */

export enum AssetType {
  WEB_APPLICATION = 'web_application',
}

export enum SeverityLevel {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFORMATIONAL = 'informational',
}

export enum ActionResult {
  ALLOWED = 'allowed',
  BLOCKED = 'blocked',
}

export enum ScanStatus {
  PENDING = 'pending',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
}

export interface Asset {
  id: string;
  name: string;
  asset_type: AssetType;
  target: string;
  in_scope: boolean;
  notes: string;
}

export interface ProgramRule {
  id: string;
  description: string;
  is_allowed: boolean;
  category: string;
}

export interface RewardTier {
  id?: string;
  severity: SeverityLevel;
  min_reward: number;
  max_reward: number;
  currency: string;
}

export interface ParsedProgram {
  id: string;
  name: string;
  platform: string;
  assets: Asset[];
  rules: ProgramRule[];
  reward_tiers: RewardTier[];
  disclosure_requirements: string;
  raw_text: string;
  created_at: string;
  is_archived: boolean;
}

export interface ScanProgress {
  scan_id: string;
  status: ScanStatus | string;
  current_stage: string;
  percent_complete: number;
  findings_count: number;
}

export interface ScanRecord {
  id: string;
  program_id: string;
  asset_id: string;
  status: string;
  current_stage: string;
  percent_complete: number;
  started_at: string | null;
  completed_at: string | null;
  findings_count: number;
  target_url?: string;
  target_name?: string;
}

export interface Vulnerability {
  id: string;
  scan_id: string;
  program_id: string;
  vulnerability_type: string;
  severity: string;
  description: string;
  steps_to_reproduce: string;
  evidence: string;
  impact_assessment: string;
  remediation: string;
  status: string;
  created_at: string | null;
}

export interface Report {
  id: string;
  vulnerability_id: string;
  program_id: string;
  title: string;
  description: string;
  steps_to_reproduce: string;
  proof_of_concept: string;
  impact: string;
  severity: string;
  remediation: string;
  created_at: string | null;
  updated_at: string | null;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  action_type: string;
  target_asset: string;
  result: string;
  program_id: string;
  rule_reference: string;
  details: string;
}

export interface ComplianceSummary {
  program_id: string;
  total_actions: number;
  allowed_actions: number;
  blocked_actions: number;
  blocked_reasons: Array<{ reason: string; count: number }>;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
}

export interface ApiError {
  error: string;
  detail: string;
  [key: string]: unknown;
}
