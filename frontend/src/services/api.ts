import axios, { AxiosError, type InternalAxiosRequestConfig } from 'axios';
import type {
  AuditEntry,
  ComplianceSummary,
  LoginRequest,
  LoginResponse,
  ParsedProgram,
  Report,
  ScanProgress,
  ScanRecord,
  Vulnerability,
  Asset,
} from '../types';

const API_URL = import.meta.env.VITE_API_URL || '';

const api = axios.create({
  baseURL: API_URL,
  headers: { 'Content-Type': 'application/json' },
});

// --- Auth token management ---

const TOKEN_KEY = 'bb_access_token';

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export function isAuthenticated(): boolean {
  return !!getToken();
}

// Request interceptor — attach JWT
api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = getToken();
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor — handle 401/403/423
api.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response) {
      const { status } = error.response;
      if (status === 401) {
        clearToken();
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  },
);

// --- Auth API ---

export async function login(data: LoginRequest): Promise<LoginResponse> {
  const res = await api.post<LoginResponse>('/api/auth/login', data);
  setToken(res.data.access_token);
  return res.data;
}

export async function logout(): Promise<void> {
  await api.post('/api/auth/logout').catch(() => {});
  clearToken();
}

// --- Programs API ---

export async function listPrograms(archived?: boolean): Promise<ParsedProgram[]> {
  const params = archived !== undefined ? { archived } : {};
  const res = await api.get<ParsedProgram[]>('/api/programs', { params });
  return res.data;
}

export async function getProgram(id: string): Promise<ParsedProgram> {
  const res = await api.get<ParsedProgram>(`/api/programs/${id}`);
  return res.data;
}

export async function importProgram(source: { url?: string; text?: string }): Promise<ParsedProgram> {
  const res = await api.post<ParsedProgram>('/api/programs', source);
  return res.data;
}

export async function archiveProgram(id: string): Promise<ParsedProgram> {
  const res = await api.patch<ParsedProgram>(`/api/programs/${id}/archive`);
  return res.data;
}

// --- Assets API ---

export async function listProgramAssets(programId: string): Promise<Asset[]> {
  const res = await api.get<Asset[]>(`/api/programs/${programId}/assets`);
  return res.data;
}

// --- Scans API ---

export async function quickScan(targetUrl: string, scanType: string = 'web'): Promise<ScanProgress & { target_url: string }> {
  const res = await api.post<ScanProgress & { target_url: string }>('/api/scans/quick', {
    target_url: targetUrl,
    scan_type: scanType,
  });
  return res.data;
}

export async function listScans(limit: number = 50, offset: number = 0): Promise<ScanRecord[]> {
  const res = await api.get<ScanRecord[]>('/api/scans', { params: { limit, offset } });
  return res.data;
}

export async function startScan(programId: string, assetId: string, checkTypes: string[] = []): Promise<ScanProgress> {
  const res = await api.post<ScanProgress>(`/api/programs/${programId}/scans`, {
    asset_id: assetId,
    check_types: checkTypes,
  });
  return res.data;
}

export async function getScan(scanId: string): Promise<ScanRecord> {
  const res = await api.get<ScanRecord>(`/api/scans/${scanId}`);
  return res.data;
}

export async function getScanProgress(scanId: string): Promise<ScanProgress> {
  const res = await api.get<ScanProgress>(`/api/scans/${scanId}/progress`);
  return res.data;
}

export async function getScanVulnerabilities(scanId: string): Promise<Vulnerability[]> {
  const res = await api.get<Vulnerability[]>('/api/vulnerabilities', { params: { scan_id: scanId } });
  return res.data;
}

export async function startAIScan(scanId: string): Promise<{ status: string; message: string }> {
  const res = await api.post<{ status: string; message: string }>(`/api/scans/${scanId}/ai-analyze`);
  return res.data;
}

// --- Vulnerabilities API ---

export async function listVulnerabilities(filters?: {
  severity?: string;
  asset_type?: string;
  status?: string;
}): Promise<Vulnerability[]> {
  const res = await api.get<Vulnerability[]>('/api/vulnerabilities', { params: filters });
  return res.data;
}

export async function getVulnerability(id: string): Promise<Vulnerability> {
  const res = await api.get<Vulnerability>(`/api/vulnerabilities/${id}`);
  return res.data;
}

// --- Reports API ---

export async function generateReport(vulnId: string): Promise<Report> {
  // Try AI report first, fallback to template
  try {
    const res = await api.post<Report>(`/api/ai/report/${vulnId}`);
    return res.data;
  } catch {
    const res = await api.post<Report>(`/api/vulnerabilities/${vulnId}/report`);
    return res.data;
  }
}

export async function getReport(id: string): Promise<Report> {
  const res = await api.get<Report>(`/api/reports/${id}`);
  return res.data;
}

export async function exportReport(id: string, format: 'md' | 'pdf' = 'md'): Promise<string | Blob> {
  if (format === 'pdf') {
    const res = await api.get(`/api/reports/${id}/export`, {
      params: { format: 'pdf' },
      responseType: 'blob',
    });
    return res.data as Blob;
  }
  const res = await api.get<string>(`/api/reports/${id}/export`, { params: { format: 'md' } });
  return res.data;
}

// --- Compliance API ---

export async function getComplianceSummary(programId: string): Promise<ComplianceSummary> {
  const res = await api.get<ComplianceSummary>(`/api/compliance/${programId}`);
  return res.data;
}

// --- Audit API ---

export async function listAuditLog(filters?: {
  start_date?: string;
  end_date?: string;
  action_type?: string;
  program_id?: string;
  result?: string;
}): Promise<AuditEntry[]> {
  const res = await api.get<AuditEntry[]>('/api/audit', { params: filters });
  return res.data;
}

export async function exportAuditLog(filters?: {
  start_date?: string;
  end_date?: string;
  action_type?: string;
  program_id?: string;
  result?: string;
}): Promise<string> {
  const res = await api.get<string>('/api/audit/export', { params: filters });
  return typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
}

export default api;
