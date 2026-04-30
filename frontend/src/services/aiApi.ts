import api from './api';
import type { ChatMessage, ChatRequest, ChatResponse, FindingAnalysis, LLMSettings } from '../types/ai';

export async function sendChatMessage(request: ChatRequest): Promise<ChatResponse> {
  const res = await api.post<ChatResponse>('/api/ai/chat', request);
  return res.data;
}

export async function getChatHistory(programId: string): Promise<ChatMessage[]> {
  const res = await api.get<ChatMessage[]>(`/api/ai/chat/${programId}/history`);
  return res.data;
}

export async function clearChatHistory(programId: string): Promise<void> {
  await api.delete(`/api/ai/chat/${programId}/history`);
}

export async function getLLMSettings(): Promise<LLMSettings> {
  const res = await api.get<LLMSettings>('/api/ai/settings');
  return res.data;
}

export async function updateLLMSettings(settings: Partial<LLMSettings>): Promise<void> {
  await api.put('/api/ai/settings', settings);
}

export async function testLLMConnection(): Promise<{ connected: boolean; error?: string }> {
  const res = await api.post<{ connected: boolean; error?: string }>('/api/ai/settings/test');
  return res.data;
}

export async function analyzeFinding(findingId: string): Promise<FindingAnalysis> {
  const res = await api.post<FindingAnalysis>(`/api/ai/analyze/finding/${findingId}`);
  return res.data;
}

export async function analyzeRules(programId: string, question: string): Promise<{ answer: string }> {
  const res = await api.post<{ answer: string }>('/api/ai/analyze/rules', { program_id: programId, question });
  return res.data;
}

export async function generateAIReport(vulnId: string): Promise<Record<string, unknown>> {
  const res = await api.post<Record<string, unknown>>(`/api/ai/report/${vulnId}`);
  return res.data;
}

export async function improveReport(reportId: string, instruction: string): Promise<Record<string, unknown>> {
  const res = await api.post<Record<string, unknown>>(`/api/ai/report/${reportId}/improve`, { instruction });
  return res.data;
}

export async function getRecommendations(programId: string): Promise<{ recommendations: string }> {
  const res = await api.post<{ recommendations: string }>(`/api/ai/recommendations/${programId}`);
  return res.data;
}
