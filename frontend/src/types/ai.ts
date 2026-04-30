/* TypeScript types for AI module */

export enum ProviderType {
  DEEPSEEK = 'deepseek',
  OPENAI = 'openai',
  ANTHROPIC = 'anthropic',
  OLLAMA = 'ollama',
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  intent?: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface ChatRequest {
  program_id: string;
  message: string;
}

export interface ChatResponse {
  message: string;
  intent: string;
  metadata: Record<string, unknown>;
}

export interface LLMSettings {
  provider: ProviderType | string;
  base_url: string;
  model: string;
  api_key?: string;
  max_tokens: number;
  temperature: number;
  is_connected: boolean;
}

export interface FindingAnalysis {
  is_real_vulnerability: boolean;
  confidence: number;
  severity: string;
  exploitability: string;
  reasoning: string;
}
