import { useState, useCallback, useEffect } from 'react';
import type { ChatMessage, ChatResponse } from '../types/ai';
import { sendChatMessage, getChatHistory, clearChatHistory } from '../services/aiApi';

export function useChat(programId: string) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadHistory = useCallback(async () => {
    try {
      const history = await getChatHistory(programId);
      setMessages(history);
    } catch (e) {
      setError('Failed to load chat history');
    }
  }, [programId]);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const sendMessage = useCallback(async (content: string) => {
    setLoading(true);
    setError(null);

    const userMsg: ChatMessage = {
      id: `temp-${Date.now()}`,
      role: 'user',
      content,
      metadata: {},
      created_at: new Date().toISOString(),
    };
    setMessages(prev => [...prev, userMsg]);

    try {
      const response: ChatResponse = await sendChatMessage({
        program_id: programId,
        message: content,
      });

      const assistantMsg: ChatMessage = {
        id: `resp-${Date.now()}`,
        role: 'assistant',
        content: response.message,
        intent: response.intent,
        metadata: response.metadata,
        created_at: new Date().toISOString(),
      };
      setMessages(prev => [...prev, assistantMsg]);
    } catch (e: unknown) {
      const errMsg = e instanceof Error ? e.message : 'Failed to send message';
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  }, [programId]);

  const clearHistory = useCallback(async () => {
    try {
      await clearChatHistory(programId);
      setMessages([]);
    } catch {
      setError('Failed to clear history');
    }
  }, [programId]);

  return { messages, loading, error, sendMessage, clearHistory, loadHistory };
}
