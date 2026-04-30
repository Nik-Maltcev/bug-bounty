import { useRef, useEffect } from 'react';
import type { ChatMessage as ChatMessageType } from '../../types/ai';
import ChatMessage from './ChatMessage';
import ChatInput from './ChatInput';
import TypingIndicator from './TypingIndicator';
import { Trash2 } from 'lucide-react';

interface Props {
  messages: ChatMessageType[];
  loading: boolean;
  error: string | null;
  onSend: (message: string) => void;
  onClear: () => void;
}

export default function ChatPanel({ messages, loading, error, onSend, onClear }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  return (
    <div className="flex flex-col h-full bg-slate-900/50">
      <div className="flex justify-between items-center px-6 py-4 border-b border-slate-800 bg-slate-900/80">
        <div className="flex items-center gap-2 text-sm text-slate-400">
          <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
          Модель DeepSeek V4 готова
        </div>
        <button 
          onClick={onClear} 
          className="flex items-center px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
          title="Очистить историю"
        >
          <Trash2 className="w-4 h-4 mr-1.5" />
          Очистить
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-6 scrollbar-thin scrollbar-thumb-slate-800">
        {messages.length === 0 && !loading && (
          <div className="flex flex-col items-center justify-center h-full text-slate-500 space-y-4">
            <div className="w-16 h-16 rounded-2xl bg-slate-800 flex items-center justify-center text-slate-400">
              🤖
            </div>
            <p>Начните диалог с ИИ-агентом</p>
          </div>
        )}
        
        {messages.map((msg) => (
          <ChatMessage key={msg.id} role={msg.role} content={msg.content} intent={msg.intent} />
        ))}
        
        {loading && <TypingIndicator />}
        
        {error && (
          <div className="p-3 text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg text-center max-w-lg mx-auto">
            {error}
          </div>
        )}
        <div ref={bottomRef} className="h-4" />
      </div>

      <div className="p-4 bg-slate-900/80 border-t border-slate-800">
        <ChatInput onSend={onSend} disabled={loading} />
      </div>
    </div>
  );
}
