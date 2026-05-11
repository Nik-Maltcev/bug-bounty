import { useParams, Link } from 'react-router-dom';
import { useChat } from '../hooks/useChat';
import ChatPanel from '../components/Chat/ChatPanel';
import { ArrowLeft, Bot } from 'lucide-react';

export default function ChatPage() {
  const { id } = useParams<{ id: string }>();
  const programId = id || '';
  const { messages, loading, error, sendMessage, clearHistory } = useChat(programId);

  if (!programId) {
    return (
      <div className="flex items-center justify-center h-full text-slate-400">
        Программа не выбрана.
      </div>
    );
  }

  return (
    <div className="flex flex-col h-[calc(100vh-4rem)]">
      <div className="flex items-center justify-between mb-4 shrink-0">
        <div className="flex items-center">
          <div className="w-10 h-10 rounded-xl bg-blue-500/10 flex items-center justify-center mr-4">
            <Bot className="w-6 h-6 text-blue-500" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-100">ИИ-Ассистент</h1>
            <p className="text-slate-400 text-sm">Управление сканированием и анализ уязвимостей</p>
          </div>
        </div>
        <Link 
          to={`/app/programs/${programId}`}
          className="flex items-center px-4 py-2 text-sm font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          К программе
        </Link>
      </div>
      
      <div className="flex-1 bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl shadow-xl overflow-hidden relative">
        <ChatPanel
          messages={messages}
          loading={loading}
          error={error}
          onSend={sendMessage}
          onClear={clearHistory}
        />
      </div>
    </div>
  );
}
