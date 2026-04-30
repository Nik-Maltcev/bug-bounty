import { Bot } from 'lucide-react';

export default function TypingIndicator() {
  return (
    <div className="flex items-start gap-3 animate-fade-in" aria-label="ИИ думает">
      <div className="shrink-0 w-8 h-8 rounded-lg flex items-center justify-center mt-1 border bg-slate-800 text-emerald-400 border-slate-700">
        <Bot className="w-5 h-5" />
      </div>
      <div className="bg-slate-800/80 text-slate-400 border border-slate-700/50 rounded-2xl rounded-tl-sm px-4 py-3 flex items-center gap-1.5 shadow-sm">
        <div className="w-1.5 h-1.5 rounded-full bg-slate-500 animate-bounce [animation-delay:-0.3s]" />
        <div className="w-1.5 h-1.5 rounded-full bg-slate-500 animate-bounce [animation-delay:-0.15s]" />
        <div className="w-1.5 h-1.5 rounded-full bg-slate-500 animate-bounce" />
      </div>
    </div>
  );
}
