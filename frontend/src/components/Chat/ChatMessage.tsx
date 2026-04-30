import clsx from 'clsx';
import { Bot, User } from 'lucide-react';

interface Props {
  role: 'user' | 'assistant';
  content: string;
  intent?: string;
}

function simpleMarkdown(text: string): string {
  let html = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  // Code blocks
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre class="bg-slate-900 border border-slate-700 p-3 rounded-lg overflow-x-auto my-2 text-sm font-mono text-slate-300"><code>$2</code></pre>');
  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code class="bg-slate-800/50 text-blue-300 px-1.5 py-0.5 rounded text-sm font-mono border border-slate-700/50">$1</code>');
  // Bold
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong class="font-bold text-white">$1</strong>');
  // Italic
  html = html.replace(/\*(.+?)\*/g, '<em class="italic">$1</em>');
  // Line breaks
  html = html.replace(/\n/g, '<br/>');
  return html;
}

export default function ChatMessage({ role, content, intent }: Props) {
  const isUser = role === 'user';
  
  return (
    <div className={clsx("flex w-full animate-fade-in", isUser ? "justify-end" : "justify-start")}>
      <div className={clsx("flex max-w-[80%] gap-3", isUser ? "flex-row-reverse" : "flex-row")}>
        
        {/* Avatar */}
        <div className={clsx(
          "shrink-0 w-8 h-8 rounded-lg flex items-center justify-center mt-1 border",
          isUser 
            ? "bg-blue-600/20 text-blue-400 border-blue-500/30" 
            : "bg-slate-800 text-emerald-400 border-slate-700"
        )}>
          {isUser ? <User className="w-5 h-5" /> : <Bot className="w-5 h-5" />}
        </div>
        
        {/* Message Bubble */}
        <div className="flex flex-col gap-1">
          <div className={clsx(
            "px-4 py-3 rounded-2xl",
            isUser 
              ? "bg-blue-600 text-white rounded-tr-sm" 
              : "bg-slate-800/80 text-slate-200 border border-slate-700/50 rounded-tl-sm shadow-sm"
          )}>
            <div 
              className="prose prose-invert prose-p:leading-relaxed prose-pre:my-0 max-w-none break-words text-sm"
              dangerouslySetInnerHTML={{ __html: simpleMarkdown(content) }} 
            />
          </div>
          
          {/* Intent Tag (AI only) */}
          {intent && !isUser && (
            <div className="flex items-center mt-1 ml-1">
              <span className="text-[10px] font-medium tracking-wider uppercase text-slate-500 bg-slate-800/50 px-2 py-0.5 rounded border border-slate-700/50">
                {intent}
              </span>
            </div>
          )}
        </div>
        
      </div>
    </div>
  );
}
