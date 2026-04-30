import { useState, type FormEvent, type KeyboardEvent, useRef, useEffect } from 'react';
import { Send, Loader2 } from 'lucide-react';
import clsx from 'clsx';

interface Props {
  onSend: (message: string) => void;
  disabled?: boolean;
}

const MAX_LENGTH = 10000;

export default function ChatInput({ onSend, disabled }: Props) {
  const [text, setText] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const handleSubmit = (e?: FormEvent) => {
    if (e) e.preventDefault();
    const trimmed = text.trim();
    if (!trimmed || disabled) return;
    onSend(trimmed);
    setText('');
    
    // Reset height
    if (textareaRef.current) {
      textareaRef.current.style.height = '44px';
    }
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  // Auto-resize textarea
  useEffect(() => {
    const textarea = textareaRef.current;
    if (textarea) {
      textarea.style.height = '44px';
      const scrollHeight = textarea.scrollHeight;
      textarea.style.height = Math.min(scrollHeight, 150) + 'px';
    }
  }, [text]);

  return (
    <form 
      onSubmit={handleSubmit} 
      className="relative flex items-end gap-2 bg-slate-950/50 p-2 rounded-xl border border-slate-700/50 focus-within:border-blue-500/50 focus-within:ring-1 focus-within:ring-blue-500/50 transition-all shadow-inner"
    >
      <textarea
        ref={textareaRef}
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="Введите сообщение ИИ-агенту..."
        maxLength={MAX_LENGTH}
        disabled={disabled}
        rows={1}
        aria-label="Поле ввода сообщения"
        className="flex-1 max-h-[150px] min-h-[44px] py-3 px-4 bg-transparent border-none focus:outline-none focus:ring-0 resize-none text-slate-100 placeholder-slate-500 text-sm scrollbar-thin scrollbar-thumb-slate-700"
      />
      <div className="shrink-0 p-1">
        <button
          type="submit"
          disabled={disabled || !text.trim()}
          aria-label="Отправить"
          className={clsx(
            "flex items-center justify-center w-10 h-10 rounded-lg transition-all",
            disabled || !text.trim()
              ? "bg-slate-800 text-slate-500 cursor-not-allowed"
              : "bg-blue-600 text-white hover:bg-blue-500 hover:shadow-lg hover:shadow-blue-500/20 active:scale-95"
          )}
        >
          {disabled && text.trim() ? (
            <Loader2 className="w-5 h-5 animate-spin" />
          ) : (
            <Send className="w-5 h-5 ml-0.5" />
          )}
        </button>
      </div>
    </form>
  );
}
