import { useEffect, useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { listPrograms, importProgram, archiveProgram } from '../services/api';
import type { ParsedProgram } from '../types';
import { 
  Plus, 
  X, 
  Link as LinkIcon, 
  FileText, 
  Archive, 
  Activity, 
  Search, 
  Globe, 
  ShieldCheck,
  Package
} from 'lucide-react';
import clsx from 'clsx';

export default function ProgramsPage() {
  const [programs, setPrograms] = useState<ParsedProgram[]>([]);
  const [loading, setLoading] = useState(true);
  const [showImport, setShowImport] = useState(false);
  const [importUrl, setImportUrl] = useState('');
  const [importText, setImportText] = useState('');
  const [importError, setImportError] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const load = () => {
    setLoading(true);
    listPrograms().then(setPrograms).catch(() => {}).finally(() => setLoading(false));
  };

  useEffect(load, []);

  const handleImport = async (e: FormEvent) => {
    e.preventDefault();
    setImporting(true);
    setImportError(null);
    try {
      const source: { url?: string; text?: string } = {};
      if (importUrl) source.url = importUrl;
      if (importText) source.text = importText;
      await importProgram(source);
      setShowImport(false);
      setImportUrl('');
      setImportText('');
      load();
    } catch (err: unknown) {
      setImportError(
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Ошибка импорта',
      );
    } finally {
      setImporting(false);
    }
  };

  const handleArchive = async (id: string, name: string) => {
    if (!confirm(`Архивировать программу "${name}"?`)) return;
    await archiveProgram(id);
    load();
  };

  const filteredPrograms = programs.filter(p => 
    p.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
    p.platform.toLowerCase().includes(searchQuery.toLowerCase())
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 animate-pulse">
        <Activity className="w-6 h-6 mr-3 animate-spin" />
        Загрузка программ...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <h1 className="text-3xl font-bold tracking-tight text-slate-100">Программы</h1>
        
        <div className="flex w-full sm:w-auto items-center gap-3">
          <div className="relative group w-full sm:w-64">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500 group-focus-within:text-blue-500">
              <Search className="h-4 w-4" />
            </div>
            <input
              type="text"
              placeholder="Поиск программ..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="block w-full pl-9 pr-3 py-2 border border-slate-700 rounded-lg bg-slate-900/50 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
            />
          </div>
          <button 
            onClick={() => setShowImport(!showImport)}
            className={clsx(
              "flex items-center px-4 py-2 rounded-lg text-sm font-medium transition-all shrink-0",
              showImport 
                ? "bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-700" 
                : "bg-blue-600 text-white hover:bg-blue-500 shadow-lg shadow-blue-500/20"
            )}
          >
            {showImport ? (
              <><X className="w-4 h-4 mr-2" /> Отмена</>
            ) : (
              <><Plus className="w-4 h-4 mr-2" /> Импорт программы</>
            )}
          </button>
        </div>
      </div>

      {showImport && (
        <div className="bg-slate-900/80 backdrop-blur-sm border border-slate-700 rounded-xl p-6 shadow-xl animate-fade-in">
          <h3 className="text-lg font-semibold text-slate-100 mb-4">Импорт новой программы</h3>
          <form onSubmit={handleImport} className="space-y-5">
            <div className="space-y-2">
              <label htmlFor="import-url" className="block text-sm font-medium text-slate-300">
                URL программы (HackerOne, Bugcrowd, Intigriti и др.)
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                  <LinkIcon className="h-4 w-4" />
                </div>
                <input
                  id="import-url"
                  type="url"
                  placeholder="https://hackerone.com/security"
                  value={importUrl}
                  onChange={(e) => setImportUrl(e.target.value)}
                  className="block w-full pl-9 pr-3 py-2 border border-slate-700 rounded-lg bg-slate-950/50 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
                />
              </div>
            </div>
            
            <div className="relative flex items-center py-2">
              <div className="flex-grow border-t border-slate-700"></div>
              <span className="flex-shrink-0 mx-4 text-slate-500 text-xs font-medium uppercase tracking-wider">или</span>
              <div className="flex-grow border-t border-slate-700"></div>
            </div>

            <div className="space-y-2">
              <label htmlFor="import-text" className="block text-sm font-medium text-slate-300">
                Вставьте текст описания программы
              </label>
              <div className="relative">
                <div className="absolute top-3 left-3 pointer-events-none text-slate-500">
                  <FileText className="h-4 w-4" />
                </div>
                <textarea
                  id="import-text"
                  rows={5}
                  placeholder="Вставьте правила, область действия (scope) и другую информацию о программе..."
                  value={importText}
                  onChange={(e) => setImportText(e.target.value)}
                  className="block w-full pl-9 pr-3 py-2 border border-slate-700 rounded-lg bg-slate-950/50 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all resize-none"
                />
              </div>
            </div>

            {importError && (
              <div className="p-3 text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg">
                {importError}
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button 
                type="submit" 
                disabled={importing || (!importUrl && !importText)}
                className="flex items-center px-5 py-2.5 rounded-lg text-sm font-medium bg-blue-600 text-white hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-blue-500/20"
              >
                {importing ? (
                  <><Activity className="w-4 h-4 mr-2 animate-spin" /> Обработка ИИ...</>
                ) : (
                  'Импортировать'
                )}
              </button>
            </div>
          </form>
        </div>
      )}

      {programs.length === 0 ? (
        <div className="text-center py-20 bg-slate-900/30 rounded-2xl border border-slate-800 border-dashed">
          <div className="mx-auto w-16 h-16 bg-slate-800 rounded-full flex items-center justify-center text-slate-500 mb-4">
            <FolderOpen className="w-8 h-8" />
          </div>
          <h3 className="text-lg font-medium text-slate-200 mb-2">Нет добавленных программ</h3>
          <p className="text-slate-400 max-w-sm mx-auto mb-6">
            Импортируйте вашу первую bug bounty программу по URL или вставив текст, чтобы начать сканирование.
          </p>
          <button 
            onClick={() => setShowImport(true)}
            className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-500 transition-colors shadow-lg shadow-blue-500/20"
          >
            <Plus className="w-4 h-4 mr-2" /> Импорт программы
          </button>
        </div>
      ) : filteredPrograms.length === 0 ? (
        <div className="text-center py-12 text-slate-400">
          По вашему запросу ничего не найдено.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
          {filteredPrograms.map((p) => (
            <div 
              key={p.id} 
              className={clsx(
                "group relative flex flex-col bg-slate-900/60 backdrop-blur-sm border rounded-2xl overflow-hidden transition-all duration-300",
                p.is_archived 
                  ? "border-slate-800 opacity-60 hover:opacity-100" 
                  : "border-slate-700 hover:border-blue-500/50 hover:shadow-xl hover:shadow-blue-900/10"
              )}
            >
              <div className="p-5 flex-1">
                <div className="flex justify-between items-start mb-4">
                  <span className={clsx(
                    "px-2.5 py-1 text-xs font-semibold rounded-md border",
                    p.is_archived
                      ? "bg-slate-800/50 text-slate-400 border-slate-700/50"
                      : "bg-blue-500/10 text-blue-400 border-blue-500/20"
                  )}>
                    {p.platform}
                  </span>
                  
                  {p.is_archived ? (
                    <span className="flex items-center text-xs text-slate-500 bg-slate-800 px-2 py-1 rounded">
                      <Package className="w-3 h-3 mr-1" /> Архив
                    </span>
                  ) : (
                    <span className="flex items-center text-xs text-green-400 bg-green-500/10 border border-green-500/20 px-2 py-1 rounded">
                      <div className="w-1.5 h-1.5 rounded-full bg-green-400 mr-1.5 animate-pulse" /> Активна
                    </span>
                  )}
                </div>
                
                <h3 className="text-lg font-bold text-slate-100 mb-3 group-hover:text-blue-400 transition-colors line-clamp-1">
                  {p.name}
                </h3>
                
                <div className="grid grid-cols-2 gap-3 mb-2">
                  <div className="flex items-center text-slate-400 text-sm">
                    <Globe className="w-4 h-4 mr-2 text-slate-500" />
                    <span>{p.assets.length} активов</span>
                  </div>
                  <div className="flex items-center text-slate-400 text-sm">
                    <ShieldCheck className="w-4 h-4 mr-2 text-slate-500" />
                    <span>{p.rules.length} правил</span>
                  </div>
                </div>
              </div>
              
              <div className="p-4 bg-slate-900/80 border-t border-slate-800 flex justify-between items-center gap-3">
                <Link 
                  to={`/programs/${p.id}`} 
                  className="flex-1 inline-flex justify-center items-center px-4 py-2 bg-slate-800 text-slate-200 text-sm font-medium rounded-lg hover:bg-slate-700 hover:text-white transition-colors"
                >
                  Подробнее
                </Link>
                {!p.is_archived && (
                  <button 
                    onClick={() => handleArchive(p.id, p.name)}
                    className="p-2 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
                    title="В архив"
                  >
                    <Archive className="w-5 h-5" />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
