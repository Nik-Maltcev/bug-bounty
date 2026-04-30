import { useEffect, useState } from 'react';
import { listAuditLog, exportAuditLog } from '../services/api';
import type { AuditEntry } from '../types';
import { 
  ListOrdered, 
  Download, 
  Filter, 
  Search, 
  Activity, 
  Clock, 
  ShieldCheck, 
  ShieldX,
  ExternalLink,
  ChevronRight
} from 'lucide-react';
import clsx from 'clsx';

export default function AuditLogPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionFilter, setActionFilter] = useState('');
  const [resultFilter, setResultFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  const load = () => {
    setLoading(true);
    const filters: Record<string, string> = {};
    if (actionFilter) filters.action_type = actionFilter;
    if (resultFilter) filters.result = resultFilter;
    listAuditLog(filters).then(setEntries).catch(() => {}).finally(() => setLoading(false));
  };

  useEffect(load, [actionFilter, resultFilter]);

  const handleExport = async () => {
    try {
      const filters: Record<string, string> = {};
      if (actionFilter) filters.action_type = actionFilter;
      if (resultFilter) filters.result = resultFilter;
      const json = await exportAuditLog(filters);
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit-log-${new Date().toISOString().split('T')[0]}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      alert('Ошибка при экспорте JSON');
    }
  };

  const filteredEntries = entries.filter(e => 
    e.target_asset.toLowerCase().includes(searchQuery.toLowerCase()) ||
    e.details.toLowerCase().includes(searchQuery.toLowerCase()) ||
    e.action_type.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <h1 className="text-3xl font-bold tracking-tight text-slate-100">Журнал аудита</h1>
        
        <div className="flex w-full md:w-auto items-center gap-3">
          <div className="relative group w-full md:w-64">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500 group-focus-within:text-blue-500">
              <Search className="h-4 w-4" />
            </div>
            <input
              type="text"
              placeholder="Поиск по цели или деталям..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="block w-full pl-9 pr-3 py-2 border border-slate-700 rounded-lg bg-slate-900/50 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
            />
          </div>
          <button 
            onClick={handleExport}
            className="flex items-center px-4 py-2 rounded-lg text-sm font-medium bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-700 transition-all shrink-0"
          >
            <Download className="w-4 h-4 mr-2" /> JSON
          </button>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="flex flex-wrap items-center gap-4 p-4 bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-xl">
        <div className="flex items-center text-slate-400 text-sm mr-2">
          <Filter className="w-4 h-4 mr-2" />
          Фильтры:
        </div>
        
        <div className="flex items-center gap-2">
          <label htmlFor="filter-result" className="text-xs font-medium text-slate-500 uppercase tracking-wider">Результат</label>
          <select 
            id="filter-result" 
            value={resultFilter} 
            onChange={(e) => setResultFilter(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg focus:ring-blue-500 focus:border-blue-500 block p-1.5 outline-none transition-all"
          >
            <option value="">Все результаты</option>
            <option value="allowed">Разрешено</option>
            <option value="blocked">Заблокировано</option>
          </select>
        </div>

        {(actionFilter || resultFilter || searchQuery) && (
          <button 
            onClick={() => { setActionFilter(''); setResultFilter(''); setSearchQuery(''); }}
            className="text-xs text-slate-400 hover:text-slate-200 underline underline-offset-4 ml-auto"
          >
            Сбросить всё
          </button>
        )}
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64 text-slate-400 animate-pulse">
          <Activity className="w-6 h-6 mr-3 animate-spin" />
          Загрузка журнала аудита...
        </div>
      ) : filteredEntries.length === 0 ? (
        <div className="text-center py-20 bg-slate-900/30 rounded-2xl border border-slate-800 border-dashed">
          <div className="mx-auto w-16 h-16 bg-slate-800 rounded-full flex items-center justify-center text-slate-500 mb-4">
            <ListOrdered className="w-8 h-8" />
          </div>
          <h3 className="text-lg font-medium text-slate-200 mb-2">Записей не найдено</h3>
          <p className="text-slate-400 max-w-sm mx-auto">
            Журнал аудита пока пуст или записи не соответствуют выбранным фильтрам.
          </p>
        </div>
      ) : (
        <div className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-widest font-bold">
                <tr>
                  <th className="px-6 py-4">Временая метка</th>
                  <th className="px-6 py-4">Действие</th>
                  <th className="px-6 py-4">Цель</th>
                  <th className="px-6 py-4">Результат</th>
                  <th className="px-6 py-4">Детали</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {filteredEntries.map((e) => (
                  <tr 
                    key={e.id} 
                    className={clsx(
                      "hover:bg-slate-800/30 transition-colors group",
                      e.result === 'blocked' ? "bg-red-500/[0.02]" : ""
                    )}
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center text-slate-400 group-hover:text-slate-300">
                        <Clock className="w-3.5 h-3.5 mr-2 opacity-50" />
                        <span className="font-mono text-xs">{new Date(e.timestamp).toLocaleString('ru-RU')}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="px-2 py-1 bg-slate-800 text-slate-300 rounded text-xs font-medium border border-slate-700">
                        {e.action_type}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center max-w-[200px] truncate text-slate-300" title={e.target_asset}>
                        {e.target_asset}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={clsx(
                        "inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-bold border",
                        e.result === 'allowed' 
                          ? "bg-green-500/10 text-green-400 border-green-500/20" 
                          : "bg-red-500/10 text-red-400 border-red-500/20"
                      )}>
                        {e.result === 'allowed' ? (
                          <><ShieldCheck className="w-3 h-3 mr-1" /> РАЗРЕШЕНО</>
                        ) : (
                          <><ShieldX className="w-3 h-3 mr-1" /> ЗАБЛОКИРОВАНО</>
                        )}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center text-slate-400 max-w-xs truncate italic text-xs" title={e.details}>
                        {e.details}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
