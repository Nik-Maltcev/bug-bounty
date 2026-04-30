import { useEffect, useState } from 'react';
import { listVulnerabilities, generateReport } from '../services/api';
import type { Vulnerability } from '../types';
import { SeverityLevel } from '../types';
import { 
  ShieldAlert, 
  Filter, 
  FilePlus, 
  Activity, 
  Search,
  ExternalLink,
  ChevronRight,
  Loader2,
  AlertCircle
} from 'lucide-react';
import clsx from 'clsx';

const STATUS_MAP: Record<string, string> = {
  'new': 'Новая',
  'reported': 'Отправлена',
  'accepted': 'Принята',
  'rejected': 'Отклонена',
  'fixed': 'Исправлена'
};

const SEVERITY_MAP: Record<string, string> = {
  'critical': 'Критическая',
  'high': 'Высокая',
  'medium': 'Средняя',
  'low': 'Низкая',
  'informational': 'Инфо'
};

export default function VulnerabilitiesPage() {
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [generating, setGenerating] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  const load = () => {
    setLoading(true);
    const filters: Record<string, string> = {};
    if (severityFilter) filters.severity = severityFilter;
    if (statusFilter) filters.status = statusFilter;
    listVulnerabilities(filters).then(setVulns).catch(() => {}).finally(() => setLoading(false));
  };

  useEffect(load, [severityFilter, statusFilter]);

  const handleGenerateReport = async (vulnId: string) => {
    setGenerating(vulnId);
    try {
      const report = await generateReport(vulnId);
      // Success toast would be better but let's use a nice localized alert for now
      alert(`Отчёт успешно создан: ${report.title}`);
    } catch {
      alert('Не удалось создать отчёт');
    } finally {
      setGenerating(null);
    }
  };

  const filteredVulns = vulns.filter(v => 
    v.vulnerability_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
    v.description.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <h1 className="text-3xl font-bold tracking-tight text-slate-100">Уязвимости</h1>
        
        <div className="flex w-full md:w-auto items-center gap-3">
          <div className="relative group w-full md:w-64">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500 group-focus-within:text-blue-500">
              <Search className="h-4 w-4" />
            </div>
            <input
              type="text"
              placeholder="Поиск по типу или описанию..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="block w-full pl-9 pr-3 py-2 border border-slate-700 rounded-lg bg-slate-900/50 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all"
            />
          </div>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="flex flex-wrap items-center gap-4 p-4 bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-xl">
        <div className="flex items-center text-slate-400 text-sm mr-2">
          <Filter className="w-4 h-4 mr-2" />
          Фильтры:
        </div>
        
        <div className="flex items-center gap-2">
          <label htmlFor="filter-severity" className="text-xs font-medium text-slate-500 uppercase tracking-wider">Критичность</label>
          <select 
            id="filter-severity" 
            value={severityFilter} 
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg focus:ring-blue-500 focus:border-blue-500 block p-1.5 outline-none transition-all"
          >
            <option value="">Все уровни</option>
            {Object.values(SeverityLevel).map((s) => (
              <option key={s} value={s}>{SEVERITY_MAP[s] || s}</option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-2">
          <label htmlFor="filter-status" className="text-xs font-medium text-slate-500 uppercase tracking-wider">Статус</label>
          <select 
            id="filter-status" 
            value={statusFilter} 
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded-lg focus:ring-blue-500 focus:border-blue-500 block p-1.5 outline-none transition-all"
          >
            <option value="">Все статусы</option>
            {Object.entries(STATUS_MAP).map(([val, label]) => (
              <option key={val} value={val}>{label}</option>
            ))}
          </select>
        </div>

        {(severityFilter || statusFilter || searchQuery) && (
          <button 
            onClick={() => { setSeverityFilter(''); setStatusFilter(''); setSearchQuery(''); }}
            className="text-xs text-slate-400 hover:text-slate-200 underline underline-offset-4 ml-auto"
          >
            Сбросить всё
          </button>
        )}
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64 text-slate-400 animate-pulse">
          <Activity className="w-6 h-6 mr-3 animate-spin" />
          Загрузка списка уязвимостей...
        </div>
      ) : filteredVulns.length === 0 ? (
        <div className="text-center py-20 bg-slate-900/30 rounded-2xl border border-slate-800 border-dashed">
          <div className="mx-auto w-16 h-16 bg-slate-800 rounded-full flex items-center justify-center text-slate-500 mb-4">
            <ShieldAlert className="w-8 h-8" />
          </div>
          <h3 className="text-lg font-medium text-slate-200 mb-2">Уязвимостей не найдено</h3>
          <p className="text-slate-400 max-w-sm mx-auto">
            Попробуйте изменить параметры фильтрации или запустите новое сканирование.
          </p>
        </div>
      ) : (
        <div className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-widest font-bold">
                <tr>
                  <th className="px-6 py-4">Уровень</th>
                  <th className="px-6 py-4">Тип уязвимости</th>
                  <th className="px-6 py-4">Описание</th>
                  <th className="px-6 py-4">Статус</th>
                  <th className="px-6 py-4 text-right">Действия</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {filteredVulns.map((v) => (
                  <tr key={v.id} className="hover:bg-slate-800/30 transition-colors group">
                    <td className="px-6 py-4">
                      <span className={clsx(
                        "px-2.5 py-1 text-[10px] font-bold rounded-md border shadow-sm",
                        v.severity === 'critical' ? "bg-red-500/10 text-red-400 border-red-500/20" :
                        v.severity === 'high' ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
                        v.severity === 'medium' ? "bg-amber-500/10 text-amber-400 border-amber-500/20" :
                        v.severity === 'low' ? "bg-blue-500/10 text-blue-400 border-blue-500/20" :
                        "bg-slate-500/10 text-slate-400 border-slate-500/20"
                      )}>
                        {(SEVERITY_MAP[v.severity] || v.severity).toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 font-medium text-slate-200">
                      {v.vulnerability_type}
                    </td>
                    <td className="px-6 py-4 max-w-xs xl:max-w-md">
                      <div className="truncate text-slate-400 group-hover:text-slate-300 transition-colors" title={v.description}>
                        {v.description}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
                        {STATUS_MAP[v.status] || v.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button
                        onClick={() => handleGenerateReport(v.id)}
                        disabled={generating === v.id}
                        className={clsx(
                          "inline-flex items-center justify-center px-3 py-1.5 rounded-lg text-xs font-medium transition-all",
                          generating === v.id 
                            ? "bg-slate-800 text-slate-500" 
                            : "bg-blue-600/10 text-blue-400 hover:bg-blue-600 hover:text-white"
                        )}
                      >
                        {generating === v.id ? (
                          <><Loader2 className="w-3 h-3 mr-1.5 animate-spin" /> Генерирую...</>
                        ) : (
                          <><FilePlus className="w-3 h-3 mr-1.5" /> Создать отчёт</>
                        )}
                      </button>
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
