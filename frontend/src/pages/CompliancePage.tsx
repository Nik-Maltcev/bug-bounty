import { useEffect, useState } from 'react';
import { listPrograms, getComplianceSummary } from '../services/api';
import type { ParsedProgram, ComplianceSummary } from '../types';
import { 
  ShieldCheck, 
  Activity, 
  Layers, 
  CheckCircle2, 
  XCircle, 
  AlertCircle,
  BarChart3,
  ListRestart
} from 'lucide-react';
import clsx from 'clsx';

export default function CompliancePage() {
  const [programs, setPrograms] = useState<ParsedProgram[]>([]);
  const [selectedProgram, setSelectedProgram] = useState('');
  const [summary, setSummary] = useState<ComplianceSummary | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    listPrograms(false).then(setPrograms).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedProgram) { setSummary(null); return; }
    setLoading(true);
    getComplianceSummary(selectedProgram).then(setSummary).catch(() => setSummary(null)).finally(() => setLoading(false));
  }, [selectedProgram]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold tracking-tight text-slate-100">Комплаенс</h1>
        <div className="flex items-center text-sm text-slate-400 bg-slate-900/50 px-3 py-1.5 rounded-full border border-slate-800">
          <ShieldCheck className="w-4 h-4 mr-2 text-purple-500" />
          Контроль правил
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-start">
        {/* Selector Column */}
        <div className="lg:col-span-1">
          <section className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl p-6 shadow-sm">
            <label htmlFor="compliance-program" className="block text-sm font-medium text-slate-400 mb-3">Выберите программу</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <Layers className="h-4 w-4" />
              </div>
              <select
                id="compliance-program"
                value={selectedProgram}
                onChange={(e) => setSelectedProgram(e.target.value)}
                className="block w-full pl-9 pr-3 py-2.5 border border-slate-700 rounded-xl bg-slate-950/50 text-sm text-slate-100 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all appearance-none cursor-pointer"
              >
                <option value="">Выберите...</option>
                {programs.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>
          </section>
        </div>

        {/* Content Column */}
        <div className="lg:col-span-3 space-y-6">
          {loading ? (
            <div className="flex items-center justify-center h-64 text-slate-400 animate-pulse">
              <Activity className="w-6 h-6 mr-3 animate-spin" />
              Загрузка данных комплаенса...
            </div>
          ) : summary ? (
            <div className="animate-fade-in space-y-6">
              {/* Stats Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl p-6 shadow-sm">
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-sm font-medium text-slate-400">Всего действий</span>
                    <Activity className="w-5 h-5 text-blue-500" />
                  </div>
                  <p className="text-3xl font-bold text-slate-100">{summary.total_actions}</p>
                </div>

                <div className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl p-6 shadow-sm">
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-sm font-medium text-slate-400">Разрешено</span>
                    <CheckCircle2 className="w-5 h-5 text-green-500" />
                  </div>
                  <p className="text-3xl font-bold text-green-400">{summary.allowed_actions}</p>
                </div>

                <div className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl p-6 shadow-sm">
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-sm font-medium text-slate-400">Заблокировано</span>
                    <XCircle className="w-5 h-5 text-red-500" />
                  </div>
                  <p className="text-3xl font-bold text-red-400">{summary.blocked_actions}</p>
                </div>
              </div>

              {/* Blocked Reasons */}
              {summary.blocked_reasons.length > 0 ? (
                <section className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl overflow-hidden shadow-sm">
                  <div className="p-6 border-b border-slate-800 bg-slate-900/80">
                    <h3 className="text-lg font-semibold text-slate-100 flex items-center">
                      <AlertCircle className="w-5 h-5 mr-2 text-amber-500" /> Причины блокировок
                    </h3>
                  </div>
                  <div className="p-0 overflow-x-auto">
                    <table className="w-full text-left text-sm whitespace-nowrap">
                      <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-widest font-bold">
                        <tr>
                          <th className="px-6 py-4">Причина</th>
                          <th className="px-6 py-4 text-center">Количество</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/50">
                        {summary.blocked_reasons.map((br, i) => (
                          <tr key={i} className="hover:bg-slate-800/30 transition-colors">
                            <td className="px-6 py-4 text-slate-300 font-medium">{br.reason}</td>
                            <td className="px-6 py-4 text-center">
                              <span className="px-3 py-1 bg-red-500/10 text-red-400 rounded-full border border-red-500/20 font-bold">
                                {br.count}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              ) : (
                <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-10 flex flex-col items-center justify-center text-center">
                  <CheckCircle2 className="w-12 h-12 text-green-500 mb-4 opacity-50" />
                  <h3 className="text-lg font-medium text-slate-200 mb-2">Нарушений не зафиксировано</h3>
                  <p className="text-slate-500 max-w-sm">Все действия агента соответствуют правилам выбранной программы.</p>
                </div>
              )}
            </div>
          ) : (
            <div className="h-full min-h-[300px] bg-slate-900/30 border-2 border-slate-800 border-dashed rounded-2xl flex flex-col items-center justify-center text-center p-8">
              <div className="w-16 h-16 bg-slate-800 rounded-full flex items-center justify-center text-slate-500 mb-4 opacity-50">
                <BarChart3 className="w-8 h-8" />
              </div>
              <h3 className="text-lg font-medium text-slate-300 mb-2">Выберите программу для анализа</h3>
              <p className="text-slate-500 max-w-sm">
                Выберите программу в панели слева, чтобы просмотреть статистику разрешенных и заблокированных действий агента.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
