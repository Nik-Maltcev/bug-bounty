import { useEffect, useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { listPrograms, listVulnerabilities, listAuditLog } from '../services/api';
import type { ParsedProgram, Vulnerability, AuditEntry } from '../types';
import { 
  ShieldAlert, 
  Target, 
  FolderLock, 
  ShieldX, 
  ChevronRight,
  TrendingUp,
  Activity
} from 'lucide-react';
import { AreaChart, Area, ResponsiveContainer, Tooltip } from 'recharts';
import clsx from 'clsx';

// Simple helper to group items by date for a sparkline
const groupDates = (items: { created_at?: string | null; timestamp?: string | null }[]) => {
  const counts: Record<string, number> = {};
  const today = new Date();
  
  // Initialize last 7 days
  for (let i = 6; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    counts[d.toISOString().split('T')[0]] = 0;
  }
  
  items.forEach(item => {
    const dateStr = item.created_at || item.timestamp;
    if (dateStr) {
      const d = dateStr.split('T')[0];
      if (counts[d] !== undefined) counts[d]++;
    }
  });
  
  return Object.entries(counts).map(([date, count]) => ({ date, count }));
};

export default function DashboardPage() {
  const [programs, setPrograms] = useState<ParsedProgram[]>([]);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      listPrograms().catch(() => []),
      listVulnerabilities().catch(() => []),
      listAuditLog().catch(() => []),
    ]).then(([p, v, a]) => {
      setPrograms(p);
      setVulns(v);
      setAuditEntries(a);
      setLoading(false);
    });
  }, []);

  const chartData = useMemo(() => groupDates(vulns), [vulns]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 animate-pulse">
        <Activity className="w-6 h-6 mr-3 animate-spin" />
        Загрузка дашборда...
      </div>
    );
  }

  const activePrograms = programs.filter((p) => !p.is_archived);
  const criticalVulns = vulns.filter((v) => v.severity === 'critical');
  const blockedActions = auditEntries.filter((e) => e.result === 'blocked');

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold tracking-tight text-slate-100">Обзор</h1>
        <div className="flex items-center text-sm text-slate-400 bg-slate-900/50 px-3 py-1.5 rounded-full border border-slate-800 shadow-inner">
          <Activity className="w-4 h-4 mr-2 text-green-500" />
          Система активна
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <Link to="/app/programs" className="group relative bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl p-6 transition-all hover:bg-slate-800/80 hover:border-blue-500/50 hover:shadow-lg hover:shadow-blue-900/20 overflow-hidden">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-slate-400 group-hover:text-slate-300 transition-colors">Активные программы</h3>
            <div className="p-2 bg-blue-500/10 rounded-lg text-blue-500 group-hover:bg-blue-500/20 transition-colors">
              <FolderLock className="w-5 h-5" />
            </div>
          </div>
          <div className="flex items-baseline">
            <p className="text-3xl font-bold text-slate-100">{activePrograms.length}</p>
          </div>
          <div className="absolute bottom-0 left-0 w-full h-1 bg-blue-500/20" />
        </Link>

        <Link to="/app/vulnerabilities" className="group relative bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl p-6 transition-all hover:bg-slate-800/80 hover:border-amber-500/50 hover:shadow-lg hover:shadow-amber-900/20 overflow-hidden">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-slate-400 group-hover:text-slate-300 transition-colors">Всего уязвимостей</h3>
            <div className="p-2 bg-amber-500/10 rounded-lg text-amber-500 group-hover:bg-amber-500/20 transition-colors">
              <Target className="w-5 h-5" />
            </div>
          </div>
          <div className="flex items-baseline">
            <p className="text-3xl font-bold text-slate-100">{vulns.length}</p>
          </div>
          <div className="absolute bottom-0 left-0 w-full h-1 bg-amber-500/20" />
        </Link>

        <Link to="/app/vulnerabilities" className="group relative bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl p-6 transition-all hover:bg-slate-800/80 hover:border-red-500/50 hover:shadow-lg hover:shadow-red-900/20 overflow-hidden">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-slate-400 group-hover:text-slate-300 transition-colors">Критические</h3>
            <div className="p-2 bg-red-500/10 rounded-lg text-red-500 group-hover:bg-red-500/20 transition-colors">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </div>
          <div className="flex items-baseline">
            <p className="text-3xl font-bold text-slate-100">{criticalVulns.length}</p>
          </div>
          <div className="absolute bottom-0 left-0 w-full h-1 bg-red-500/20" />
        </Link>

        <Link to="/app/audit" className="group relative bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl p-6 transition-all hover:bg-slate-800/80 hover:border-purple-500/50 hover:shadow-lg hover:shadow-purple-900/20 overflow-hidden">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-slate-400 group-hover:text-slate-300 transition-colors">Заблокировано</h3>
            <div className="p-2 bg-purple-500/10 rounded-lg text-purple-500 group-hover:bg-purple-500/20 transition-colors">
              <ShieldX className="w-5 h-5" />
            </div>
          </div>
          <div className="flex items-baseline">
            <p className="text-3xl font-bold text-slate-100">{blockedActions.length}</p>
          </div>
          <div className="absolute bottom-0 left-0 w-full h-1 bg-purple-500/20" />
        </Link>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column */}
        <div className="lg:col-span-2 space-y-6">
          {/* Chart Section */}
          <section className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl p-6 shadow-sm">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-semibold text-slate-100 flex items-center">
                <TrendingUp className="w-5 h-5 mr-2 text-blue-500" />
                Динамика находок
              </h2>
            </div>
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 5, right: 0, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorVulns" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', borderRadius: '0.5rem', color: '#f8fafc' }}
                    itemStyle={{ color: '#60a5fa' }}
                  />
                  <Area type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={3} fillOpacity={1} fill="url(#colorVulns)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </section>

          {/* Vulnerabilities List */}
          <section className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl shadow-sm overflow-hidden">
            <div className="p-6 border-b border-slate-800 flex justify-between items-center bg-slate-900/80">
              <h2 className="text-lg font-semibold text-slate-100">Последние уязвимости</h2>
              <Link to="/app/vulnerabilities" className="text-sm text-blue-400 hover:text-blue-300 transition-colors flex items-center">
                Все <ChevronRight className="w-4 h-4 ml-1" />
              </Link>
            </div>
            <div className="p-0">
              {vulns.length === 0 ? (
                <div className="p-8 text-center text-slate-500">
                  Пока не найдено ни одной уязвимости.
                </div>
              ) : (
                <ul className="divide-y divide-slate-800/50">
                  {vulns.slice(0, 5).map((v) => (
                    <li key={v.id} className="p-4 hover:bg-slate-800/30 transition-colors flex items-center justify-between">
                      <div className="flex items-center gap-4">
                        <span className={clsx(
                          "px-2.5 py-1 text-xs font-semibold rounded-md border",
                          v.severity === 'critical' ? "bg-red-500/10 text-red-400 border-red-500/20" :
                          v.severity === 'high' ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
                          v.severity === 'medium' ? "bg-amber-500/10 text-amber-400 border-amber-500/20" :
                          v.severity === 'low' ? "bg-blue-500/10 text-blue-400 border-blue-500/20" :
                          "bg-slate-500/10 text-slate-400 border-slate-500/20"
                        )}>
                          {v.severity.toUpperCase()}
                        </span>
                        <span className="font-medium text-slate-200">{v.vulnerability_type}</span>
                      </div>
                      <span className="text-sm px-2 py-1 bg-slate-800 rounded text-slate-400">{v.status}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>
        </div>

        {/* Right Column */}
        <div className="space-y-6">
          <section className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl shadow-sm overflow-hidden flex flex-col h-full">
            <div className="p-6 border-b border-slate-800 bg-slate-900/80">
              <h2 className="text-lg font-semibold text-slate-100 flex items-center justify-between">
                Недавние программы
                <Link to="/app/programs" className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors">
                  <ChevronRight className="w-5 h-5" />
                </Link>
              </h2>
            </div>
            <div className="p-4 flex-1">
              {activePrograms.length === 0 ? (
                <div className="text-center py-8">
                  <p className="text-slate-500 mb-4">Программ пока нет.</p>
                  <Link to="/app/programs" className="inline-flex items-center justify-center px-4 py-2 text-sm font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-500 transition-colors">
                    Добавить программу
                  </Link>
                </div>
              ) : (
                <ul className="space-y-3">
                  {activePrograms.slice(0, 5).map((p) => (
                    <li key={p.id}>
                      <Link to={`/app/programs/${p.id}`} className="block p-3 rounded-xl border border-slate-800 hover:border-slate-700 hover:bg-slate-800/50 transition-all group">
                        <div className="flex justify-between items-start mb-2">
                          <h4 className="font-medium text-slate-200 group-hover:text-blue-400 transition-colors line-clamp-1">{p.name}</h4>
                          <span className="text-xs px-2 py-1 rounded bg-slate-800 text-slate-400 whitespace-nowrap ml-2">
                            {p.platform}
                          </span>
                        </div>
                        <div className="text-xs text-slate-500">
                          {p.assets.length} {p.assets.length === 1 ? 'актив' : p.assets.length < 5 ? 'актива' : 'активов'}
                        </div>
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
