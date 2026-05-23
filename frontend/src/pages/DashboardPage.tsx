import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { listScans, listVulnerabilities } from '../services/api';
import type { ScanRecord, Vulnerability } from '../types';
import { 
  PieChart, Pie, Cell, AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer
} from 'recharts';
import { 
  Search, 
  ShieldAlert, 
  Target, 
  Activity,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  ArrowRight,
  TrendingUp,
  Shield,
  AlertTriangle
} from 'lucide-react';
import clsx from 'clsx';

const SEVERITY_CONFIG: Record<string, { label: string; color: string }> = {
  'critical': { label: 'Критические', color: '#ef4444' },
  'high': { label: 'Высокие', color: '#f97316' },
  'medium': { label: 'Средние', color: '#eab308' },
  'low': { label: 'Низкие', color: '#3b82f6' },
  'informational': { label: 'Инфо', color: '#6b7280' },
};

export default function DashboardPage() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      listScans(500).catch(() => []),
      listVulnerabilities().catch(() => []),
    ]).then(([s, v]) => {
      setScans(s);
      setVulns(v);
      setLoading(false);
    });
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 animate-pulse">
        <Activity className="w-6 h-6 mr-3 animate-spin" />
        Загрузка...
      </div>
    );
  }

  const criticalVulns = vulns.filter((v) => v.severity === 'critical');
  const highVulns = vulns.filter((v) => v.severity === 'high');
  const runningScans = scans.filter((s) => s.status === 'running');
  const completedScans = scans.filter((s) => s.status === 'completed');

  // Данные для круговой диаграммы
  const severityCounts = vulns.reduce((acc, v) => {
    acc[v.severity] = (acc[v.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const pieData = Object.entries(severityCounts).map(([severity, count]) => ({
    name: SEVERITY_CONFIG[severity]?.label || severity,
    value: count,
    color: SEVERITY_CONFIG[severity]?.color || '#6b7280',
  }));

  // Данные для графика активности (последние 7 дней)
  const last7Days = Array.from({ length: 7 }, (_, i) => {
    const date = new Date();
    date.setDate(date.getDate() - (6 - i));
    return date.toISOString().split('T')[0];
  });

  const activityData = last7Days.map(date => {
    const dayScans = scans.filter(s => s.started_at?.startsWith(date)).length;
    const dayVulns = vulns.filter(v => v.created_at?.startsWith(date)).length;
    return {
      date: new Date(date).toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit' }),
      scans: dayScans,
      vulns: dayVulns,
    };
  });

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle2 className="w-4 h-4 text-green-400" />;
      case 'failed': return <XCircle className="w-4 h-4 text-red-400" />;
      case 'running': return <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />;
      default: return <Clock className="w-4 h-4 text-slate-400" />;
    }
  };

  const getStatusLabel = (status: string) => {
    switch (status) {
      case 'pending': return 'В очереди';
      case 'running': return 'Выполняется';
      case 'completed': return 'Завершено';
      case 'failed': return 'Ошибка';
      default: return status;
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return '—';
    const date = new Date(dateStr);
    return date.toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold tracking-tight text-slate-100">Обзор</h1>
        <div className="flex items-center text-sm text-slate-400 bg-slate-900/50 px-3 py-1.5 rounded-full border border-slate-800 shadow-inner">
          <Activity className="w-4 h-4 mr-2 text-green-500" />
          Система активна
        </div>
      </div>

      {/* Quick Action - Start Scan */}
      <Link 
        to="/app/scans"
        className="block p-6 bg-gradient-to-r from-blue-600/20 to-cyan-600/20 border border-blue-500/30 rounded-2xl hover:from-blue-600/30 hover:to-cyan-600/30 transition-all group"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-14 h-14 bg-blue-500/20 rounded-xl flex items-center justify-center">
              <Search className="w-7 h-7 text-blue-400" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">Начать сканирование</h2>
              <p className="text-slate-400">Введите URL сайта для поиска уязвимостей</p>
            </div>
          </div>
          <ArrowRight className="w-6 h-6 text-blue-400 group-hover:translate-x-1 transition-transform" />
        </div>
      </Link>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm text-slate-400">Всего сканирований</span>
            <Search className="w-5 h-5 text-blue-500" />
          </div>
          <p className="text-3xl font-bold text-white">{scans.length}</p>
          <p className="text-xs text-slate-500 mt-1">Завершено: {completedScans.length}</p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm text-slate-400">Активных</span>
            <Loader2 className={clsx("w-5 h-5 text-cyan-500", runningScans.length > 0 && "animate-spin")} />
          </div>
          <p className="text-3xl font-bold text-white">{runningScans.length}</p>
          <p className="text-xs text-slate-500 mt-1">Сейчас выполняется</p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm text-slate-400">Уязвимостей</span>
            <Target className="w-5 h-5 text-amber-500" />
          </div>
          <p className="text-3xl font-bold text-white">{vulns.length}</p>
          <p className="text-xs text-slate-500 mt-1">Всего найдено</p>
        </div>

        <div className="bg-slate-900/60 border border-red-500/20 rounded-xl p-5">
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm text-slate-400">Критических</span>
            <ShieldAlert className="w-5 h-5 text-red-500" />
          </div>
          <p className="text-3xl font-bold text-red-400">{criticalVulns.length + highVulns.length}</p>
          <p className="text-xs text-red-400/70 mt-1">Требуют внимания</p>
        </div>
      </div>

      {/* Charts Row */}
      {vulns.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Severity Distribution */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Shield className="w-5 h-5 text-blue-400" />
              Распределение по критичности
            </h3>
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                  labelStyle={{ color: '#f1f5f9' }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex flex-wrap justify-center gap-4 mt-4">
              {pieData.map((entry, index) => (
                <div key={index} className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full" style={{ backgroundColor: entry.color }} />
                  <span className="text-xs text-slate-400">{entry.name}: {entry.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Activity Chart */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <TrendingUp className="w-5 h-5 text-green-400" />
              Активность за 7 дней
            </h3>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={activityData}>
                <defs>
                  <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorVulns" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" stroke="#64748b" tick={{ fontSize: 11 }} />
                <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                  labelStyle={{ color: '#f1f5f9' }}
                />
                <Area type="monotone" dataKey="scans" stroke="#3b82f6" fillOpacity={1} fill="url(#colorScans)" name="Сканирования" />
                <Area type="monotone" dataKey="vulns" stroke="#f97316" fillOpacity={1} fill="url(#colorVulns)" name="Уязвимости" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Critical Vulnerabilities Alert */}
      {(criticalVulns.length > 0 || highVulns.length > 0) && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-2xl p-5">
          <div className="flex items-start gap-4">
            <div className="w-10 h-10 bg-red-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            <div className="flex-1">
              <h3 className="text-lg font-semibold text-red-400">Обнаружены критические уязвимости</h3>
              <p className="text-sm text-slate-400 mt-1">
                Найдено {criticalVulns.length} критических и {highVulns.length} высоких уязвимостей, требующих немедленного внимания.
              </p>
              <Link to="/app/vulnerabilities" className="inline-flex items-center text-sm text-red-400 hover:text-red-300 mt-3">
                Просмотреть все <ArrowRight className="w-4 h-4 ml-1" />
              </Link>
            </div>
          </div>
        </div>
      )}

      {/* Recent Scans */}
      <section className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex justify-between items-center">
          <h2 className="text-lg font-semibold text-white">Последние сканирования</h2>
          <Link to="/app/scans" className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1">
            Все сканирования <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
        
        {scans.length === 0 ? (
          <div className="p-12 text-center">
            <div className="w-16 h-16 bg-slate-800 rounded-full flex items-center justify-center mx-auto mb-4">
              <Search className="w-8 h-8 text-slate-500" />
            </div>
            <h3 className="text-lg font-medium text-slate-300 mb-2">Нет сканирований</h3>
            <p className="text-slate-500 mb-4">Начните первое сканирование, чтобы найти уязвимости</p>
            <Link 
              to="/app/scans"
              className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-500 transition-colors"
            >
              <Search className="w-4 h-4 mr-2" />
              Начать сканирование
            </Link>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/50">
            {scans.slice(0, 5).map((scan) => (
              <Link 
                key={scan.id} 
                to={`/app/scans/${scan.id}`}
                className="block p-4 hover:bg-slate-800/30 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {getStatusIcon(scan.status)}
                    <div>
                      <p className="font-medium text-slate-200">
                        {scan.target_name || scan.target_url || `Scan ${scan.id.slice(0, 8)}`}
                      </p>
                      {scan.target_url && (
                        <p className="text-sm text-slate-500">{scan.target_url}</p>
                      )}
                    </div>
                  </div>
                  <div className="text-right">
                    <span className={clsx(
                      "text-xs px-2 py-1 rounded-full",
                      scan.status === 'completed' ? "bg-green-500/10 text-green-400" :
                      scan.status === 'failed' ? "bg-red-500/10 text-red-400" :
                      scan.status === 'running' ? "bg-blue-500/10 text-blue-400" :
                      "bg-slate-500/10 text-slate-400"
                    )}>
                      {getStatusLabel(scan.status)}
                    </span>
                    <p className="text-xs text-slate-500 mt-1">{formatDate(scan.started_at)}</p>
                  </div>
                </div>
                {scan.status === 'running' && (
                  <div className="mt-3">
                    <div className="flex justify-between text-xs text-slate-400 mb-1">
                      <span>{scan.current_stage || 'Инициализация'}</span>
                      <span>{scan.percent_complete}%</span>
                    </div>
                    <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                      <div className="h-full bg-blue-500 transition-all duration-500" style={{ width: `${scan.percent_complete}%` }} />
                    </div>
                  </div>
                )}
                {scan.findings_count > 0 && (
                  <p className="text-xs text-amber-400 mt-2">Найдено уязвимостей: {scan.findings_count}</p>
                )}
              </Link>
            ))}
          </div>
        )}
      </section>

      {/* Recent Vulnerabilities */}
      {vulns.length > 0 && (
        <section className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
          <div className="p-5 border-b border-slate-800 flex justify-between items-center">
            <h2 className="text-lg font-semibold text-white">Последние уязвимости</h2>
            <Link to="/app/vulnerabilities" className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1">
              Все уязвимости <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
          <div className="divide-y divide-slate-800/50">
            {vulns.slice(0, 5).map((v) => (
              <Link 
                key={v.id} 
                to={`/app/vulnerabilities/${v.id}`}
                className="block p-4 hover:bg-slate-800/30 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className={clsx(
                      "px-2 py-1 text-xs font-semibold rounded border",
                      v.severity === 'critical' ? "bg-red-500/10 text-red-400 border-red-500/20" :
                      v.severity === 'high' ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
                      v.severity === 'medium' ? "bg-amber-500/10 text-amber-400 border-amber-500/20" :
                      "bg-blue-500/10 text-blue-400 border-blue-500/20"
                    )}>
                      {v.severity.toUpperCase()}
                    </span>
                    <span className="font-medium text-slate-200">{v.vulnerability_type}</span>
                  </div>
                  <span className="text-sm text-slate-500">{v.status}</span>
                </div>
              </Link>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
