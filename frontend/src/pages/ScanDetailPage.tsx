import { useEffect, useState, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getScan, getScanVulnerabilities, startAIScan, getAIStatus, stopAIScan } from '../services/api';
import type { ScanRecord, Vulnerability } from '../types';
import type { AIStatusResponse } from '../services/api';
import { 
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import { 
  ArrowLeft,
  Globe,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  ShieldAlert,
  Brain,
  ExternalLink,
  AlertTriangle,
  Info,
  ChevronDown,
  ChevronUp,
  FileText,
  Shield,
  Bug,
  Zap,
  StopCircle,
  Cpu,
  Target,
  FlaskConical,
  CheckCheck
} from 'lucide-react';
import clsx from 'clsx';

const SEVERITY_CONFIG: Record<string, { label: string; color: string; bgColor: string; borderColor: string }> = {
  'critical': { label: 'Критическая', color: '#ef4444', bgColor: 'bg-red-500/10', borderColor: 'border-red-500/20' },
  'high': { label: 'Высокая', color: '#f97316', bgColor: 'bg-orange-500/10', borderColor: 'border-orange-500/20' },
  'medium': { label: 'Средняя', color: '#eab308', bgColor: 'bg-amber-500/10', borderColor: 'border-amber-500/20' },
  'low': { label: 'Низкая', color: '#3b82f6', bgColor: 'bg-blue-500/10', borderColor: 'border-blue-500/20' },
  'informational': { label: 'Инфо', color: '#6b7280', bgColor: 'bg-slate-500/10', borderColor: 'border-slate-500/20' },
};

const STATUS_MAP: Record<string, string> = {
  'pending': 'В очереди',
  'running': 'Выполняется',
  'completed': 'Завершено',
  'failed': 'Ошибка',
};

// Рекомендации по типам уязвимостей
const REMEDIATION_GUIDE: Record<string, { title: string; description: string; steps: string[]; references: string[] }> = {
  'http-missing-security-headers': {
    title: 'Отсутствующие заголовки безопасности',
    description: 'HTTP-заголовки безопасности защищают от различных атак: XSS, clickjacking, MIME-sniffing и др.',
    steps: [
      'Добавьте заголовок X-Content-Type-Options: nosniff',
      'Добавьте заголовок X-Frame-Options: DENY или SAMEORIGIN',
      'Добавьте заголовок X-XSS-Protection: 1; mode=block',
      'Настройте Content-Security-Policy (CSP)',
      'Добавьте Strict-Transport-Security для HTTPS',
      'Настройте Referrer-Policy: strict-origin-when-cross-origin',
    ],
    references: ['https://owasp.org/www-project-secure-headers/', 'https://securityheaders.com/'],
  },
  'sql_injection': {
    title: 'SQL-инъекция',
    description: 'Критическая уязвимость, позволяющая выполнять произвольные SQL-запросы к базе данных.',
    steps: [
      'Используйте параметризованные запросы (prepared statements)',
      'Применяйте ORM вместо сырых SQL-запросов',
      'Валидируйте и санитизируйте все входные данные',
      'Ограничьте права пользователя БД (принцип минимальных привилегий)',
      'Включите WAF с правилами против SQL-инъекций',
    ],
    references: ['https://owasp.org/www-community/attacks/SQL_Injection', 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
  },
  'xss': {
    title: 'Cross-Site Scripting (XSS)',
    description: 'Уязвимость позволяет внедрять вредоносный JavaScript-код на страницы сайта.',
    steps: [
      'Экранируйте все выводимые данные (HTML entities)',
      'Используйте Content-Security-Policy',
      'Применяйте HttpOnly и Secure флаги для cookies',
      'Валидируйте входные данные на сервере',
      'Используйте современные фреймворки с автоэкранированием',
    ],
    references: ['https://owasp.org/www-community/attacks/xss/', 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
  },
  'open_port': {
    title: 'Открытый порт',
    description: 'Обнаружен открытый сетевой порт. Проверьте необходимость его доступности извне.',
    steps: [
      'Проверьте, нужен ли этот порт для работы приложения',
      'Закройте неиспользуемые порты в firewall',
      'Ограничьте доступ по IP-адресам',
      'Обновите сервисы до последних версий',
      'Настройте мониторинг подозрительной активности',
    ],
    references: ['https://www.sans.org/reading-room/whitepapers/firewalls/'],
  },
  'subdomain_discovery': {
    title: 'Обнаруженный поддомен',
    description: 'Найден поддомен, который может содержать тестовые или устаревшие приложения.',
    steps: [
      'Проверьте, используется ли поддомен',
      'Удалите неиспользуемые DNS-записи',
      'Убедитесь, что все поддомены защищены HTTPS',
      'Проверьте поддомены на уязвимости',
    ],
    references: ['https://owasp.org/www-project-web-security-testing-guide/'],
  },
};

function getRemediation(vulnType: string): typeof REMEDIATION_GUIDE[string] | null {
  const lowerType = vulnType.toLowerCase();
  for (const [key, value] of Object.entries(REMEDIATION_GUIDE)) {
    if (lowerType.includes(key.replace(/-/g, '_')) || lowerType.includes(key.replace(/_/g, '-'))) {
      return value;
    }
  }
  return null;
}

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiStatus, setAiStatus] = useState<AIStatusResponse | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);
  const [expandedVulns, setExpandedVulns] = useState<Set<string>>(new Set());

  // Polling for AI status
  const pollAIStatus = useCallback(async () => {
    if (!id) return;
    try {
      const status = await getAIStatus(id);
      setAiStatus(status);
      
      // If completed or failed, refresh vulnerabilities
      if (status.status === 'completed' || status.status === 'failed' || status.status === 'cancelled') {
        const newVulns = await getScanVulnerabilities(id).catch(() => []);
        setVulns(newVulns);
      }
      
      return status;
    } catch {
      // AI analysis not started yet
      return null;
    }
  }, [id]);

  // Polling for scan status (Stage 1)
  const pollScanStatus = useCallback(async () => {
    if (!id) return;
    try {
      const scanData = await getScan(id);
      setScan(scanData);
      
      // If scan completed, refresh vulnerabilities
      if (scanData.status === 'completed' || scanData.status === 'failed') {
        const newVulns = await getScanVulnerabilities(id).catch(() => []);
        setVulns(newVulns);
      }
      
      return scanData;
    } catch {
      return null;
    }
  }, [id]);

  useEffect(() => {
    if (!id) return;
    
    Promise.all([
      getScan(id),
      getScanVulnerabilities(id).catch(() => []),
    ]).then(([scanData, vulnsData]) => {
      setScan(scanData);
      setVulns(vulnsData);
      // Check if AI analysis is running
      pollAIStatus();
    }).finally(() => {
      setLoading(false);
    });
  }, [id, pollAIStatus]);

  // Poll scan status while running (Stage 1)
  useEffect(() => {
    if (!scan || (scan.status !== 'running' && scan.status !== 'pending')) return;
    
    const interval = setInterval(async () => {
      const scanData = await pollScanStatus();
      if (scanData && (scanData.status === 'completed' || scanData.status === 'failed')) {
        clearInterval(interval);
      }
    }, 2000);
    
    return () => clearInterval(interval);
  }, [scan?.status, pollScanStatus]);

  // Poll AI status while running
  useEffect(() => {
    if (!aiStatus || aiStatus.status !== 'running') return;
    
    const interval = setInterval(async () => {
      const status = await pollAIStatus();
      if (status && (status.status === 'completed' || status.status === 'failed' || status.status === 'cancelled')) {
        clearInterval(interval);
      }
    }, 3000);
    
    return () => clearInterval(interval);
  }, [aiStatus, pollAIStatus]);

  const handleStartAI = async () => {
    if (!id) return;
    setAiLoading(true);
    setAiError(null);
    
    try {
      await startAIScan(id);
      // Start polling
      const status = await pollAIStatus();
      if (status) {
        setAiStatus(status);
      }
    } catch (err: unknown) {
      const errorMsg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 
        'Ошибка запуска ИИ-анализа';
      setAiError(errorMsg);
    } finally {
      setAiLoading(false);
    }
  };

  const handleStopAI = async () => {
    if (!id) return;
    try {
      await stopAIScan(id);
      await pollAIStatus();
    } catch (err: unknown) {
      setAiError('Ошибка остановки ИИ-анализа');
    }
  };

  const toggleVuln = (vulnId: string) => {
    setExpandedVulns(prev => {
      const next = new Set(prev);
      if (next.has(vulnId)) {
        next.delete(vulnId);
      } else {
        next.add(vulnId);
      }
      return next;
    });
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleString('ru-RU');
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle2 className="w-5 h-5 text-green-400" />;
      case 'failed': return <XCircle className="w-5 h-5 text-red-400" />;
      case 'running': return <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />;
      default: return <Clock className="w-5 h-5 text-slate-400" />;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400">
        <Loader2 className="w-6 h-6 animate-spin mr-3" />
        Загрузка...
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-20">
        <ShieldAlert className="w-16 h-16 text-slate-500 mx-auto mb-4" />
        <h2 className="text-xl font-bold text-slate-200 mb-2">Сканирование не найдено</h2>
        <Link to="/app/scans" className="text-blue-400 hover:text-blue-300">← Вернуться к списку</Link>
      </div>
    );
  }

  // Подготовка данных для графиков
  const severityCounts = vulns.reduce((acc, v) => {
    acc[v.severity] = (acc[v.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const pieData = Object.entries(severityCounts).map(([severity, count]) => ({
    name: SEVERITY_CONFIG[severity]?.label || severity,
    value: count,
    color: SEVERITY_CONFIG[severity]?.color || '#6b7280',
  }));

  // Группировка по типам уязвимостей
  const typeCounts = vulns.reduce((acc, v) => {
    const type = v.vulnerability_type.replace(/^nuclei_/, '').replace(/_/g, ' ');
    acc[type] = (acc[type] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const barData = Object.entries(typeCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([type, count]) => ({ type: type.length > 25 ? type.slice(0, 25) + '...' : type, count }));

  const criticalVulns = vulns.filter(v => v.severity === 'critical' || v.severity === 'high');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link to="/app/scans" className="p-2 hover:bg-slate-800 rounded-lg transition-colors">
          <ArrowLeft className="w-5 h-5 text-slate-400" />
        </Link>
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-slate-100">
            {scan.target_name || scan.target_url || `Сканирование ${scan.id.slice(0, 8)}`}
          </h1>
          {scan.target_url && (
            <a href={scan.target_url} target="_blank" rel="noopener noreferrer"
               className="text-slate-400 hover:text-blue-400 flex items-center gap-1 text-sm mt-1">
              <Globe className="w-4 h-4" />{scan.target_url}<ExternalLink className="w-3 h-3" />
            </a>
          )}
        </div>
        <div className="flex items-center gap-2">
          {getStatusIcon(scan.status)}
          <span className={clsx(
            "px-3 py-1 rounded-full text-sm font-medium",
            scan.status === 'completed' ? "bg-green-500/10 text-green-400" :
            scan.status === 'failed' ? "bg-red-500/10 text-red-400" :
            scan.status === 'running' ? "bg-blue-500/10 text-blue-400" : "bg-slate-500/10 text-slate-400"
          )}>
            {STATUS_MAP[scan.status] || scan.status}
          </span>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Начало</p>
          <p className="text-sm text-slate-200">{formatDate(scan.started_at)}</p>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Завершение</p>
          <p className="text-sm text-slate-200">{formatDate(scan.completed_at)}</p>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Этап</p>
          <p className="text-sm text-slate-200">{scan.current_stage || '—'}</p>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Прогресс</p>
          <p className="text-sm text-slate-200">{scan.percent_complete}%</p>
        </div>
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Найдено</p>
          <p className="text-sm text-amber-400 font-bold">{vulns.length} уязвимостей</p>
        </div>
      </div>

      {/* Charts Section */}
      {vulns.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Pie Chart - Severity Distribution */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Shield className="w-5 h-5 text-blue-400" />
              Распределение по критичности
            </h3>
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={2}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                  labelLine={false}
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                  labelStyle={{ color: '#f1f5f9' }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Bar Chart - Vulnerability Types */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Bug className="w-5 h-5 text-amber-400" />
              Типы уязвимостей (топ-10)
            </h3>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={barData} layout="vertical" margin={{ left: 20, right: 20 }}>
                <XAxis type="number" stroke="#64748b" />
                <YAxis type="category" dataKey="type" stroke="#64748b" width={120} tick={{ fontSize: 11 }} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                  labelStyle={{ color: '#f1f5f9' }}
                />
                <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Severity Summary Cards */}
      {vulns.length > 0 && (
        <div className="grid grid-cols-5 gap-4">
          {['critical', 'high', 'medium', 'low', 'informational'].map(severity => {
            const count = severityCounts[severity] || 0;
            const config = SEVERITY_CONFIG[severity];
            return (
              <div key={severity} className={clsx("border rounded-xl p-4 text-center", config.bgColor, config.borderColor)}>
                <p className="text-3xl font-bold" style={{ color: config.color }}>{count}</p>
                <p className="text-xs uppercase tracking-wider" style={{ color: config.color }}>{config.label}</p>
              </div>
            );
          })}
        </div>
      )}

      {/* AI Analysis Button */}
      {scan.status === 'completed' && vulns.length > 0 && (
        <div className="flex gap-4">
          {/* Summary Report Button */}
          <Link
            to={`/app/scans/${id}/report`}
            className="flex-1 bg-gradient-to-r from-green-900/30 to-emerald-900/30 border border-green-500/30 rounded-xl p-6 hover:from-green-900/40 hover:to-emerald-900/40 transition-all"
          >
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-green-500/20 rounded-xl flex items-center justify-center">
                <FileText className="w-6 h-6 text-green-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white">Сводный отчёт</h3>
                <p className="text-slate-400 text-sm">Полный отчёт для печати и экспорта</p>
              </div>
            </div>
          </Link>

          {/* AI Analysis */}
          <div className="flex-1 bg-gradient-to-r from-purple-900/30 to-blue-900/30 border border-purple-500/30 rounded-xl p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center">
                  <Brain className="w-6 h-6 text-purple-400" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white">ИИ-анализ (Stage 2)</h3>
                  <p className="text-slate-400 text-sm">Глубокий анализ с генерацией PoC</p>
                </div>
              </div>
              
              {/* Buttons based on AI status */}
              {aiStatus?.status === 'running' ? (
                <button onClick={handleStopAI}
                  className="px-6 py-3 rounded-xl font-medium transition-all flex items-center gap-2 bg-red-600 text-white hover:bg-red-500">
                  <StopCircle className="w-5 h-5" />Остановить
                </button>
              ) : (
                <button onClick={handleStartAI} disabled={aiLoading}
                  className={clsx(
                    "px-6 py-3 rounded-xl font-medium transition-all flex items-center gap-2",
                    aiLoading ? "bg-slate-700 text-slate-400 cursor-not-allowed" 
                             : "bg-purple-600 text-white hover:bg-purple-500 shadow-lg shadow-purple-500/25"
                  )}>
                  {aiLoading ? <><Loader2 className="w-5 h-5 animate-spin" />Запуск...</> 
                            : <><Brain className="w-5 h-5" />Запустить</>}
                </button>
              )}
            </div>
            
            {/* AI Status Display */}
            {aiStatus && aiStatus.status !== 'not_started' && (
              <div className="mt-4 space-y-3">
                {/* Progress bar */}
                {aiStatus.status === 'running' && (
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-400">
                        Фаза: <span className="text-purple-400">{aiStatus.current_phase}</span>
                      </span>
                      <span className="text-purple-400">{aiStatus.percent_complete}%</span>
                    </div>
                    <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-purple-500 to-blue-500 transition-all duration-500"
                        style={{ width: `${aiStatus.percent_complete}%` }}
                      />
                    </div>
                  </div>
                )}
                
                {/* Stats grid */}
                <div className="grid grid-cols-3 gap-3">
                  <div className="bg-slate-800/50 rounded-lg p-3 text-center">
                    <Cpu className="w-4 h-4 text-blue-400 mx-auto mb-1" />
                    <p className="text-lg font-bold text-white">{aiStatus.stats.technologies_found}</p>
                    <p className="text-xs text-slate-500">Технологий</p>
                  </div>
                  <div className="bg-slate-800/50 rounded-lg p-3 text-center">
                    <FlaskConical className="w-4 h-4 text-amber-400 mx-auto mb-1" />
                    <p className="text-lg font-bold text-white">
                      {aiStatus.stats.hypotheses_tested}/{aiStatus.stats.hypotheses_generated}
                    </p>
                    <p className="text-xs text-slate-500">Гипотез</p>
                  </div>
                  <div className="bg-slate-800/50 rounded-lg p-3 text-center">
                    <Target className="w-4 h-4 text-green-400 mx-auto mb-1" />
                    <p className="text-lg font-bold text-white">{aiStatus.stats.findings_confirmed}</p>
                    <p className="text-xs text-slate-500">Подтверждено</p>
                  </div>
                </div>
                
                {/* Status message */}
                {aiStatus.status === 'completed' && (
                  <div className="flex items-center gap-2 text-green-400 text-sm">
                    <CheckCheck className="w-4 h-4" />
                    Анализ завершён. Найдено {aiStatus.stats.findings_confirmed} новых уязвимостей.
                  </div>
                )}
                {aiStatus.status === 'failed' && (
                  <div className="flex items-center gap-2 text-red-400 text-sm">
                    <XCircle className="w-4 h-4" />
                    Анализ завершился с ошибкой
                  </div>
                )}
                {aiStatus.status === 'cancelled' && (
                  <div className="flex items-center gap-2 text-amber-400 text-sm">
                    <StopCircle className="w-4 h-4" />
                    Анализ остановлен пользователем
                  </div>
                )}
                
                {/* AI Findings preview */}
                {aiStatus.ai_findings && aiStatus.ai_findings.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-slate-700">
                    <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">
                      Найденные AI уязвимости
                    </p>
                    <div className="space-y-2 max-h-40 overflow-y-auto">
                      {aiStatus.ai_findings.map(f => (
                        <div key={f.id} className="flex items-center gap-2 text-sm">
                          <span className={clsx(
                            "px-2 py-0.5 text-xs rounded",
                            f.severity === 'critical' ? "bg-red-500/20 text-red-400" :
                            f.severity === 'high' ? "bg-orange-500/20 text-orange-400" :
                            f.severity === 'medium' ? "bg-amber-500/20 text-amber-400" :
                            "bg-blue-500/20 text-blue-400"
                          )}>
                            {f.severity}
                          </span>
                          <span className="text-slate-300 truncate">{f.vulnerability_type}</span>
                          <span className="text-slate-500 text-xs">({Math.round(f.confidence * 100)}%)</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
            
            {/* Error message */}
            {aiError && (
              <p className="mt-4 text-sm text-red-400 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" />
                {aiError}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Critical/High Vulnerabilities with Detailed Remediation */}
      {criticalVulns.length > 0 && (
        <section className="bg-slate-900/60 border border-red-500/20 rounded-2xl overflow-hidden">
          <div className="p-5 border-b border-slate-800 bg-red-500/5">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              Критические и высокие уязвимости ({criticalVulns.length})
            </h2>
            <p className="text-sm text-slate-400 mt-1">Требуют немедленного внимания</p>
          </div>
          <div className="divide-y divide-slate-800/50">
            {criticalVulns.map((v) => {
              const isExpanded = expandedVulns.has(v.id);
              const config = SEVERITY_CONFIG[v.severity];
              const remediation = getRemediation(v.vulnerability_type);
              
              return (
                <div key={v.id} className="p-4">
                  <div 
                    className="flex items-center justify-between cursor-pointer"
                    onClick={() => toggleVuln(v.id)}
                  >
                    <div className="flex items-center gap-3">
                      <span className={clsx(
                        "flex items-center gap-1.5 px-2.5 py-1 text-xs font-bold rounded-md border",
                        config.bgColor, config.borderColor
                      )} style={{ color: config.color }}>
                        <Zap className="w-3 h-3" />
                        {config.label}
                      </span>
                      <span className="font-medium text-slate-200">{v.vulnerability_type}</span>
                    </div>
                    {isExpanded ? <ChevronUp className="w-5 h-5 text-slate-500" /> 
                                : <ChevronDown className="w-5 h-5 text-slate-500" />}
                  </div>

                  {isExpanded && (
                    <div className="mt-4 space-y-4 pl-4 border-l-2 border-slate-700">
                      <div>
                        <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-2">Описание</h4>
                        <p className="text-slate-300 text-sm">{v.description}</p>
                      </div>
                      
                      {v.evidence && (
                        <div>
                          <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-2">Доказательства</h4>
                          <pre className="text-slate-300 text-sm bg-slate-950 p-3 rounded-lg overflow-x-auto">
                            {v.evidence}
                          </pre>
                        </div>
                      )}

                      {/* Detailed Remediation Guide */}
                      {remediation && (
                        <div className="bg-green-500/5 border border-green-500/20 rounded-xl p-4">
                          <h4 className="text-sm font-semibold text-green-400 mb-2 flex items-center gap-2">
                            <FileText className="w-4 h-4" />
                            {remediation.title} — Рекомендации по устранению
                          </h4>
                          <p className="text-slate-400 text-sm mb-3">{remediation.description}</p>
                          <ol className="list-decimal list-inside space-y-2 text-sm text-slate-300">
                            {remediation.steps.map((step, i) => (
                              <li key={i}>{step}</li>
                            ))}
                          </ol>
                          {remediation.references.length > 0 && (
                            <div className="mt-3 pt-3 border-t border-green-500/20">
                              <p className="text-xs text-slate-500 mb-1">Ссылки:</p>
                              {remediation.references.map((ref, i) => (
                                <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                                   className="text-xs text-blue-400 hover:text-blue-300 block">
                                  {ref}
                                </a>
                              ))}
                            </div>
                          )}
                        </div>
                      )}

                      <Link to={`/app/vulnerabilities/${v.id}`}
                        className="inline-flex items-center px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-500 transition-colors">
                        Полный отчёт
                      </Link>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* All Vulnerabilities List */}
      <section className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-5 border-b border-slate-800">
          <h2 className="text-lg font-semibold text-white">Все уязвимости ({vulns.length})</h2>
        </div>

        {vulns.length === 0 ? (
          <div className="p-12 text-center">
            <ShieldAlert className="w-12 h-12 text-slate-500 mx-auto mb-4" />
            <p className="text-slate-400">Уязвимости не найдены</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/50 max-h-[600px] overflow-y-auto">
            {vulns.map((v) => {
              const config = SEVERITY_CONFIG[v.severity] || SEVERITY_CONFIG['informational'];
              return (
                <div key={v.id} className="p-4 hover:bg-slate-800/30 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className={clsx(
                        "px-2 py-1 text-xs font-bold rounded border",
                        config.bgColor, config.borderColor
                      )} style={{ color: config.color }}>
                        {config.label}
                      </span>
                      <span className="font-medium text-slate-200 text-sm">{v.vulnerability_type}</span>
                    </div>
                    <Link to={`/app/vulnerabilities/${v.id}`} 
                      className="text-xs text-blue-400 hover:text-blue-300">
                      Подробнее →
                    </Link>
                  </div>
                  <p className="text-xs text-slate-500 mt-2 line-clamp-2">{v.description}</p>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
