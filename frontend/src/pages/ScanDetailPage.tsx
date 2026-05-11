import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getScan, getScanVulnerabilities, startAIScan } from '../services/api';
import type { ScanRecord, Vulnerability } from '../types';
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
  ChevronRight
} from 'lucide-react';
import clsx from 'clsx';

const SEVERITY_MAP: Record<string, string> = {
  'critical': 'Критическая',
  'high': 'Высокая',
  'medium': 'Средняя',
  'low': 'Низкая',
  'informational': 'Инфо'
};

const STATUS_MAP: Record<string, string> = {
  'pending': 'В очереди',
  'running': 'Выполняется',
  'completed': 'Завершено',
  'failed': 'Ошибка',
};

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiStatus, setAiStatus] = useState<string | null>(null);
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);

  useEffect(() => {
    if (!id) return;
    
    Promise.all([
      getScan(id),
      getScanVulnerabilities(id).catch(() => []),
    ]).then(([scanData, vulnsData]) => {
      setScan(scanData);
      setVulns(vulnsData);
    }).catch(() => {
      // Handle error
    }).finally(() => {
      setLoading(false);
    });
  }, [id]);

  const handleStartAI = async () => {
    if (!id) return;
    setAiLoading(true);
    setAiStatus(null);
    
    try {
      const result = await startAIScan(id);
      setAiStatus(result.message || 'ИИ-анализ запущен');
      // Reload vulnerabilities after a delay
      setTimeout(async () => {
        const newVulns = await getScanVulnerabilities(id).catch(() => []);
        setVulns(newVulns);
      }, 5000);
    } catch (err: unknown) {
      setAiStatus(
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 
        'Ошибка запуска ИИ-анализа'
      );
    } finally {
      setAiLoading(false);
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleString('ru-RU');
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle2 className="w-5 h-5 text-green-400" />;
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-400" />;
      case 'running':
        return <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />;
      default:
        return <Clock className="w-5 h-5 text-slate-400" />;
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return <AlertTriangle className="w-4 h-4" />;
      case 'medium':
        return <ShieldAlert className="w-4 h-4" />;
      default:
        return <Info className="w-4 h-4" />;
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
        <Link to="/app/scans" className="text-blue-400 hover:text-blue-300">
          ← Вернуться к списку
        </Link>
      </div>
    );
  }

  const criticalCount = vulns.filter(v => v.severity === 'critical').length;
  const highCount = vulns.filter(v => v.severity === 'high').length;
  const mediumCount = vulns.filter(v => v.severity === 'medium').length;
  const lowCount = vulns.filter(v => v.severity === 'low' || v.severity === 'informational').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link 
          to="/app/scans" 
          className="p-2 hover:bg-slate-800 rounded-lg transition-colors"
        >
          <ArrowLeft className="w-5 h-5 text-slate-400" />
        </Link>
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-slate-100">
            {scan.target_name || scan.target_url || `Сканирование ${scan.id.slice(0, 8)}`}
          </h1>
          {scan.target_url && (
            <a 
              href={scan.target_url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-400 hover:text-blue-400 flex items-center gap-1 text-sm mt-1"
            >
              <Globe className="w-4 h-4" />
              {scan.target_url}
              <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </div>
        <div className="flex items-center gap-2">
          {getStatusIcon(scan.status)}
          <span className={clsx(
            "px-3 py-1 rounded-full text-sm font-medium",
            scan.status === 'completed' ? "bg-green-500/10 text-green-400" :
            scan.status === 'failed' ? "bg-red-500/10 text-red-400" :
            scan.status === 'running' ? "bg-blue-500/10 text-blue-400" :
            "bg-slate-500/10 text-slate-400"
          )}>
            {STATUS_MAP[scan.status] || scan.status}
          </span>
        </div>
      </div>

      {/* Stats */}
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

      {/* AI Analysis Button */}
      {scan.status === 'completed' && vulns.length > 0 && (
        <div className="bg-gradient-to-r from-purple-900/30 to-blue-900/30 border border-purple-500/30 rounded-xl p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center">
                <Brain className="w-6 h-6 text-purple-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white">ИИ-анализ (Stage 2)</h3>
                <p className="text-slate-400 text-sm">
                  Глубокий анализ найденных уязвимостей с генерацией PoC
                </p>
              </div>
            </div>
            <button
              onClick={handleStartAI}
              disabled={aiLoading}
              className={clsx(
                "px-6 py-3 rounded-xl font-medium transition-all flex items-center gap-2",
                aiLoading
                  ? "bg-slate-700 text-slate-400 cursor-not-allowed"
                  : "bg-purple-600 text-white hover:bg-purple-500 shadow-lg shadow-purple-500/25"
              )}
            >
              {aiLoading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Анализирую...
                </>
              ) : (
                <>
                  <Brain className="w-5 h-5" />
                  Запустить ИИ-анализ
                </>
              )}
            </button>
          </div>
          {aiStatus && (
            <p className={clsx(
              "mt-4 text-sm",
              aiStatus.includes('Ошибка') ? "text-red-400" : "text-green-400"
            )}>
              {aiStatus}
            </p>
          )}
        </div>
      )}

      {/* Vulnerabilities Summary */}
      {vulns.length > 0 && (
        <div className="grid grid-cols-4 gap-4">
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 text-center">
            <p className="text-3xl font-bold text-red-400">{criticalCount}</p>
            <p className="text-xs text-red-400/70 uppercase tracking-wider">Критических</p>
          </div>
          <div className="bg-orange-500/10 border border-orange-500/20 rounded-xl p-4 text-center">
            <p className="text-3xl font-bold text-orange-400">{highCount}</p>
            <p className="text-xs text-orange-400/70 uppercase tracking-wider">Высоких</p>
          </div>
          <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl p-4 text-center">
            <p className="text-3xl font-bold text-amber-400">{mediumCount}</p>
            <p className="text-xs text-amber-400/70 uppercase tracking-wider">Средних</p>
          </div>
          <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-4 text-center">
            <p className="text-3xl font-bold text-blue-400">{lowCount}</p>
            <p className="text-xs text-blue-400/70 uppercase tracking-wider">Низких</p>
          </div>
        </div>
      )}

      {/* Vulnerabilities List */}
      <section className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-5 border-b border-slate-800">
          <h2 className="text-lg font-semibold text-white">Найденные уязвимости</h2>
        </div>

        {vulns.length === 0 ? (
          <div className="p-12 text-center">
            <ShieldAlert className="w-12 h-12 text-slate-500 mx-auto mb-4" />
            <p className="text-slate-400">Уязвимости не найдены</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/50">
            {vulns.map((v) => (
              <div 
                key={v.id} 
                className="p-4 hover:bg-slate-800/30 transition-colors cursor-pointer"
                onClick={() => setSelectedVuln(selectedVuln?.id === v.id ? null : v)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className={clsx(
                      "flex items-center gap-1.5 px-2.5 py-1 text-xs font-bold rounded-md border",
                      v.severity === 'critical' ? "bg-red-500/10 text-red-400 border-red-500/20" :
                      v.severity === 'high' ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
                      v.severity === 'medium' ? "bg-amber-500/10 text-amber-400 border-amber-500/20" :
                      "bg-blue-500/10 text-blue-400 border-blue-500/20"
                    )}>
                      {getSeverityIcon(v.severity)}
                      {SEVERITY_MAP[v.severity] || v.severity}
                    </span>
                    <span className="font-medium text-slate-200">{v.vulnerability_type}</span>
                  </div>
                  <ChevronRight className={clsx(
                    "w-5 h-5 text-slate-500 transition-transform",
                    selectedVuln?.id === v.id && "rotate-90"
                  )} />
                </div>

                {/* Expanded Details */}
                {selectedVuln?.id === v.id && (
                  <div className="mt-4 space-y-4 animate-fade-in">
                    <div>
                      <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-1">Описание</h4>
                      <p className="text-slate-300 text-sm">{v.description}</p>
                    </div>
                    
                    {v.steps_to_reproduce && (
                      <div>
                        <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-1">Шаги воспроизведения</h4>
                        <pre className="text-slate-300 text-sm bg-slate-950 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap">
                          {v.steps_to_reproduce}
                        </pre>
                      </div>
                    )}

                    {v.evidence && (
                      <div>
                        <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-1">Доказательства</h4>
                        <pre className="text-slate-300 text-sm bg-slate-950 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap">
                          {v.evidence}
                        </pre>
                      </div>
                    )}

                    {v.impact_assessment && (
                      <div>
                        <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-1">Оценка влияния</h4>
                        <p className="text-slate-300 text-sm">{v.impact_assessment}</p>
                      </div>
                    )}

                    {v.remediation && (
                      <div>
                        <h4 className="text-xs text-slate-500 uppercase tracking-wider mb-1">Рекомендации</h4>
                        <p className="text-slate-300 text-sm">{v.remediation}</p>
                      </div>
                    )}

                    <div className="flex gap-2 pt-2">
                      <Link
                        to={`/app/vulnerabilities/${v.id}`}
                        className="px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-500 transition-colors"
                      >
                        Подробнее
                      </Link>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
