import { useEffect, useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { quickScan, listScans, getScanProgress } from '../services/api';
import type { ScanRecord, ScanProgress } from '../types';
import { 
  Search, 
  Play, 
  Activity, 
  Globe,
  Clock, 
  CheckCircle2, 
  XCircle,
  Loader2,
  ShieldAlert,
  RefreshCw,
  ExternalLink
} from 'lucide-react';
import clsx from 'clsx';

export default function ScansPage() {
  const [targetUrl, setTargetUrl] = useState('');
  const [scanType, setScanType] = useState('web');
  const [currentScan, setCurrentScan] = useState<(ScanProgress & { target_url?: string }) | null>(null);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Load scan history
  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    try {
      const data = await listScans(20);
      setScans(data);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  // Poll current scan progress
  useEffect(() => {
    if (!currentScan || currentScan.status === 'completed' || currentScan.status === 'failed') {
      return;
    }

    const interval = setInterval(async () => {
      try {
        const progress = await getScanProgress(currentScan.scan_id);
        setCurrentScan(prev => ({ ...prev, ...progress }));
        
        if (progress.status === 'completed' || progress.status === 'failed') {
          setScanning(false);
          loadScans(); // Refresh list
        }
      } catch {
        // ignore
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [currentScan?.scan_id, currentScan?.status]);

  const handleStartScan = async (e: FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;

    // Validate URL
    let url = targetUrl.trim();
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }

    try {
      new URL(url);
    } catch {
      setError('Введите корректный URL');
      return;
    }

    setScanning(true);
    setError(null);
    setCurrentScan(null);

    try {
      const result = await quickScan(url, scanType);
      setCurrentScan(result);
      setTargetUrl('');
    } catch (err: unknown) {
      setError(
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 
        'Ошибка запуска сканирования'
      );
      setScanning(false);
    }
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
    return date.toLocaleString('ru-RU', { 
      day: '2-digit', 
      month: '2-digit', 
      year: 'numeric',
      hour: '2-digit', 
      minute: '2-digit' 
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold tracking-tight text-slate-100">Сканирования</h1>
        <button 
          onClick={loadScans}
          className="flex items-center gap-2 px-3 py-1.5 text-sm text-slate-400 hover:text-white bg-slate-800 rounded-lg transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Обновить
        </button>
      </div>

      {/* Scan Form */}
      <section className="bg-gradient-to-br from-slate-900/80 to-slate-800/50 border border-slate-700 rounded-2xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Play className="w-5 h-5 text-green-500" />
          Новое сканирование
        </h2>

        <form onSubmit={handleStartScan} className="space-y-4">
          <div>
            <label htmlFor="target-url" className="block text-sm font-medium text-slate-300 mb-2">
              URL сайта
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                <Globe className="h-5 w-5 text-slate-500" />
              </div>
              <input
                id="target-url"
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="example.com или https://example.com"
                className="block w-full pl-12 pr-4 py-3 border border-slate-600 rounded-xl bg-slate-900/50 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all text-lg"
                disabled={scanning}
              />
            </div>
          </div>

          <div className="flex flex-wrap gap-3">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="radio"
                name="scan-type"
                value="web"
                checked={scanType === 'web'}
                onChange={(e) => setScanType(e.target.value)}
                className="w-4 h-4 text-blue-500 bg-slate-800 border-slate-600 focus:ring-blue-500"
              />
              <span className="text-sm text-slate-300">Web-приложение</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="radio"
                name="scan-type"
                value="api"
                checked={scanType === 'api'}
                onChange={(e) => setScanType(e.target.value)}
                className="w-4 h-4 text-blue-500 bg-slate-800 border-slate-600 focus:ring-blue-500"
              />
              <span className="text-sm text-slate-300">API</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="radio"
                name="scan-type"
                value="full"
                checked={scanType === 'full'}
                onChange={(e) => setScanType(e.target.value)}
                className="w-4 h-4 text-blue-500 bg-slate-800 border-slate-600 focus:ring-blue-500"
              />
              <span className="text-sm text-slate-300">Полное сканирование</span>
            </label>
          </div>

          {error && (
            <div className="p-3 text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}

          <button 
            type="submit" 
            disabled={scanning || !targetUrl.trim()}
            className={clsx(
              "w-full flex justify-center items-center py-3.5 px-4 rounded-xl text-base font-bold text-white transition-all duration-200",
              scanning || !targetUrl.trim()
                ? "bg-slate-700 text-slate-400 cursor-not-allowed"
                : "bg-blue-600 hover:bg-blue-500 shadow-lg shadow-blue-500/25 active:scale-[0.98]"
            )}
          >
            {scanning ? (
              <>
                <Loader2 className="animate-spin mr-2 h-5 w-5" />
                Сканирование...
              </>
            ) : (
              <>
                <Search className="mr-2 h-5 w-5" />
                Запустить сканирование
              </>
            )}
          </button>
        </form>
      </section>

      {/* Current Scan Progress */}
      {currentScan && (
        <section className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden animate-fade-in">
          <div className="p-5 border-b border-slate-800 flex justify-between items-center">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-blue-500" />
              Текущее сканирование
            </h2>
            <span className={clsx(
              "px-3 py-1 rounded-full text-xs font-bold border",
              currentScan.status === 'completed' ? "bg-green-500/10 text-green-400 border-green-500/20" :
              currentScan.status === 'failed' ? "bg-red-500/10 text-red-400 border-red-500/20" :
              "bg-blue-500/10 text-blue-400 border-blue-500/20 animate-pulse"
            )}>
              {getStatusLabel(currentScan.status as string)}
            </span>
          </div>
          
          <div className="p-5 space-y-4">
            {currentScan.target_url && (
              <div className="flex items-center gap-2 text-slate-300">
                <Globe className="w-4 h-4 text-slate-500" />
                <a 
                  href={currentScan.target_url} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="hover:text-blue-400 flex items-center gap-1"
                >
                  {currentScan.target_url}
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            )}

            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-slate-400">{currentScan.current_stage || 'Инициализация'}</span>
                <span className="text-blue-400 font-bold">{currentScan.percent_complete}%</span>
              </div>
              <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
                <div 
                  className={clsx(
                    "h-full transition-all duration-500",
                    currentScan.status === 'failed' ? "bg-red-500" : "bg-blue-500"
                  )}
                  style={{ width: `${currentScan.percent_complete}%` }}
                />
              </div>
            </div>

            {currentScan.findings_count > 0 && (
              <p className="text-amber-400 font-medium">
                Найдено уязвимостей: {currentScan.findings_count}
              </p>
            )}

            {currentScan.status === 'completed' && (
              <div className="flex items-center p-3 bg-green-500/5 border border-green-500/10 rounded-lg text-green-400 text-sm">
                <CheckCircle2 className="w-5 h-5 mr-2" />
                Сканирование завершено. Результаты доступны в разделе «Уязвимости».
              </div>
            )}

            {currentScan.status === 'failed' && (
              <div className="flex items-center p-3 bg-red-500/5 border border-red-500/10 rounded-lg text-red-400 text-sm">
                <XCircle className="w-5 h-5 mr-2" />
                Произошла ошибка при сканировании.
              </div>
            )}
          </div>
        </section>
      )}

      {/* Scan History */}
      <section className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="p-5 border-b border-slate-800">
          <h2 className="text-lg font-semibold text-white">История сканирований</h2>
        </div>

        {loading ? (
          <div className="p-12 text-center text-slate-400">
            <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />
            Загрузка...
          </div>
        ) : scans.length === 0 ? (
          <div className="p-12 text-center">
            <div className="w-16 h-16 bg-slate-800 rounded-full flex items-center justify-center mx-auto mb-4">
              <Clock className="w-8 h-8 text-slate-500" />
            </div>
            <h3 className="text-lg font-medium text-slate-300 mb-2">Нет сканирований</h3>
            <p className="text-slate-500">Запустите первое сканирование выше</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/50">
            {scans.map((scan) => (
              <Link 
                key={scan.id} 
                to={`/app/scans/${scan.id}`}
                className="block p-4 hover:bg-slate-800/30 transition-colors"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-3 min-w-0">
                    {getStatusIcon(scan.status)}
                    <div className="min-w-0">
                      <p className="font-medium text-slate-200 truncate">
                        {scan.target_name || scan.target_url || `Scan ${scan.id.slice(0, 8)}`}
                      </p>
                      {scan.target_url && (
                        <p className="text-sm text-slate-500 truncate">
                          {scan.target_url}
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="text-right shrink-0">
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
                  <div className="mt-3 ml-8">
                    <div className="flex justify-between text-xs text-slate-400 mb-1">
                      <span>{scan.current_stage || 'Инициализация'}</span>
                      <span>{scan.percent_complete}%</span>
                    </div>
                    <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-blue-500 transition-all"
                        style={{ width: `${scan.percent_complete}%` }}
                      />
                    </div>
                  </div>
                )}

                {scan.findings_count > 0 && (
                  <p className="text-xs text-amber-400 mt-2 ml-8">
                    Найдено уязвимостей: {scan.findings_count}
                  </p>
                )}
              </Link>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
