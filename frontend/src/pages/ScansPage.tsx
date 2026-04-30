import { useEffect, useState, type FormEvent } from 'react';
import { listPrograms, listProgramAssets, startScan, getScanProgress } from '../services/api';
import type { ParsedProgram, Asset, ScanProgress } from '../types';
import { 
  Search, 
  Play, 
  Activity, 
  Target, 
  Layers, 
  Clock, 
  CheckCircle2, 
  XCircle,
  Loader2,
  ShieldAlert
} from 'lucide-react';
import clsx from 'clsx';

export default function ScansPage() {
  const [programs, setPrograms] = useState<ParsedProgram[]>([]);
  const [selectedProgram, setSelectedProgram] = useState('');
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selectedAsset, setSelectedAsset] = useState('');
  const [scanResult, setScanResult] = useState<ScanProgress | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listPrograms(false).then(setPrograms).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedProgram) { setAssets([]); return; }
    listProgramAssets(selectedProgram).then(setAssets).catch(() => setAssets([]));
  }, [selectedProgram]);

  const handleStartScan = async (e: FormEvent) => {
    e.preventDefault();
    if (!selectedProgram || !selectedAsset) return;
    setScanning(true);
    setError(null);
    setScanResult(null);
    try {
      const result = await startScan(selectedProgram, selectedAsset);
      setScanResult(result);
      // Poll progress
      if (result.scan_id) {
        const poll = setInterval(async () => {
          try {
            const progress = await getScanProgress(result.scan_id);
            setScanResult(progress);
            if (progress.status === 'completed' || progress.status === 'failed') {
              clearInterval(poll);
              setScanning(false);
            }
          } catch {
            clearInterval(poll);
            setScanning(false);
          }
        }, 2000);
      }
    } catch (err: unknown) {
      setError(
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Ошибка запуска сканирования',
      );
      setScanning(false);
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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold tracking-tight text-slate-100">Сканирования</h1>
        <div className="hidden sm:flex items-center text-sm text-slate-400 bg-slate-900/50 px-3 py-1.5 rounded-full border border-slate-800">
          <Activity className="w-4 h-4 mr-2 text-blue-500" />
          Готов к запуску
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Form Column */}
        <div className="lg:col-span-1">
          <section className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl p-6 shadow-sm sticky top-6">
            <h2 className="text-lg font-semibold text-slate-100 mb-6 flex items-center">
              <Play className="w-5 h-5 mr-2 text-green-500" />
              Новое сканирование
            </h2>
            
            <form onSubmit={handleStartScan} className="space-y-5">
              <div className="space-y-2">
                <label htmlFor="scan-program" className="block text-sm font-medium text-slate-300">
                  Программа
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                    <Layers className="h-4 w-4" />
                  </div>
                  <select
                    id="scan-program"
                    value={selectedProgram}
                    onChange={(e) => { setSelectedProgram(e.target.value); setSelectedAsset(''); }}
                    required
                    className="block w-full pl-9 pr-3 py-2.5 border border-slate-700 rounded-xl bg-slate-950/50 text-sm text-slate-100 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all appearance-none cursor-pointer"
                  >
                    <option value="">Выберите программу...</option>
                    {programs.map((p) => (
                      <option key={p.id} value={p.id}>{p.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="space-y-2">
                <label htmlFor="scan-asset" className="block text-sm font-medium text-slate-300">
                  Актив
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                    <Target className="h-4 w-4" />
                  </div>
                  <select
                    id="scan-asset"
                    value={selectedAsset}
                    onChange={(e) => setSelectedAsset(e.target.value)}
                    required
                    disabled={!selectedProgram}
                    className="block w-full pl-9 pr-3 py-2.5 border border-slate-700 rounded-xl bg-slate-950/50 text-sm text-slate-100 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-all appearance-none cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <option value="">Выберите актив...</option>
                    {assets.filter((a) => a.in_scope).map((a) => (
                      <option key={a.id} value={a.id}>{a.name} ({a.asset_type})</option>
                    ))}
                  </select>
                </div>
                {!selectedProgram && (
                  <p className="text-[10px] text-slate-500 ml-1 italic">Сначала выберите программу</p>
                )}
              </div>

              {error && (
                <div className="p-3 text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg animate-fade-in flex items-center">
                  <ShieldAlert className="w-4 h-4 mr-2 shrink-0" />
                  {error}
                </div>
              )}

              <button 
                type="submit" 
                disabled={scanning || !selectedAsset}
                className={clsx(
                  "w-full flex justify-center items-center py-3 px-4 rounded-xl text-sm font-bold text-white transition-all duration-200",
                  scanning || !selectedAsset
                    ? "bg-slate-800 text-slate-500 cursor-not-allowed"
                    : "bg-blue-600 hover:bg-blue-500 shadow-lg shadow-blue-500/25 active:scale-95"
                )}
              >
                {scanning ? (
                  <>
                    <Loader2 className="animate-spin -ml-1 mr-2 h-4 w-4" />
                    Сканирование...
                  </>
                ) : (
                  <>
                    <Search className="mr-2 h-4 w-4" />
                    Запустить сканер
                  </>
                )}
              </button>
            </form>
          </section>
        </div>

        {/* Progress Column */}
        <div className="lg:col-span-2">
          {scanResult ? (
            <div className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl overflow-hidden shadow-sm animate-fade-in">
              <div className="p-6 border-b border-slate-800 bg-slate-900/80 flex justify-between items-center">
                <h2 className="text-lg font-semibold text-slate-100 flex items-center">
                  <Activity className="w-5 h-5 mr-2 text-blue-500" />
                  Прогресс сканирования
                </h2>
                <span className={clsx(
                  "px-3 py-1 rounded-full text-xs font-bold border",
                  scanResult.status === 'completed' ? "bg-green-500/10 text-green-400 border-green-500/20" :
                  scanResult.status === 'failed' ? "bg-red-500/10 text-red-400 border-red-500/20" :
                  "bg-blue-500/10 text-blue-400 border-blue-500/20 animate-pulse"
                )}>
                  {getStatusLabel(scanResult.status).toUpperCase()}
                </span>
              </div>
              
              <div className="p-6 space-y-8">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
                  <div className="space-y-1">
                    <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Scan ID</p>
                    <p className="text-xs font-mono text-slate-300 truncate" title={scanResult.scan_id}>{scanResult.scan_id}</p>
                  </div>
                  <div className="space-y-1">
                    <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Текущий этап</p>
                    <p className="text-sm font-medium text-slate-100">{scanResult.current_stage || 'Инициализация'}</p>
                  </div>
                  <div className="space-y-1">
                    <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Находок</p>
                    <p className="text-lg font-bold text-amber-500">{scanResult.findings_count}</p>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="flex justify-between items-center text-sm">
                    <span className="text-slate-400 font-medium">Выполнение</span>
                    <span className="text-blue-400 font-bold">{scanResult.percent_complete}%</span>
                  </div>
                  <div className="w-full bg-slate-950 h-3 rounded-full overflow-hidden border border-slate-800 shadow-inner">
                    <div 
                      className={clsx(
                        "h-full transition-all duration-1000 ease-out shadow-[0_0_15px_rgba(59,130,246,0.5)]",
                        scanResult.status === 'failed' ? "bg-red-500" : "bg-blue-500"
                      )}
                      style={{ width: `${scanResult.percent_complete}%` }}
                    />
                  </div>
                </div>
                
                {scanResult.status === 'completed' && (
                  <div className="flex items-center p-4 bg-green-500/5 border border-green-500/10 rounded-xl text-green-400 text-sm animate-fade-in">
                    <CheckCircle2 className="w-5 h-5 mr-3 shrink-0" />
                    Сканирование успешно завершено. Все результаты доступны в разделе «Уязвимости».
                  </div>
                )}
                
                {scanResult.status === 'failed' && (
                  <div className="flex items-center p-4 bg-red-500/5 border border-red-500/10 rounded-xl text-red-400 text-sm animate-fade-in">
                    <XCircle className="w-5 h-5 mr-3 shrink-0" />
                    Произошла ошибка при сканировании. Проверьте параметры и попробуйте снова.
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="h-full min-h-[400px] bg-slate-900/30 border-2 border-slate-800 border-dashed rounded-2xl flex flex-col items-center justify-center text-center p-8">
              <div className="w-16 h-16 bg-slate-800 rounded-full flex items-center justify-center text-slate-500 mb-4 opacity-50">
                <Clock className="w-8 h-8" />
              </div>
              <h3 className="text-lg font-medium text-slate-300 mb-2">Ожидание запуска</h3>
              <p className="text-slate-500 max-w-sm">
                Выберите программу и актив в панели слева, затем нажмите кнопку запуска для начала автоматического поиска уязвимостей.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
