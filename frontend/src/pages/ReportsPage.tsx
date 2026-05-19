import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { listScanReports, deleteScanReport, downloadScanReportPdf } from '../services/api';
import type { ScanReportData } from '../services/api';
import { 
  FileText, 
  Download, 
  Trash2, 
  Edit3, 
  Loader2, 
  Globe,
  Calendar,
  Tag,
  ShieldAlert,
  ChevronDown,
  ChevronRight,
  Lock,
  Unlock,
  Eye
} from 'lucide-react';
import clsx from 'clsx';

interface GroupedReports {
  target_url: string;
  category: string;
  scan_id: string;
  reports: ScanReportData[];
  created_at: string | null;
}

export default function ReportsPage() {
  const [reports, setReports] = useState<ScanReportData[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());

  useEffect(() => {
    loadReports();
  }, []);

  const loadReports = async () => {
    try {
      const data = await listScanReports();
      setReports(data);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  // Группируем отчёты по scan_id (компании)
  const grouped: GroupedReports[] = [];
  const scanMap = new Map<string, ScanReportData[]>();
  
  for (const r of reports) {
    const key = r.scan_id;
    if (!scanMap.has(key)) scanMap.set(key, []);
    scanMap.get(key)!.push(r);
  }
  
  for (const [scanId, reps] of scanMap) {
    const first = reps[0];
    grouped.push({
      target_url: first.target_url,
      category: first.category,
      scan_id: scanId,
      reports: reps.sort((a, b) => {
        const order = { full: 0, medium: 1, demo: 2 };
        return (order[a.report_type as keyof typeof order] ?? 3) - (order[b.report_type as keyof typeof order] ?? 3);
      }),
      created_at: first.created_at,
    });
  }

  // Сортируем по дате (новые сверху)
  grouped.sort((a, b) => {
    if (!a.created_at) return 1;
    if (!b.created_at) return -1;
    return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
  });

  const toggleGroup = (scanId: string) => {
    const next = new Set(expandedGroups);
    if (next.has(scanId)) next.delete(scanId);
    else next.add(scanId);
    setExpandedGroups(next);
  };

  const handleDownloadPdf = async (report: ScanReportData) => {
    setDownloading(report.id);
    try {
      const blob = await downloadScanReportPdf(report.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report_${report.report_type}_${report.target_url.replace(/https?:\/\//, '').replace(/\//g, '_')}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      alert('Ошибка скачивания PDF');
    } finally {
      setDownloading(null);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Удалить отчёт?')) return;
    try {
      await deleteScanReport(id);
      setReports(reports.filter(r => r.id !== id));
    } catch {
      alert('Ошибка удаления');
    }
  };

  const getReportTypeInfo = (type: string) => {
    switch (type) {
      case 'full':
        return { label: 'Полный', icon: Unlock, color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/20', desc: 'Все детали + инструкции по устранению' };
      case 'medium':
        return { label: 'Технический', icon: Eye, color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20', desc: 'Уязвимости видны, без инструкций' };
      case 'demo':
        return { label: 'Демо', icon: Lock, color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/20', desc: 'Только статистика и риски' };
      default:
        return { label: type, icon: FileText, color: 'text-slate-400', bg: 'bg-slate-500/10 border-slate-500/20', desc: '' };
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleString('ru-RU', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 animate-pulse">
        <Loader2 className="w-6 h-6 mr-3 animate-spin" />
        Загрузка отчётов...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold tracking-tight text-slate-100">Отчёты</h1>
        <span className="text-sm text-slate-500">{grouped.length} компаний • {reports.length} отчётов</span>
      </div>

      {grouped.length === 0 ? (
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-12 text-center">
          <div className="w-16 h-16 bg-slate-800 rounded-full flex items-center justify-center mx-auto mb-4">
            <FileText className="w-8 h-8 text-slate-500" />
          </div>
          <h3 className="text-lg font-medium text-slate-300 mb-2">Нет отчётов</h3>
          <p className="text-slate-500">Отчёты создаются автоматически после AI-анализа сканирований</p>
        </div>
      ) : (
        <div className="space-y-3">
          {grouped.map((group) => (
            <div key={group.scan_id} className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
              {/* Company header */}
              <button
                onClick={() => toggleGroup(group.scan_id)}
                className="w-full flex items-center justify-between p-5 hover:bg-slate-800/30 transition-colors text-left"
              >
                <div className="flex items-center gap-3 min-w-0">
                  {expandedGroups.has(group.scan_id) ? (
                    <ChevronDown className="w-5 h-5 text-slate-400 shrink-0" />
                  ) : (
                    <ChevronRight className="w-5 h-5 text-slate-400 shrink-0" />
                  )}
                  <Globe className="w-5 h-5 text-blue-400 shrink-0" />
                  <div className="min-w-0">
                    <p className="font-semibold text-white truncate">{group.target_url || 'Неизвестный сайт'}</p>
                    <div className="flex items-center gap-3 text-xs text-slate-500 mt-0.5">
                      {group.category && (
                        <span className="flex items-center gap-1">
                          <Tag className="w-3 h-3" />
                          {group.category}
                        </span>
                      )}
                      <span className="flex items-center gap-1">
                        <Calendar className="w-3 h-3" />
                        {formatDate(group.created_at)}
                      </span>
                      <span>{group.reports.length} отчётов</span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {group.reports.map(r => {
                    const info = getReportTypeInfo(r.report_type);
                    return (
                      <span key={r.id} className={clsx("text-xs px-2 py-0.5 rounded-full border", info.bg, info.color)}>
                        {info.label}
                      </span>
                    );
                  })}
                </div>
              </button>

              {/* Expanded: report variants */}
              {expandedGroups.has(group.scan_id) && (
                <div className="border-t border-slate-800 divide-y divide-slate-800/50">
                  {group.reports.map((report) => {
                    const info = getReportTypeInfo(report.report_type);
                    const Icon = info.icon;
                    return (
                      <div key={report.id} className="p-4 pl-14 flex items-center justify-between gap-4 hover:bg-slate-800/20 transition-colors">
                        <div className="flex items-center gap-3 min-w-0">
                          <Icon className={clsx("w-5 h-5 shrink-0", info.color)} />
                          <div className="min-w-0">
                            <p className="font-medium text-slate-200">{info.label} отчёт</p>
                            <p className="text-xs text-slate-500">{info.desc}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <Link
                            to={`/app/reports/${report.id}`}
                            className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-blue-400 hover:text-blue-300 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/20 rounded-lg transition-colors"
                          >
                            <Edit3 className="w-3.5 h-3.5" />
                            Открыть
                          </Link>
                          <button
                            onClick={() => handleDownloadPdf(report)}
                            disabled={downloading === report.id}
                            className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-green-400 hover:text-green-300 bg-green-500/10 hover:bg-green-500/20 border border-green-500/20 rounded-lg transition-colors disabled:opacity-50"
                          >
                            {downloading === report.id ? (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                              <Download className="w-3.5 h-3.5" />
                            )}
                            PDF
                          </button>
                          <button
                            onClick={() => handleDelete(report.id)}
                            className="p-1.5 text-red-400 hover:text-red-300 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 rounded-lg transition-colors"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
