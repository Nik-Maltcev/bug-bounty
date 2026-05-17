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
  ShieldAlert
} from 'lucide-react';
import clsx from 'clsx';

export default function ReportsPage() {
  const [reports, setReports] = useState<ScanReportData[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState<string | null>(null);

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

  const handleDownloadPdf = async (report: ScanReportData) => {
    setDownloading(report.id);
    try {
      const blob = await downloadScanReportPdf(report.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report_${report.target_url.replace(/https?:\/\//, '').replace(/\//g, '_')}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
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

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleString('ru-RU', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
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
        <span className="text-sm text-slate-500">{reports.length} отчётов</span>
      </div>

      {reports.length === 0 ? (
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-12 text-center">
          <div className="w-16 h-16 bg-slate-800 rounded-full flex items-center justify-center mx-auto mb-4">
            <FileText className="w-8 h-8 text-slate-500" />
          </div>
          <h3 className="text-lg font-medium text-slate-300 mb-2">Нет отчётов</h3>
          <p className="text-slate-500">Отчёты создаются автоматически после AI-анализа сканирований</p>
        </div>
      ) : (
        <div className="grid gap-4">
          {reports.map((report) => (
            <div
              key={report.id}
              className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 hover:border-slate-700 transition-colors"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <FileText className="w-5 h-5 text-blue-400 shrink-0" />
                    <h3 className="text-lg font-semibold text-white truncate">{report.title}</h3>
                    <span className={clsx(
                      "text-xs px-2 py-0.5 rounded-full shrink-0",
                      report.status === 'final' ? "bg-green-500/10 text-green-400" : "bg-yellow-500/10 text-yellow-400"
                    )}>
                      {report.status === 'final' ? 'Финальный' : 'Черновик'}
                    </span>
                  </div>
                  
                  <div className="flex flex-wrap items-center gap-4 text-sm text-slate-400">
                    {report.target_url && (
                      <span className="flex items-center gap-1">
                        <Globe className="w-3.5 h-3.5" />
                        {report.target_url}
                      </span>
                    )}
                    {report.category && (
                      <span className="flex items-center gap-1">
                        <Tag className="w-3.5 h-3.5" />
                        {report.category}
                      </span>
                    )}
                    {report.findings_count > 0 && (
                      <span className="flex items-center gap-1 text-amber-400">
                        <ShieldAlert className="w-3.5 h-3.5" />
                        {report.findings_count} уязвимостей
                      </span>
                    )}
                    <span className="flex items-center gap-1">
                      <Calendar className="w-3.5 h-3.5" />
                      {formatDate(report.created_at)}
                    </span>
                  </div>

                  {report.executive_summary && (
                    <p className="mt-3 text-sm text-slate-400 line-clamp-2">
                      {report.executive_summary}
                    </p>
                  )}
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <Link
                    to={`/app/reports/${report.id}`}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-blue-400 hover:text-blue-300 bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/20 rounded-lg transition-colors"
                  >
                    <Edit3 className="w-4 h-4" />
                    Редактировать
                  </Link>
                  <button
                    onClick={() => handleDownloadPdf(report)}
                    disabled={downloading === report.id}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-green-400 hover:text-green-300 bg-green-500/10 hover:bg-green-500/20 border border-green-500/20 rounded-lg transition-colors disabled:opacity-50"
                  >
                    {downloading === report.id ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Download className="w-4 h-4" />
                    )}
                    PDF
                  </button>
                  <button
                    onClick={() => handleDelete(report.id)}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-red-400 hover:text-red-300 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 rounded-lg transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
