import { useEffect, useState } from 'react';
import { listVulnerabilities, generateReport, exportReport } from '../services/api';
import type { Vulnerability, Report } from '../types';
import { 
  FileText, 
  FilePlus, 
  Download, 
  Eye, 
  Copy, 
  Check, 
  Activity, 
  Search,
  ChevronRight,
  Loader2,
  FileCode
} from 'lucide-react';
import clsx from 'clsx';

export default function ReportsPage() {
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [generating, setGenerating] = useState<string | null>(null);
  const [markdownPreview, setMarkdownPreview] = useState<{ id: string; md: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    listVulnerabilities().then(setVulns).catch(() => {}).finally(() => setLoading(false));
  }, []);

  const handleGenerate = async (vulnId: string) => {
    setGenerating(vulnId);
    try {
      const report = await generateReport(vulnId);
      setReports((prev) => [report, ...prev]);
    } catch {
      alert('Не удалось создать отчёт');
    }
    setGenerating(null);
  };

  const handlePreviewMd = async (reportId: string) => {
    try {
      const md = await exportReport(reportId, 'md');
      setMarkdownPreview({ id: reportId, md: md as string });
    } catch {
      alert('Ошибка при экспорте Markdown');
    }
  };

  const handleExportPdf = async (reportId: string) => {
    try {
      const blob = await exportReport(reportId, 'pdf');
      const url = URL.createObjectURL(blob as Blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report-${reportId}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      alert('Ошибка при экспорте PDF');
    }
  };

  const copyToClipboard = () => {
    if (markdownPreview) {
      navigator.clipboard.writeText(markdownPreview.md);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const filteredVulns = vulns.filter(v => 
    v.vulnerability_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
    v.description.toLowerCase().includes(searchQuery.toLowerCase())
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 animate-pulse">
        <Activity className="w-6 h-6 mr-3 animate-spin" />
        Загрузка отчётов...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold tracking-tight text-slate-100">Отчёты</h1>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 items-start">
        {/* Reports List */}
        <section className="space-y-6 order-2 xl:order-1">
          {reports.length > 0 && (
            <div className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl shadow-sm overflow-hidden animate-fade-in">
              <div className="p-6 border-b border-slate-800 bg-slate-900/80">
                <h3 className="text-lg font-semibold text-slate-100 flex items-center">
                  <FileText className="w-5 h-5 mr-2 text-blue-500" /> Сгенерированные отчёты ({reports.length})
                </h3>
              </div>
              <div className="p-0 overflow-x-auto">
                <table className="w-full text-left text-sm whitespace-nowrap">
                  <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-widest font-bold">
                    <tr>
                      <th className="px-6 py-4">Уровень</th>
                      <th className="px-6 py-4">Заголовок</th>
                      <th className="px-6 py-4 text-right">Действия</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {reports.map((r) => (
                      <tr key={r.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="px-6 py-4">
                          <span className={clsx(
                            "px-2 py-0.5 text-[10px] font-bold rounded border",
                            r.severity === 'critical' ? "bg-red-500/10 text-red-400 border-red-500/20" :
                            r.severity === 'high' ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
                            r.severity === 'medium' ? "bg-amber-500/10 text-amber-400 border-amber-500/20" :
                            "bg-blue-500/10 text-blue-400 border-blue-500/20"
                          )}>
                            {r.severity.toUpperCase()}
                          </span>
                        </td>
                        <td className="px-6 py-4 font-medium text-slate-200 max-w-xs truncate">
                          {r.title}
                        </td>
                        <td className="px-6 py-4 text-right space-x-2">
                          <button 
                            onClick={() => handlePreviewMd(r.id)}
                            className="p-1.5 text-slate-400 hover:text-blue-400 hover:bg-blue-400/10 rounded transition-all"
                            title="Предпросмотр MD"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                          <button 
                            onClick={() => handleExportPdf(r.id)}
                            className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-400/10 rounded transition-all"
                            title="Скачать PDF"
                          >
                            <Download className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {markdownPreview && (
            <div className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl shadow-xl overflow-hidden animate-fade-in ring-2 ring-blue-500/20">
              <div className="p-6 border-b border-slate-800 bg-slate-900/80 flex justify-between items-center">
                <h3 className="text-lg font-semibold text-slate-100 flex items-center">
                  <FileCode className="w-5 h-5 mr-2 text-blue-400" /> Предпросмотр Markdown
                </h3>
                <button 
                  onClick={copyToClipboard}
                  className={clsx(
                    "flex items-center px-3 py-1.5 rounded-lg text-xs font-medium transition-all",
                    copied ? "bg-green-500/20 text-green-400" : "bg-slate-800 text-slate-300 hover:bg-slate-700"
                  )}
                >
                  {copied ? <><Check className="w-3.5 h-3.5 mr-1.5" /> Скопировано!</> : <><Copy className="w-3.5 h-3.5 mr-1.5" /> Копировать</>}
                </button>
              </div>
              <div className="p-6">
                <pre className="bg-slate-950 p-6 rounded-xl border border-slate-800 text-sm font-mono text-slate-300 overflow-x-auto max-h-[500px] scrollbar-thin scrollbar-thumb-slate-800 leading-relaxed">
                  {markdownPreview.md}
                </pre>
              </div>
            </div>
          )}
        </section>

        {/* Vulnerabilities Selection */}
        <section className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl shadow-sm overflow-hidden order-1 xl:order-2">
          <div className="p-6 border-b border-slate-800 bg-slate-900/80">
            <h3 className="text-lg font-semibold text-slate-100 flex items-center">
              <FilePlus className="w-5 h-5 mr-2 text-emerald-500" /> Создать отчёт из уязвимости
            </h3>
            <div className="mt-4 relative group">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500 group-focus-within:text-blue-500">
                <Search className="h-3.5 w-3.5" />
              </div>
              <input
                type="text"
                placeholder="Фильтр уязвимостей..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="block w-full pl-9 pr-3 py-1.5 border border-slate-800 rounded-lg bg-slate-950/50 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-all"
              />
            </div>
          </div>
          
          <div className="p-0 max-h-[600px] overflow-y-auto scrollbar-thin scrollbar-thumb-slate-800">
            {vulns.length === 0 ? (
              <div className="p-8 text-center text-slate-500">Нет доступных уязвимостей.</div>
            ) : filteredVulns.length === 0 ? (
              <div className="p-8 text-center text-slate-500">Ничего не найдено.</div>
            ) : (
              <ul className="divide-y divide-slate-800/50">
                {filteredVulns.map((v) => (
                  <li key={v.id} className="p-4 hover:bg-slate-800/30 transition-colors group">
                    <div className="flex justify-between items-start gap-4 mb-2">
                      <span className={clsx(
                        "px-2 py-0.5 text-[10px] font-bold rounded border uppercase",
                        v.severity === 'critical' ? "bg-red-500/10 text-red-400 border-red-500/20" :
                        v.severity === 'high' ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
                        v.severity === 'medium' ? "bg-amber-500/10 text-amber-400 border-amber-500/20" :
                        "bg-blue-500/10 text-blue-400 border-blue-500/20"
                      )}>
                        {v.severity}
                      </span>
                      <button
                        onClick={() => handleGenerate(v.id)}
                        disabled={generating === v.id}
                        className={clsx(
                          "px-3 py-1 rounded text-[10px] font-bold transition-all",
                          generating === v.id 
                            ? "bg-slate-800 text-slate-500" 
                            : "bg-blue-600 text-white hover:bg-blue-500 shadow-sm"
                        )}
                      >
                        {generating === v.id ? <Loader2 className="w-3 h-3 animate-spin" /> : 'СОЗДАТЬ'}
                      </button>
                    </div>
                    <div className="text-sm font-medium text-slate-200 mb-1 group-hover:text-blue-400 transition-colors">{v.vulnerability_type}</div>
                    <div className="text-xs text-slate-500 line-clamp-1">{v.description}</div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
