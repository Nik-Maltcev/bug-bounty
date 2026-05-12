import { useEffect, useState, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getScanSummaryReport, type ScanSummaryReport } from '../services/api';
import { 
  ArrowLeft,
  Globe,
  Calendar,
  Shield,
  AlertTriangle,
  CheckCircle,
  Info,
  Printer,
  Download,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  FileText,
  Clock
} from 'lucide-react';
import clsx from 'clsx';

const SEVERITY_CONFIG: Record<string, { 
  label: string; 
  color: string; 
  bgColor: string; 
  borderColor: string;
  icon: typeof AlertTriangle;
}> = {
  'critical': { 
    label: 'Критические', 
    color: '#ef4444', 
    bgColor: 'bg-red-50', 
    borderColor: 'border-red-200',
    icon: AlertTriangle
  },
  'high': { 
    label: 'Высокие', 
    color: '#f97316', 
    bgColor: 'bg-orange-50', 
    borderColor: 'border-orange-200',
    icon: AlertTriangle
  },
  'medium': { 
    label: 'Средние', 
    color: '#eab308', 
    bgColor: 'bg-yellow-50', 
    borderColor: 'border-yellow-200',
    icon: Shield
  },
  'low': { 
    label: 'Низкие', 
    color: '#3b82f6', 
    bgColor: 'bg-blue-50', 
    borderColor: 'border-blue-200',
    icon: Info
  },
  'informational': { 
    label: 'Информационные', 
    color: '#6b7280', 
    bgColor: 'bg-gray-50', 
    borderColor: 'border-gray-200',
    icon: Info
  },
};

export default function ScanReportPage() {
  const { id } = useParams<{ id: string }>();
  const [report, setReport] = useState<ScanSummaryReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['critical', 'high']));
  const [expandedVulns, setExpandedVulns] = useState<Set<string>>(new Set());
  const reportRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!id) return;
    getScanSummaryReport(id)
      .then(setReport)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [id]);

  const toggleSection = (severity: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev);
      if (next.has(severity)) next.delete(severity);
      else next.add(severity);
      return next;
    });
  };

  const toggleVuln = (vulnId: string) => {
    setExpandedVulns(prev => {
      const next = new Set(prev);
      if (next.has(vulnId)) next.delete(vulnId);
      else next.add(vulnId);
      return next;
    });
  };

  const handlePrint = () => {
    window.print();
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleString('ru-RU', {
      day: '2-digit',
      month: 'long',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="text-center py-20">
        <FileText className="w-16 h-16 text-slate-400 mx-auto mb-4" />
        <h2 className="text-xl font-bold text-slate-200 mb-2">Отчёт не найден</h2>
        <Link to="/app/scans" className="text-blue-400 hover:text-blue-300">← К списку сканирований</Link>
      </div>
    );
  }

  const severityOrder = ['critical', 'high', 'medium', 'low', 'informational'];

  return (
    <div className="space-y-6">
      {/* Header with actions */}
      <div className="flex items-center justify-between print:hidden">
        <Link to={`/app/scans/${id}`} className="flex items-center gap-2 text-slate-400 hover:text-white">
          <ArrowLeft className="w-5 h-5" />
          Назад к сканированию
        </Link>
        <div className="flex gap-3">
          <button
            onClick={handlePrint}
            className="flex items-center gap-2 px-4 py-2 bg-slate-800 text-white rounded-lg hover:bg-slate-700 transition-colors"
          >
            <Printer className="w-4 h-4" />
            Печать
          </button>
        </div>
      </div>

      {/* Report Content */}
      <div ref={reportRef} className="bg-white text-slate-900 rounded-2xl shadow-xl overflow-hidden print:shadow-none print:rounded-none">
        {/* Report Header */}
        <div className="bg-gradient-to-r from-slate-800 to-slate-900 text-white p-8 print:bg-slate-800">
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-3xl font-bold mb-2">Отчёт о безопасности</h1>
              <div className="flex items-center gap-2 text-slate-300">
                <Globe className="w-4 h-4" />
                <a href={report.target_url} target="_blank" rel="noopener noreferrer" 
                   className="hover:text-white flex items-center gap-1">
                  {report.target_url}
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
            <div className="text-right text-sm text-slate-400">
              <div className="flex items-center gap-2 justify-end">
                <Calendar className="w-4 h-4" />
                {formatDate(report.scan_date)}
              </div>
              <div className="flex items-center gap-2 justify-end mt-1">
                <Clock className="w-4 h-4" />
                Завершено: {formatDate(report.completed_at)}
              </div>
            </div>
          </div>
        </div>

        {/* Executive Summary */}
        <div className="p-8 border-b border-slate-200">
          <h2 className="text-xl font-bold text-slate-800 mb-4">Краткое резюме</h2>
          
          <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mb-6">
            <div className="text-center p-4 bg-slate-100 rounded-xl">
              <p className="text-3xl font-bold text-slate-800">{report.stats.total}</p>
              <p className="text-sm text-slate-500">Всего</p>
            </div>
            {severityOrder.map(sev => {
              const config = SEVERITY_CONFIG[sev];
              const count = report.stats[sev as keyof typeof report.stats] as number;
              return (
                <div key={sev} className={clsx("text-center p-4 rounded-xl", config.bgColor)}>
                  <p className="text-3xl font-bold" style={{ color: config.color }}>{count}</p>
                  <p className="text-sm" style={{ color: config.color }}>{config.label}</p>
                </div>
              );
            })}
          </div>

          {(report.stats.critical > 0 || report.stats.high > 0) && (
            <div className="bg-red-50 border border-red-200 rounded-xl p-4">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-6 h-6 text-red-500 flex-shrink-0 mt-0.5" />
                <div>
                  <h3 className="font-semibold text-red-800">Требуется немедленное внимание</h3>
                  <p className="text-red-700 text-sm mt-1">
                    Обнаружено {report.stats.critical + report.stats.high} уязвимостей критического и высокого уровня.
                    Рекомендуется устранить их в первую очередь.
                  </p>
                </div>
              </div>
            </div>
          )}

          {report.stats.critical === 0 && report.stats.high === 0 && report.stats.total > 0 && (
            <div className="bg-green-50 border border-green-200 rounded-xl p-4">
              <div className="flex items-start gap-3">
                <CheckCircle className="w-6 h-6 text-green-500 flex-shrink-0 mt-0.5" />
                <div>
                  <h3 className="font-semibold text-green-800">Критических уязвимостей не обнаружено</h3>
                  <p className="text-green-700 text-sm mt-1">
                    Найдены только уязвимости среднего и низкого уровня. Рекомендуется устранить их по мере возможности.
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Vulnerabilities by Severity */}
        <div className="p-8">
          <h2 className="text-xl font-bold text-slate-800 mb-6">Детальный анализ уязвимостей</h2>
          
          {severityOrder.map(severity => {
            const group = report.vulnerabilities[severity];
            if (!group || group.count === 0) return null;
            
            const config = SEVERITY_CONFIG[severity];
            const isExpanded = expandedSections.has(severity);
            const Icon = config.icon;

            return (
              <div key={severity} className={clsx("mb-6 border rounded-xl overflow-hidden", config.borderColor)}>
                {/* Section Header */}
                <button
                  onClick={() => toggleSection(severity)}
                  className={clsx(
                    "w-full flex items-center justify-between p-4 text-left",
                    config.bgColor
                  )}
                >
                  <div className="flex items-center gap-3">
                    <Icon className="w-5 h-5" style={{ color: config.color }} />
                    <span className="font-semibold" style={{ color: config.color }}>
                      {group.label} ({group.count})
                    </span>
                  </div>
                  {isExpanded ? (
                    <ChevronUp className="w-5 h-5 text-slate-400" />
                  ) : (
                    <ChevronDown className="w-5 h-5 text-slate-400" />
                  )}
                </button>

                {/* Section Content */}
                {isExpanded && (
                  <div className="divide-y divide-slate-100">
                    {group.items.map((vuln, index) => {
                      const isVulnExpanded = expandedVulns.has(vuln.id);
                      
                      return (
                        <div key={vuln.id} className="bg-white">
                          {/* Vulnerability Header */}
                          <button
                            onClick={() => toggleVuln(vuln.id)}
                            className="w-full flex items-center justify-between p-4 text-left hover:bg-slate-50"
                          >
                            <div className="flex items-center gap-3">
                              <span className="text-slate-400 font-mono text-sm">#{index + 1}</span>
                              <span className="font-medium text-slate-800">{vuln.title}</span>
                            </div>
                            {isVulnExpanded ? (
                              <ChevronUp className="w-4 h-4 text-slate-400" />
                            ) : (
                              <ChevronDown className="w-4 h-4 text-slate-400" />
                            )}
                          </button>

                          {/* Vulnerability Details */}
                          {isVulnExpanded && (
                            <div className="px-4 pb-4 space-y-4 bg-slate-50">
                              {/* Description */}
                              <div>
                                <h4 className="text-sm font-semibold text-slate-600 mb-2">Описание</h4>
                                <p className="text-slate-700 text-sm whitespace-pre-wrap">{vuln.description}</p>
                              </div>

                              {/* Evidence */}
                              {vuln.evidence && (
                                <div>
                                  <h4 className="text-sm font-semibold text-slate-600 mb-2">Доказательства</h4>
                                  <div className="bg-slate-800 text-green-400 p-3 rounded-lg font-mono text-sm overflow-x-auto">
                                    {vuln.evidence}
                                  </div>
                                </div>
                              )}

                              {/* Steps to Reproduce */}
                              {vuln.steps_to_reproduce && (
                                <div>
                                  <h4 className="text-sm font-semibold text-slate-600 mb-2">Шаги для воспроизведения</h4>
                                  <div className="text-slate-700 text-sm whitespace-pre-wrap bg-white p-3 rounded-lg border border-slate-200">
                                    {vuln.steps_to_reproduce}
                                  </div>
                                </div>
                              )}

                              {/* Impact */}
                              {vuln.impact && (
                                <div>
                                  <h4 className="text-sm font-semibold text-slate-600 mb-2">Оценка влияния</h4>
                                  <div className="text-slate-700 text-sm whitespace-pre-wrap bg-amber-50 p-3 rounded-lg border border-amber-200">
                                    {vuln.impact}
                                  </div>
                                </div>
                              )}

                              {/* Remediation */}
                              {vuln.remediation && (
                                <div>
                                  <h4 className="text-sm font-semibold text-slate-600 mb-2">Рекомендации по устранению</h4>
                                  <div className="text-slate-700 text-sm whitespace-pre-wrap bg-green-50 p-3 rounded-lg border border-green-200">
                                    {vuln.remediation}
                                  </div>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}

          {Object.keys(report.vulnerabilities).length === 0 && (
            <div className="text-center py-12 text-slate-500">
              <Shield className="w-12 h-12 mx-auto mb-4 text-green-500" />
              <p className="text-lg font-medium text-slate-700">Уязвимости не обнаружены</p>
              <p className="text-sm">Сканирование не выявило проблем безопасности</p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="bg-slate-100 p-6 text-center text-sm text-slate-500 print:bg-slate-200">
          <p>Отчёт сгенерирован автоматически системой Bug Bounty Security Scanner</p>
          <p className="mt-1">ID сканирования: {report.scan_id}</p>
        </div>
      </div>

      {/* Print Styles */}
      <style>{`
        @media print {
          body { background: white !important; }
          .print\\:hidden { display: none !important; }
          .print\\:shadow-none { box-shadow: none !important; }
          .print\\:rounded-none { border-radius: 0 !important; }
          .print\\:bg-slate-800 { background-color: #1e293b !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
          .print\\:bg-slate-200 { background-color: #e2e8f0 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        }
      `}</style>
    </div>
  );
}
