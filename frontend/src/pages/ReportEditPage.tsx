import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getScanReport, updateScanReport, downloadScanReportPdf } from '../services/api';
import type { ScanReportData } from '../services/api';
import { 
  Save, 
  Download, 
  ArrowLeft, 
  Loader2, 
  CheckCircle2,
  Globe,
  Tag
} from 'lucide-react';
import clsx from 'clsx';

export default function ReportEditPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [report, setReport] = useState<ScanReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    if (id) {
      getScanReport(id)
        .then(setReport)
        .catch((err) => {
          console.error('Failed to load report:', id, err);
          alert(`Ошибка загрузки отчёта: ${err?.response?.status || err.message}`);
          navigate('/app/reports');
        })
        .finally(() => setLoading(false));
    }
  }, [id]);

  const handleSave = async () => {
    if (!report || !id) return;
    setSaving(true);
    try {
      const updated = await updateScanReport(id, {
        title: report.title,
        executive_summary: report.executive_summary,
        findings_summary: report.findings_summary,
        risk_assessment: report.risk_assessment,
        compliance_notes: report.compliance_notes,
        recommendations: report.recommendations,
        conclusion: report.conclusion,
        status: report.status,
      });
      setReport(updated);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch {
      alert('Ошибка сохранения');
    } finally {
      setSaving(false);
    }
  };

  const handleDownloadPdf = async () => {
    if (!id || !report) return;
    setDownloading(true);
    try {
      const blob = await downloadScanReportPdf(id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report_${report.target_url.replace(/https?:\/\//, '').replace(/\//g, '_')}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      alert('Ошибка генерации PDF');
    } finally {
      setDownloading(false);
    }
  };

  const updateField = (field: keyof ScanReportData, value: string) => {
    if (report) {
      setReport({ ...report, [field]: value });
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 animate-pulse">
        <Loader2 className="w-6 h-6 mr-3 animate-spin" />
        Загрузка отчёта...
      </div>
    );
  }

  if (!report) return null;

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/app/reports')}
            className="p-2 text-slate-400 hover:text-white bg-slate-800 rounded-lg transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-white">Редактирование отчёта</h1>
            <div className="flex items-center gap-3 mt-1 text-sm text-slate-400">
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
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleSave}
            disabled={saving}
            className={clsx(
              "flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition-all",
              saved
                ? "bg-green-500/20 text-green-400 border border-green-500/30"
                : "bg-blue-600 hover:bg-blue-500 text-white"
            )}
          >
            {saving ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : saved ? (
              <CheckCircle2 className="w-4 h-4" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            {saved ? 'Сохранено' : 'Сохранить'}
          </button>
          <button
            onClick={handleDownloadPdf}
            disabled={downloading}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-green-400 bg-green-500/10 hover:bg-green-500/20 border border-green-500/20 rounded-lg transition-colors disabled:opacity-50"
          >
            {downloading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Download className="w-4 h-4" />
            )}
            Скачать PDF
          </button>
        </div>
      </div>

      {/* Title */}
      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">Заголовок</label>
        <input
          type="text"
          value={report.title}
          onChange={(e) => updateField('title', e.target.value)}
          className="block w-full px-4 py-3 border border-slate-600 rounded-xl bg-slate-900/50 text-slate-100 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 text-lg font-semibold"
        />
      </div>

      {/* Status */}
      <div className="flex items-center gap-4">
        <label className="text-sm font-medium text-slate-300">Статус:</label>
        <select
          value={report.status}
          onChange={(e) => updateField('status', e.target.value)}
          className="px-3 py-1.5 border border-slate-600 rounded-lg bg-slate-900/50 text-slate-100 focus:outline-none focus:border-blue-500 text-sm"
        >
          <option value="draft">Черновик</option>
          <option value="final">Финальный</option>
        </select>
      </div>

      {/* Sections */}
      {[
        { key: 'executive_summary', label: 'Резюме для руководства', rows: 4 },
        { key: 'findings_summary', label: 'Обнаруженные уязвимости', rows: 8 },
        { key: 'risk_assessment', label: 'Оценка рисков', rows: 5 },
        { key: 'compliance_notes', label: 'Соответствие требованиям (152-ФЗ, PCI DSS)', rows: 4 },
        { key: 'recommendations', label: 'Рекомендации', rows: 6 },
        { key: 'conclusion', label: 'Заключение', rows: 3 },
      ].map(({ key, label, rows }) => (
        <div key={key} className="bg-slate-900/40 border border-slate-800 rounded-xl p-4">
          <label className="block text-sm font-medium text-slate-300 mb-2">{label}</label>
          <textarea
            value={(report as unknown as Record<string, string>)[key] || ''}
            onChange={(e) => updateField(key as keyof ScanReportData, e.target.value)}
            rows={rows}
            className="block w-full px-4 py-3 border border-slate-700 rounded-lg bg-slate-900/50 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono text-sm leading-relaxed resize-y"
          />
        </div>
      ))}

      {/* Bottom actions */}
      <div className="flex justify-end gap-3 pb-8">
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-2 px-6 py-3 text-base font-bold bg-blue-600 hover:bg-blue-500 text-white rounded-xl transition-all disabled:opacity-50"
        >
          {saving ? <Loader2 className="w-5 h-5 animate-spin" /> : <Save className="w-5 h-5" />}
          Сохранить изменения
        </button>
        <button
          onClick={handleDownloadPdf}
          disabled={downloading}
          className="flex items-center gap-2 px-6 py-3 text-base font-bold text-green-400 bg-green-500/10 hover:bg-green-500/20 border border-green-500/20 rounded-xl transition-all disabled:opacity-50"
        >
          {downloading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Download className="w-5 h-5" />}
          Скачать PDF
        </button>
      </div>
    </div>
  );
}
