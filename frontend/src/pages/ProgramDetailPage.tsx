import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { getProgram, getComplianceSummary } from '../services/api';
import type { ParsedProgram, ComplianceSummary } from '../types';
import { 
  Bot, 
  ArrowLeft, 
  Globe, 
  ShieldCheck, 
  Award, 
  FileWarning, 
  Activity,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info
} from 'lucide-react';
import clsx from 'clsx';

export default function ProgramDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [program, setProgram] = useState<ParsedProgram | null>(null);
  const [compliance, setCompliance] = useState<ComplianceSummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) return;
    Promise.all([
      getProgram(id),
      getComplianceSummary(id).catch(() => null),
    ]).then(([p, c]) => {
      setProgram(p);
      setCompliance(c);
      setLoading(false);
    });
  }, [id]);

  if (loading || !program) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 animate-pulse">
        <Activity className="w-6 h-6 mr-3 animate-spin" />
        Загрузка программы...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-3xl font-bold tracking-tight text-slate-100">{program.name}</h1>
            <span className={clsx(
              "px-2.5 py-1 text-xs font-semibold rounded-md border",
              program.is_archived
                ? "bg-slate-800/50 text-slate-400 border-slate-700/50"
                : "bg-blue-500/10 text-blue-400 border-blue-500/20"
            )}>
              {program.platform}
            </span>
            {!program.is_archived && (
              <span className="flex items-center text-xs text-green-400 bg-green-500/10 border border-green-500/20 px-2 py-1 rounded">
                <div className="w-1.5 h-1.5 rounded-full bg-green-400 mr-1.5 animate-pulse" /> Активна
              </span>
            )}
          </div>
          <p className="text-slate-400 text-sm">
            Добавлена {new Date(program.created_at).toLocaleDateString('ru-RU')}
          </p>
        </div>
        
        <div className="flex w-full md:w-auto items-center gap-3">
          <Link 
            to="/app/programs" 
            className="flex items-center justify-center px-4 py-2 rounded-lg text-sm font-medium bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-700 transition-all w-full md:w-auto shrink-0"
          >
            <ArrowLeft className="w-4 h-4 mr-2" /> Назад
          </Link>
          <Link 
            to={`/app/programs/${id}/chat`} 
            className="flex items-center justify-center px-4 py-2 rounded-lg text-sm font-medium bg-blue-600 text-white hover:bg-blue-500 shadow-lg shadow-blue-500/20 transition-all w-full md:w-auto shrink-0"
          >
            <Bot className="w-4 h-4 mr-2" /> ИИ-Ассистент
          </Link>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl p-6 shadow-sm">
          <h3 className="text-lg font-semibold text-slate-100 flex items-center mb-4">
            <Info className="w-5 h-5 mr-2 text-blue-500" /> Основная информация
          </h3>
          <div className="space-y-4">
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-400">Платформа</span>
              <span className="text-slate-200 font-medium">{program.platform}</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
              <span className="text-slate-400">Статус</span>
              <span className="text-slate-200 font-medium">{program.is_archived ? 'В архиве' : 'Активна'}</span>
            </div>
            <div className="flex justify-between items-center py-2">
              <span className="text-slate-400">Активов в scope</span>
              <span className="text-slate-200 font-medium">{program.assets.filter(a => a.in_scope).length} из {program.assets.length}</span>
            </div>
          </div>
        </div>

        {compliance && (
          <div className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl p-6 shadow-sm">
            <h3 className="text-lg font-semibold text-slate-100 flex items-center mb-4">
              <ShieldCheck className="w-5 h-5 mr-2 text-purple-500" /> Комплаенс и аудит
            </h3>
            <div className="space-y-4">
              <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
                <span className="text-slate-400">Всего действий</span>
                <span className="text-slate-200 font-medium">{compliance.total_actions}</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-slate-800/50">
                <span className="text-slate-400">Разрешено</span>
                <span className="text-green-400 font-medium flex items-center">
                  <CheckCircle2 className="w-4 h-4 mr-1.5" /> {compliance.allowed_actions}
                </span>
              </div>
              <div className="flex justify-between items-center py-2">
                <span className="text-slate-400">Заблокировано</span>
                <span className="text-red-400 font-medium flex items-center">
                  <XCircle className="w-4 h-4 mr-1.5" /> {compliance.blocked_actions}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Main Tabs/Sections */}
      <div className="space-y-6">
        {/* Assets Section */}
        <section className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl shadow-sm overflow-hidden">
          <div className="p-6 border-b border-slate-800 bg-slate-900/80">
            <h3 className="text-lg font-semibold text-slate-100 flex items-center">
              <Globe className="w-5 h-5 mr-2 text-blue-500" /> Активы ({program.assets.length})
            </h3>
          </div>
          <div className="p-0 overflow-x-auto">
            {program.assets.length === 0 ? (
              <div className="p-8 text-center text-slate-500">Активы не определены.</div>
            ) : (
              <table className="w-full text-left text-sm whitespace-nowrap">
                <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="px-6 py-4 font-medium">Название</th>
                    <th className="px-6 py-4 font-medium">Тип</th>
                    <th className="px-6 py-4 font-medium">Цель (Target)</th>
                    <th className="px-6 py-4 font-medium text-center">In Scope</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50">
                  {program.assets.map((a) => (
                    <tr key={a.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-6 py-4 font-medium text-slate-200">{a.name}</td>
                      <td className="px-6 py-4">
                        <span className="px-2.5 py-1 text-xs rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {a.asset_type}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <code className="text-blue-400 bg-blue-500/10 px-2 py-1 rounded font-mono text-xs">{a.target}</code>
                      </td>
                      <td className="px-6 py-4 text-center">
                        {a.in_scope ? (
                          <div className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-green-500/10 text-green-400">
                            <CheckCircle2 className="w-4 h-4" />
                          </div>
                        ) : (
                          <div className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-red-500/10 text-red-400">
                            <XCircle className="w-4 h-4" />
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>

        {/* Rules Section */}
        <section className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl shadow-sm overflow-hidden">
          <div className="p-6 border-b border-slate-800 bg-slate-900/80">
            <h3 className="text-lg font-semibold text-slate-100 flex items-center">
              <AlertTriangle className="w-5 h-5 mr-2 text-amber-500" /> Правила ({program.rules.length})
            </h3>
          </div>
          <div className="p-0 overflow-x-auto">
            {program.rules.length === 0 ? (
              <div className="p-8 text-center text-slate-500">Правила не определены.</div>
            ) : (
              <table className="w-full text-left text-sm">
                <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 whitespace-nowrap">
                  <tr>
                    <th className="px-6 py-4 font-medium w-48">Категория</th>
                    <th className="px-6 py-4 font-medium">Описание</th>
                    <th className="px-6 py-4 font-medium w-32 text-center">Статус</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50">
                  {program.rules.map((r) => (
                    <tr key={r.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="px-2.5 py-1 text-xs rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {r.category}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-slate-300 leading-relaxed">{r.description}</td>
                      <td className="px-6 py-4 text-center whitespace-nowrap">
                        {r.is_allowed ? (
                          <span className="inline-flex items-center text-xs text-green-400 bg-green-500/10 border border-green-500/20 px-2 py-1 rounded">
                            <CheckCircle2 className="w-3 h-3 mr-1" /> Разрешено
                          </span>
                        ) : (
                          <span className="inline-flex items-center text-xs text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-1 rounded">
                            <XCircle className="w-3 h-3 mr-1" /> Запрещено
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>

        {/* Rewards and Requirements Grid */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          {program.reward_tiers.length > 0 && (
            <section className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl shadow-sm overflow-hidden h-full">
              <div className="p-6 border-b border-slate-800 bg-slate-900/80">
                <h3 className="text-lg font-semibold text-slate-100 flex items-center">
                  <Award className="w-5 h-5 mr-2 text-yellow-500" /> Вознаграждения
                </h3>
              </div>
              <div className="p-0 overflow-x-auto">
                <table className="w-full text-left text-sm whitespace-nowrap">
                  <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="px-6 py-4 font-medium">Серьёзность</th>
                      <th className="px-6 py-4 font-medium">Мин.</th>
                      <th className="px-6 py-4 font-medium">Макс.</th>
                      <th className="px-6 py-4 font-medium">Валюта</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {program.reward_tiers.map((rt, i) => (
                      <tr key={i} className="hover:bg-slate-800/30 transition-colors">
                        <td className="px-6 py-4 font-medium">
                          <span className={clsx(
                            "px-2.5 py-1 text-xs font-semibold rounded-md border",
                            rt.severity === 'critical' ? "bg-red-500/10 text-red-400 border-red-500/20" :
                            rt.severity === 'high' ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
                            rt.severity === 'medium' ? "bg-amber-500/10 text-amber-400 border-amber-500/20" :
                            rt.severity === 'low' ? "bg-blue-500/10 text-blue-400 border-blue-500/20" :
                            "bg-slate-500/10 text-slate-400 border-slate-500/20"
                          )}>
                            {rt.severity.toUpperCase()}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-slate-300">{rt.min_reward}</td>
                        <td className="px-6 py-4 text-slate-300">{rt.max_reward}</td>
                        <td className="px-6 py-4 text-slate-400">{rt.currency}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {program.disclosure_requirements && (
            <section className="bg-slate-900/60 backdrop-blur-sm border border-slate-800 rounded-2xl shadow-sm overflow-hidden h-full">
              <div className="p-6 border-b border-slate-800 bg-slate-900/80">
                <h3 className="text-lg font-semibold text-slate-100 flex items-center">
                  <FileWarning className="w-5 h-5 mr-2 text-red-500" /> Требования к разглашению (Disclosure)
                </h3>
              </div>
              <div className="p-6">
                <p className="text-slate-300 leading-relaxed whitespace-pre-wrap">
                  {program.disclosure_requirements}
                </p>
              </div>
            </section>
          )}
        </div>
      </div>
    </div>
  );
}
