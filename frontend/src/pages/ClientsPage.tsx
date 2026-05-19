import { useEffect, useState, type FormEvent } from 'react';
import { 
  Search, Users, Plus, X, Download, Upload, Edit3, Trash2, 
  Loader2, Globe, Mail, Phone, Tag, Building2, ChevronLeft, ChevronRight
} from 'lucide-react';
import clsx from 'clsx';
import { api } from '../services/api';

interface ClientData {
  id: string;
  company_name: string;
  contact_name: string;
  email: string;
  phone: string;
  website: string;
  category: string;
  status: string;
  notes: string;
  scan_id: string | null;
  created_at: string | null;
  updated_at: string | null;
}

const STATUS_OPTIONS = [
  { value: 'new', label: 'Новый', color: 'bg-slate-500/10 text-slate-400 border-slate-500/20' },
  { value: 'scanning', label: 'Сканирование', color: 'bg-blue-500/10 text-blue-400 border-blue-500/20' },
  { value: 'report_ready', label: 'Отчёт готов', color: 'bg-purple-500/10 text-purple-400 border-purple-500/20' },
  { value: 'demo_sent', label: 'Демо отправлен', color: 'bg-amber-500/10 text-amber-400 border-amber-500/20' },
  { value: 'paid', label: 'Оплачено', color: 'bg-green-500/10 text-green-400 border-green-500/20' },
  { value: 'done', label: 'Завершено', color: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' },
];

export default function ClientsPage() {
  const [clients, setClients] = useState<ClientData[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [page, setPage] = useState(0);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showBulkModal, setShowBulkModal] = useState(false);
  const [editingClient, setEditingClient] = useState<ClientData | null>(null);
  const limit = 25;

  useEffect(() => { loadClients(); }, [page, filterStatus]);

  const loadClients = async () => {
    setLoading(true);
    try {
      const params: Record<string, string | number> = { limit, offset: page * limit };
      if (search) params.search = search;
      if (filterStatus) params.status = filterStatus;
      const res = await api.get('/api/clients', { params });
      setClients(res.data.clients);
      setTotal(res.data.total);
    } catch { /* ignore */ }
    finally { setLoading(false); }
  };

  const handleSearch = (e: FormEvent) => {
    e.preventDefault();
    setPage(0);
    loadClients();
  };

  const handleStatusChange = async (clientId: string, newStatus: string) => {
    try {
      await api.patch(`/api/clients/${clientId}/status`, { status: newStatus });
      setClients(clients.map(c => c.id === clientId ? { ...c, status: newStatus } : c));
    } catch { /* ignore */ }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Удалить клиента?')) return;
    try {
      await api.delete(`/api/clients/${id}`);
      setClients(clients.filter(c => c.id !== id));
      setTotal(t => t - 1);
    } catch { /* ignore */ }
  };

  const handleExportCsv = async () => {
    try {
      const res = await api.get('/api/clients/export/csv', { responseType: 'blob' });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'clients.csv';
      a.click();
      URL.revokeObjectURL(url);
    } catch { alert('Ошибка экспорта'); }
  };

  const getStatusBadge = (status: string) => {
    const opt = STATUS_OPTIONS.find(s => s.value === status);
    if (!opt) return <span className="text-xs px-2 py-0.5 rounded-full bg-slate-500/10 text-slate-400 border border-slate-500/20">{status}</span>;
    return <span className={clsx("text-xs px-2 py-0.5 rounded-full border", opt.color)}>{opt.label}</span>;
  };

  const totalPages = Math.ceil(total / limit);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-3xl font-bold tracking-tight text-slate-100 flex items-center gap-3">
          <Users className="w-8 h-8 text-blue-400" />
          CRM
        </h1>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowBulkModal(true)} className="flex items-center gap-2 px-3 py-1.5 text-sm text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors">
            <Upload className="w-4 h-4" /> Импорт
          </button>
          <button onClick={handleExportCsv} className="flex items-center gap-2 px-3 py-1.5 text-sm text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors">
            <Download className="w-4 h-4" /> CSV
          </button>
          <button onClick={() => setShowAddModal(true)} className="flex items-center gap-2 px-3 py-1.5 text-sm text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors">
            <Plus className="w-4 h-4" /> Добавить
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <form onSubmit={handleSearch} className="flex-1 min-w-[200px]">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text" value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Поиск по компании, контакту, email..."
              className="w-full pl-10 pr-4 py-2 border border-slate-700 rounded-lg bg-slate-900/50 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 text-sm"
            />
          </div>
        </form>
        <select
          value={filterStatus} onChange={e => { setFilterStatus(e.target.value); setPage(0); }}
          className="px-3 py-2 border border-slate-700 rounded-lg bg-slate-900/50 text-slate-100 text-sm focus:outline-none focus:border-blue-500"
        >
          <option value="">Все статусы</option>
          {STATUS_OPTIONS.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>
        <span className="flex items-center text-sm text-slate-500">{total} клиентов</span>
      </div>

      {/* Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-slate-400"><Loader2 className="w-6 h-6 animate-spin mx-auto" /></div>
        ) : clients.length === 0 ? (
          <div className="p-12 text-center">
            <Users className="w-12 h-12 text-slate-600 mx-auto mb-3" />
            <p className="text-slate-400">Нет клиентов</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-800/50 text-slate-400 text-xs uppercase">
                <tr>
                  <th className="px-4 py-3 text-left">Компания</th>
                  <th className="px-4 py-3 text-left">Контакт</th>
                  <th className="px-4 py-3 text-left">Сайт</th>
                  <th className="px-4 py-3 text-left">Категория</th>
                  <th className="px-4 py-3 text-left">Статус</th>
                  <th className="px-4 py-3 text-right">Действия</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {clients.map(client => (
                  <tr key={client.id} className="hover:bg-slate-800/20 transition-colors">
                    <td className="px-4 py-3">
                      <div className="font-medium text-white">{client.company_name}</div>
                      {client.email && <div className="text-xs text-slate-500 flex items-center gap-1"><Mail className="w-3 h-3" />{client.email}</div>}
                    </td>
                    <td className="px-4 py-3">
                      <div className="text-slate-300">{client.contact_name || '—'}</div>
                      {client.phone && <div className="text-xs text-slate-500 flex items-center gap-1"><Phone className="w-3 h-3" />{client.phone}</div>}
                    </td>
                    <td className="px-4 py-3">
                      {client.website ? (
                        <a href={client.website.startsWith('http') ? client.website : `https://${client.website}`} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:text-blue-300 flex items-center gap-1 text-xs">
                          <Globe className="w-3 h-3" />{client.website}
                        </a>
                      ) : '—'}
                    </td>
                    <td className="px-4 py-3">
                      {client.category ? <span className="text-xs px-2 py-0.5 rounded-full bg-slate-700 text-slate-300">{client.category}</span> : '—'}
                    </td>
                    <td className="px-4 py-3">
                      <select
                        value={client.status}
                        onChange={e => handleStatusChange(client.id, e.target.value)}
                        className="text-xs px-2 py-1 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 focus:outline-none focus:border-blue-500"
                      >
                        {STATUS_OPTIONS.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
                      </select>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button onClick={() => setEditingClient(client)} className="p-1.5 text-slate-400 hover:text-blue-400 transition-colors"><Edit3 className="w-4 h-4" /></button>
                        <button onClick={() => handleDelete(client.id)} className="p-1.5 text-slate-400 hover:text-red-400 transition-colors"><Trash2 className="w-4 h-4" /></button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-slate-800">
            <span className="text-xs text-slate-500">Стр. {page + 1} из {totalPages}</span>
            <div className="flex gap-1">
              <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0} className="p-1 text-slate-400 hover:text-white disabled:opacity-30"><ChevronLeft className="w-5 h-5" /></button>
              <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1} className="p-1 text-slate-400 hover:text-white disabled:opacity-30"><ChevronRight className="w-5 h-5" /></button>
            </div>
          </div>
        )}
      </div>

      {/* Add/Edit Modal */}
      {(showAddModal || editingClient) && (
        <ClientModal
          client={editingClient}
          onClose={() => { setShowAddModal(false); setEditingClient(null); }}
          onSaved={() => { setShowAddModal(false); setEditingClient(null); loadClients(); }}
        />
      )}

      {/* Bulk Import Modal */}
      {showBulkModal && (
        <BulkImportModal
          onClose={() => setShowBulkModal(false)}
          onDone={() => { setShowBulkModal(false); loadClients(); }}
        />
      )}
    </div>
  );
}

// --- Client Add/Edit Modal ---
function ClientModal({ client, onClose, onSaved }: { client: ClientData | null; onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState({
    company_name: client?.company_name || '',
    contact_name: client?.contact_name || '',
    email: client?.email || '',
    phone: client?.phone || '',
    website: client?.website || '',
    category: client?.category || '',
    notes: client?.notes || '',
  });
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!form.company_name.trim()) return;
    setSaving(true);
    try {
      if (client) {
        await api.put(`/api/clients/${client.id}`, form);
      } else {
        await api.post('/api/clients', form);
      }
      onSaved();
    } catch { alert('Ошибка сохранения'); }
    finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl p-6 max-w-md w-full mx-4">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-bold text-white">{client ? 'Редактировать' : 'Новый клиент'}</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-3">
          {[
            { key: 'company_name', label: 'Компания *', placeholder: 'ООО Компания', icon: Building2 },
            { key: 'contact_name', label: 'Контактное лицо', placeholder: 'Иван Иванов', icon: Users },
            { key: 'email', label: 'Email', placeholder: 'ivan@company.ru', icon: Mail },
            { key: 'phone', label: 'Телефон', placeholder: '+7 999 123-45-67', icon: Phone },
            { key: 'website', label: 'Сайт', placeholder: 'company.ru', icon: Globe },
            { key: 'category', label: 'Категория', placeholder: 'финтех, e-commerce...', icon: Tag },
          ].map(({ key, label, placeholder, icon: Icon }) => (
            <div key={key}>
              <label className="block text-xs font-medium text-slate-400 mb-1">{label}</label>
              <div className="relative">
                <Icon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input
                  type="text"
                  value={(form as Record<string, string>)[key]}
                  onChange={e => setForm({ ...form, [key]: e.target.value })}
                  placeholder={placeholder}
                  className="w-full pl-10 pr-3 py-2 border border-slate-700 rounded-lg bg-slate-800/50 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 text-sm"
                />
              </div>
            </div>
          ))}
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Заметки</label>
            <textarea
              value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })}
              rows={2} placeholder="Доп. информация..."
              className="w-full px-3 py-2 border border-slate-700 rounded-lg bg-slate-800/50 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 text-sm resize-none"
            />
          </div>
          <button type="submit" disabled={saving || !form.company_name.trim()} className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-medium rounded-lg transition-colors disabled:opacity-50">
            {saving ? 'Сохранение...' : client ? 'Сохранить' : 'Добавить'}
          </button>
        </form>
      </div>
    </div>
  );
}

// --- Bulk Import Modal ---
function BulkImportModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [text, setText] = useState('');
  const [category, setCategory] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ created: number } | null>(null);

  const handleImport = async () => {
    const lines = text.split('\n').filter(l => l.trim());
    if (!lines.length) return;

    // Парсим: каждая строка — "компания, сайт, email, телефон" или просто "сайт"
    const clients = lines.map(line => {
      const parts = line.split(/[,;\t]/).map(p => p.trim());
      if (parts.length >= 4) {
        return { company_name: parts[0], website: parts[1], email: parts[2], phone: parts[3], category };
      } else if (parts.length >= 2) {
        return { company_name: parts[0], website: parts[1], email: parts[2] || '', phone: '', category };
      } else {
        // Одно значение — считаем сайтом и компанией
        const val = parts[0];
        return { company_name: val, website: val, email: '', phone: '', category };
      }
    });

    setLoading(true);
    try {
      const res = await api.post('/api/clients/bulk', { clients });
      setResult(res.data);
    } catch { alert('Ошибка импорта'); }
    finally { setLoading(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl p-6 max-w-lg w-full mx-4">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-bold text-white flex items-center gap-2"><Upload className="w-5 h-5 text-blue-400" />Массовый импорт</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-white"><X className="w-5 h-5" /></button>
        </div>

        {!result ? (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Список (по строке: компания, сайт, email, телефон)</label>
              <textarea
                value={text} onChange={e => setText(e.target.value)}
                rows={10} placeholder={"ООО Рога, roga.ru, info@roga.ru, +79991234567\nООО Копыта, kopyta.com\nsite.ru"}
                className="w-full px-4 py-3 border border-slate-700 rounded-xl bg-slate-800/50 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono text-sm"
              />
              <p className="text-xs text-slate-500 mt-1">{text.split('\n').filter(l => l.trim()).length} записей</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Категория для всех</label>
              <input type="text" value={category} onChange={e => setCategory(e.target.value)} placeholder="финтех, e-commerce..."
                className="w-full px-4 py-2 border border-slate-700 rounded-lg bg-slate-800/50 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 text-sm" />
            </div>
            <button onClick={handleImport} disabled={loading || !text.trim()} className="w-full py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl transition-colors disabled:opacity-50">
              {loading ? 'Импорт...' : `Импортировать (${text.split('\n').filter(l => l.trim()).length})`}
            </button>
          </div>
        ) : (
          <div className="text-center space-y-4">
            <div className="text-4xl">✅</div>
            <p className="text-lg text-white font-medium">Импортировано: {result.created} клиентов</p>
            <button onClick={onDone} className="px-6 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg">Закрыть</button>
          </div>
        )}
      </div>
    </div>
  );
}
