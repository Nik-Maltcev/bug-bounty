import { NavLink, Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import {
  LayoutDashboard,
  FolderOpen,
  Search,
  ShieldAlert,
  FileText,
  ShieldCheck,
  ListOrdered,
  LogOut,
  Shield
} from 'lucide-react';
import clsx from 'clsx';

const navItems = [
  { to: '/app', label: 'Дашборд', icon: LayoutDashboard },
  { to: '/app/programs', label: 'Программы', icon: FolderOpen },
  { to: '/app/scans', label: 'Сканирования', icon: Search },
  { to: '/app/vulnerabilities', label: 'Уязвимости', icon: ShieldAlert },
  { to: '/app/reports', label: 'Отчёты', icon: FileText },
  { to: '/app/compliance', label: 'Комплаенс', icon: ShieldCheck },
  { to: '/app/audit', label: 'Аудит', icon: ListOrdered },
];

export default function Layout() {
  const { logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-200 selection:bg-blue-500/30">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 w-64 flex flex-col bg-slate-900 border-r border-slate-800 shadow-2xl z-50">
        <div className="flex items-center h-16 px-6 border-b border-slate-800 bg-slate-900/50">
          <Shield className="w-6 h-6 text-blue-500 mr-3" />
          <h2 className="text-lg font-bold text-slate-100 tracking-tight">Сканер сайтов</h2>
        </div>
        
        <div className="flex-1 py-6 px-3 overflow-y-auto space-y-1 scrollbar-thin scrollbar-thumb-slate-800">
          {navItems.map((item) => {
            const isActive = location.pathname === item.to || (item.to !== '/app' && location.pathname.startsWith(item.to));
            return (
              <NavLink
                key={item.to}
                to={item.to}
                className={clsx(
                  "flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group relative overflow-hidden",
                  isActive
                    ? "bg-blue-600/10 text-blue-400"
                    : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                )}
              >
                {isActive && (
                  <div className="absolute left-0 top-0 bottom-0 w-1 bg-blue-500 rounded-r-md" />
                )}
                <item.icon className={clsx("w-5 h-5 mr-3 transition-colors", isActive ? "text-blue-500" : "text-slate-500 group-hover:text-slate-300")} />
                {item.label}
              </NavLink>
            );
          })}
        </div>
        
        <div className="p-4 border-t border-slate-800 bg-slate-900/50">
          <button
            onClick={handleLogout}
            className="flex w-full items-center px-3 py-2.5 text-sm font-medium text-slate-400 rounded-lg transition-all hover:bg-red-500/10 hover:text-red-400 group"
          >
            <LogOut className="w-5 h-5 mr-3 text-slate-500 group-hover:text-red-400 transition-colors" />
            Выйти
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 ml-64 min-h-screen">
        <div className="max-w-7xl mx-auto p-8 animate-fade-in">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
