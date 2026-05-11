import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

// Icons as SVG components
const ShieldIcon = () => (
  <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
  </svg>
);

const BoltIcon = () => (
  <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
  </svg>
);

const ChartIcon = () => (
  <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
  </svg>
);

const BrainIcon = () => (
  <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
  </svg>
);

const LockIcon = () => (
  <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
  </svg>
);

const ClockIcon = () => (
  <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const CheckIcon = () => (
  <svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
  </svg>
);

const ArrowRightIcon = () => (
  <svg className="w-5 h-5 ml-2 group-hover:translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 8l4 4m0 0l-4 4m4-4H3" />
  </svg>
);

export default function LandingPage() {
  const navigate = useNavigate();
  const [isScrolled, setIsScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 50);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const handleGetStarted = () => {
    navigate('/login');
  };

  const features = [
    {
      icon: <BrainIcon />,
      title: 'ИИ-анализ',
      description: 'DeepSeek LLM генерирует интеллектуальные гипотезы и валидирует уязвимости с реальным PoC.',
    },
    {
      icon: <BoltIcon />,
      title: 'Двухэтапное сканирование',
      description: 'Этап 1: Автоматические инструменты (nmap, nuclei, httpx). Этап 2: Глубокий ИИ-анализ.',
    },
    {
      icon: <ShieldIcon />,
      title: 'Комплаенс в приоритете',
      description: 'Каждое действие проверяется на соответствие правилам программы. Никаких деструктивных операций.',
    },
    {
      icon: <ChartIcon />,
      title: 'Полный аудит',
      description: 'Полная прозрачность: каждое решение ИИ логируется с обоснованием и доказательствами.',
    },
    {
      icon: <LockIcon />,
      title: 'Режим супервизии',
      description: 'Одобряйте каждый тест перед выполнением. Полный контроль над действиями ИИ.',
    },
    {
      icon: <ClockIcon />,
      title: 'Ограничение запросов',
      description: 'Настраиваемые лимиты запросов. Уважение к целевым системам и правилам программ.',
    },
  ];

  const pricingFeatures = [
    'Неограниченное количество программ',
    'ИИ-сканирование (Этап 2)',
    'Экспорт полного аудита',
    'Режим супервизии',
    'Приоритетная поддержка',
    'Настраиваемые лимиты',
    'Доступ к API',
    'Командная работа',
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white overflow-x-hidden">
      {/* Animated background */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-blue-500/20 rounded-full blur-3xl animate-pulse" />
        <div className="absolute top-1/2 -left-40 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }} />
        <div className="absolute bottom-20 right-1/4 w-64 h-64 bg-cyan-500/10 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '2s' }} />
      </div>

      {/* Navigation */}
      <nav className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${isScrolled ? 'bg-slate-900/95 backdrop-blur-md shadow-lg' : 'bg-transparent'}`}>
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-cyan-400 rounded-xl flex items-center justify-center">
              <ShieldIcon />
            </div>
            <span className="text-xl font-bold bg-gradient-to-r from-white to-slate-300 bg-clip-text text-transparent">
              BugHunter AI
            </span>
          </div>
          <div className="hidden md:flex items-center gap-8">
            <a href="#features" className="text-slate-300 hover:text-white transition-colors">Возможности</a>
            <a href="#pricing" className="text-slate-300 hover:text-white transition-colors">Цены</a>
            <a href="#how-it-works" className="text-slate-300 hover:text-white transition-colors">Как это работает</a>
          </div>
          <button
            onClick={handleGetStarted}
            className="px-5 py-2.5 bg-gradient-to-r from-blue-600 to-cyan-500 rounded-lg font-medium hover:from-blue-500 hover:to-cyan-400 transition-all shadow-lg shadow-blue-500/25 hover:shadow-blue-500/40"
          >
            Начать
          </button>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-4xl mx-auto">
            <div className="inline-flex items-center gap-2 px-4 py-2 bg-blue-500/10 border border-blue-500/20 rounded-full text-blue-400 text-sm mb-8">
              <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
              ИИ-сканер безопасности
            </div>
            
            <h1 className="text-5xl md:text-7xl font-bold mb-6 leading-tight">
              <span className="bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
                Находите уязвимости
              </span>
              <br />
              <span className="bg-gradient-to-r from-blue-400 via-cyan-400 to-emerald-400 bg-clip-text text-transparent">
                раньше хакеров
              </span>
            </h1>
            
            <p className="text-xl text-slate-400 mb-10 max-w-2xl mx-auto leading-relaxed">
              ИИ-сканер уязвимостей, который думает как хакер. 
              Автоматическая разведка, интеллектуальная генерация гипотез 
              и реальная валидация proof-of-concept.
            </p>
            
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <button
                onClick={handleGetStarted}
                className="group px-8 py-4 bg-gradient-to-r from-blue-600 to-cyan-500 rounded-xl font-semibold text-lg hover:from-blue-500 hover:to-cyan-400 transition-all shadow-xl shadow-blue-500/25 hover:shadow-blue-500/40 flex items-center"
              >
                Начать сканирование
                <ArrowRightIcon />
              </button>
              <a
                href="#how-it-works"
                className="px-8 py-4 border border-slate-700 rounded-xl font-semibold text-lg hover:bg-slate-800/50 transition-all"
              >
                Как это работает
              </a>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-3 gap-8 mt-20 max-w-3xl mx-auto">
              <div className="text-center">
                <div className="text-4xl font-bold bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">50+</div>
                <div className="text-slate-500 mt-1">Типов уязвимостей</div>
              </div>
              <div className="text-center">
                <div className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">99.9%</div>
                <div className="text-slate-500 mt-1">Uptime SLA</div>
              </div>
              <div className="text-center">
                <div className="text-4xl font-bold bg-gradient-to-r from-emerald-400 to-blue-400 bg-clip-text text-transparent">24/7</div>
                <div className="text-slate-500 mt-1">Мониторинг</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 px-6 relative">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold mb-4">
              <span className="bg-gradient-to-r from-white to-slate-300 bg-clip-text text-transparent">
                Безопасность корпоративного уровня
              </span>
            </h2>
            <p className="text-slate-400 text-lg max-w-2xl mx-auto">
              На базе продвинутого ИИ и проверенных инструментов безопасности
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feature, index) => (
              <div
                key={index}
                className="group p-6 bg-slate-800/30 border border-slate-700/50 rounded-2xl hover:bg-slate-800/50 hover:border-slate-600/50 transition-all duration-300 hover:-translate-y-1"
              >
                <div className="w-14 h-14 bg-gradient-to-br from-blue-500/20 to-cyan-500/20 rounded-xl flex items-center justify-center text-blue-400 mb-4 group-hover:scale-110 transition-transform">
                  {feature.icon}
                </div>
                <h3 className="text-xl font-semibold mb-2">{feature.title}</h3>
                <p className="text-slate-400 leading-relaxed">{feature.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section id="how-it-works" className="py-20 px-6 relative">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold mb-4">
              <span className="bg-gradient-to-r from-white to-slate-300 bg-clip-text text-transparent">
                Как это работает
              </span>
            </h2>
            <p className="text-slate-400 text-lg max-w-2xl mx-auto">
              Двухэтапный интеллектуальный процесс сканирования
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-8 max-w-5xl mx-auto">
            {/* Stage 1 */}
            <div className="relative p-8 bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/50 rounded-2xl">
              <div className="absolute -top-4 -left-4 w-12 h-12 bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl flex items-center justify-center text-xl font-bold shadow-lg shadow-blue-500/30">
                1
              </div>
              <h3 className="text-2xl font-bold mb-4 mt-4">Этап 1: Разведка</h3>
              <ul className="space-y-3 text-slate-300">
                <li className="flex items-start gap-3">
                  <CheckIcon />
                  <span>Сканирование портов с nmap</span>
                </li>
                <li className="flex items-start gap-3">
                  <CheckIcon />
                  <span>Определение технологий</span>
                </li>
                <li className="flex items-start gap-3">
                  <CheckIcon />
                  <span>Сканирование шаблонами Nuclei</span>
                </li>
                <li className="flex items-start gap-3">
                  <CheckIcon />
                  <span>Анализ HTTP-заголовков</span>
                </li>
              </ul>
            </div>

            {/* Stage 2 */}
            <div className="relative p-8 bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-slate-700/50 rounded-2xl">
              <div className="absolute -top-4 -left-4 w-12 h-12 bg-gradient-to-br from-cyan-500 to-emerald-500 rounded-xl flex items-center justify-center text-xl font-bold shadow-lg shadow-cyan-500/30">
                2
              </div>
              <h3 className="text-2xl font-bold mb-4 mt-4">Этап 2: ИИ-анализ</h3>
              <ul className="space-y-3 text-slate-300">
                <li className="flex items-start gap-3">
                  <CheckIcon />
                  <span>Генерация гипотез ИИ</span>
                </li>
                <li className="flex items-start gap-3">
                  <CheckIcon />
                  <span>Целевое тестирование уязвимостей</span>
                </li>
                <li className="flex items-start gap-3">
                  <CheckIcon />
                  <span>Реальная валидация PoC</span>
                </li>
                <li className="flex items-start gap-3">
                  <CheckIcon />
                  <span>Отчёты с уровнем уверенности</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section id="pricing" className="py-20 px-6 relative">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-4xl font-bold mb-4">
              <span className="bg-gradient-to-r from-white to-slate-300 bg-clip-text text-transparent">
                Простые и прозрачные цены
              </span>
            </h2>
            <p className="text-slate-400 text-lg max-w-2xl mx-auto">
              Платите только за то, что используете. Никаких скрытых платежей.
            </p>
          </div>

          <div className="max-w-lg mx-auto">
            <div className="relative p-8 bg-gradient-to-br from-slate-800/80 to-slate-900/80 border border-blue-500/30 rounded-3xl shadow-2xl shadow-blue-500/10">
              {/* Popular badge */}
              <div className="absolute -top-4 left-1/2 -translate-x-1/2 px-4 py-1 bg-gradient-to-r from-blue-500 to-cyan-500 rounded-full text-sm font-medium">
                Популярный
              </div>

              <div className="text-center mb-8">
                <h3 className="text-2xl font-bold mb-2">Оплата за запрос</h3>
                <div className="flex items-baseline justify-center gap-1">
                  <span className="text-5xl font-bold bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">$0.01</span>
                  <span className="text-slate-400">/ ИИ-запрос</span>
                </div>
                <p className="text-slate-500 mt-2">Сканирование Этапа 1 бесплатно</p>
              </div>

              <ul className="space-y-4 mb-8">
                {pricingFeatures.map((feature, index) => (
                  <li key={index} className="flex items-center gap-3">
                    <div className="w-5 h-5 bg-emerald-500/20 rounded-full flex items-center justify-center">
                      <CheckIcon />
                    </div>
                    <span className="text-slate-300">{feature}</span>
                  </li>
                ))}
              </ul>

              <button
                onClick={handleGetStarted}
                className="w-full py-4 bg-gradient-to-r from-blue-600 to-cyan-500 rounded-xl font-semibold text-lg hover:from-blue-500 hover:to-cyan-400 transition-all shadow-lg shadow-blue-500/25 hover:shadow-blue-500/40 flex items-center justify-center group"
              >
                Начать бесплатно
                <ArrowRightIcon />
              </button>

              <p className="text-center text-slate-500 text-sm mt-4">
                Без кредитной карты • 100 бесплатных ИИ-запросов
              </p>
            </div>
          </div>

          {/* Enterprise CTA */}
          <div className="mt-12 text-center">
            <p className="text-slate-400 mb-4">Нужны индивидуальные лимиты или развёртывание на своих серверах?</p>
            <a href="mailto:enterprise@bughunter.ai" className="text-blue-400 hover:text-blue-300 font-medium">
              Свяжитесь с нами для корпоративных цен →
            </a>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-6 relative">
        <div className="max-w-4xl mx-auto text-center">
          <div className="p-12 bg-gradient-to-br from-blue-600/20 to-cyan-600/20 border border-blue-500/30 rounded-3xl">
            <h2 className="text-4xl font-bold mb-4">
              Готовы защитить свои приложения?
            </h2>
            <p className="text-slate-300 text-lg mb-8 max-w-2xl mx-auto">
              Присоединяйтесь к исследователям безопасности и компаниям, которые доверяют BugHunter AI 
              поиск уязвимостей до того, как их найдут злоумышленники.
            </p>
            <button
              onClick={handleGetStarted}
              className="group px-10 py-4 bg-white text-slate-900 rounded-xl font-semibold text-lg hover:bg-slate-100 transition-all shadow-xl flex items-center mx-auto"
            >
              Начать бесплатный период
              <ArrowRightIcon />
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 px-6 border-t border-slate-800">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-cyan-400 rounded-xl flex items-center justify-center">
                <ShieldIcon />
              </div>
              <span className="text-xl font-bold">BugHunter AI</span>
            </div>
            <div className="flex items-center gap-8 text-slate-400">
              <a href="#" className="hover:text-white transition-colors">Конфиденциальность</a>
              <a href="#" className="hover:text-white transition-colors">Условия</a>
              <a href="#" className="hover:text-white transition-colors">Документация</a>
              <a href="mailto:support@bughunter.ai" className="hover:text-white transition-colors">Поддержка</a>
            </div>
            <div className="text-slate-500">
              © 2026 BugHunter AI. Все права защищены.
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
