# Bug Bounty Security Agent — Рабочий флоу

## Что это

ИИ-агент с веб-интерфейсом для тестирования безопасности в рамках программ bug bounty.
Строго следует правилам программы, блокирует запрещённые действия, ведёт полный аудит.

## Структура проекта

```
bug-bounty/
├── backend/                  # FastAPI (Python 3.11+)
│   ├── app/
│   │   ├── api/              # REST API эндпоинты
│   │   │   ├── auth.py       # POST /api/auth/login, /logout
│   │   │   ├── programs.py   # CRUD программ bug bounty
│   │   │   ├── scans.py      # Запуск и мониторинг сканирований
│   │   │   ├── vulnerabilities.py  # Уязвимости + отчёты
│   │   │   ├── compliance.py # Статус соответствия правилам
│   │   │   └── audit.py      # Журнал аудита
│   │   ├── core/
│   │   │   ├── auth.py       # JWT, bcrypt, middleware
│   │   │   ├── database.py   # SQLite + SQLAlchemy
│   │   │   └── exceptions.py # Иерархия исключений
│   │   ├── models/
│   │   │   ├── schemas.py    # Pydantic-модели
│   │   │   └── database.py   # ORM-модели (SQLAlchemy)
│   │   ├── services/
│   │   │   ├── auth_service.py       # Логика блокировки аккаунта
│   │   │   ├── rules_parser.py       # Парсер правил bug bounty
│   │   │   ├── compliance_manager.py # Контроль соответствия
│   │   │   ├── scanner.py            # Сканер уязвимостей
│   │   │   ├── report_generator.py   # Генерация отчётов
│   │   │   ├── audit_logger.py       # Append-only журнал
│   │   │   └── scan_plugins/         # Плагины сканирования
│   │   │       ├── web_plugin.py
│   │   │       ├── smart_contract_plugin.py
│   │   │       └── api_plugin.py
│   │   └── main.py           # FastAPI app + exception handlers
│   ├── tests/                # 228 тестов (pytest)
│   └── requirements.txt
├── frontend/                 # React 18 + TypeScript + Vite
│   ├── src/
│   │   ├── components/       # Layout, ProtectedRoute, Sidebar
│   │   ├── pages/            # Dashboard, Programs, Scans, etc.
│   │   ├── services/api.ts   # Axios API-клиент
│   │   ├── hooks/useAuth.ts  # Хук аутентификации
│   │   ├── types/index.ts    # TypeScript-типы
│   │   └── styles.css        # Тёмная тема, адаптивная вёрстка
│   └── package.json
└── README.md
```

---

## 1. Установка

### Требования
- Python 3.11+
- Node.js 18+
- npm

### Бэкенд

```bash
cd backend
py -m pip install -r requirements.txt
```

### Фронтенд

```bash
cd frontend
npm install
```

---

## 2. Создание первого пользователя

Перед первым запуском нужно создать пользователя в БД.
Запусти из папки `backend/`:

```bash
py -c "
from app.core.database import init_db, SessionLocal
from app.core.auth import hash_password
from app.models.database import User
import uuid

init_db()
db = SessionLocal()
user = User(
    id=str(uuid.uuid4()),
    username='admin',
    password_hash=hash_password('your-password-here'),
)
db.add(user)
db.commit()
db.close()
print('Пользователь admin создан!')
"
```

Замени `your-password-here` на свой пароль.

---

## 3. Запуск

### Бэкенд (терминал 1)

```bash
cd backend
py -m uvicorn app.main:app --reload --port 8000
```

API будет доступен на `http://localhost:8000`
Документация: `http://localhost:8000/docs`

### Фронтенд (терминал 2)

```bash
cd frontend
npm run dev
```

Веб-интерфейс будет на `http://localhost:3000`
Vite автоматически проксирует `/api` запросы на бэкенд.

---

## 4. Рабочий флоу использования

### Шаг 1: Вход в систему

1. Открой `http://localhost:3000`
2. Введи логин `admin` и пароль
3. Получишь JWT-токен, все запросы будут авторизованы

### Шаг 2: Импорт программы Bug Bounty

1. Перейди в раздел **Программы**
2. Нажми **Импорт программы**
3. Вставь текст описания программы в формате:

```
# Program: Example Bug Bounty
Platform: immunefi

## Assets
- [web] https://app.example.com (Main App)
- [api] https://api.example.com (REST API)
- [smart_contract] 0xABC123 (Token Contract)
- [mobile] com.example.app (Mobile App) (out of scope)

## Rules
- [ALLOWED] Testing for XSS vulnerabilities
- [ALLOWED] Static analysis of smart contracts
- [FORBIDDEN] Denial of service attacks
- [FORBIDDEN] Accessing other users' data
- [FORBIDDEN] Social engineering

## Rewards
- critical: $5000-$50000
- high: $2000-$5000
- medium: $500-$2000
- low: $100-$500

## Disclosure
- Report vulnerabilities within 24 hours of discovery
- Do not publish details before fix is deployed
- Follow responsible disclosure guidelines
```

4. Система распарсит текст и покажет структурированные правила, активы, вознаграждения
5. Проверь, что всё корректно

### Шаг 3: Просмотр области действия (Scope)

1. Открой детали программы
2. Увидишь список активов с типами и статусом (in scope / out of scope)
3. Активы вне scope помечены — сканирование для них заблокировано

### Шаг 4: Запуск сканирования

1. Перейди в раздел **Сканирования**
2. Выбери программу и актив из scope
3. Нажми **Запустить сканирование**
4. Система:
   - Проверит, что актив в scope
   - Проверит действие через Менеджер соответствия
   - Запустит подходящий плагин (Web / Smart Contract / API)
   - Покажет прогресс (этап, процент)
   - Классифицирует находки по серьёзности

### Шаг 5: Просмотр уязвимостей

1. Перейди в раздел **Уязвимости**
2. Фильтруй по серьёзности (Critical/High/Medium/Low), типу актива, статусу
3. Каждая уязвимость содержит: тип, описание, доказательства, оценку серьёзности

### Шаг 6: Генерация отчёта

1. Выбери уязвимость
2. Нажми **Сгенерировать отчёт**
3. Система создаст структурированный отчёт:
   - Описание уязвимости
   - Шаги воспроизведения
   - Proof of Concept
   - Оценка воздействия
   - Рекомендации по исправлению
4. Экспортируй в **Markdown** или **PDF**
5. Подай отчёт в программу bug bounty

### Шаг 7: Мониторинг соответствия

1. Перейди в раздел **Соответствие**
2. Выбери программу
3. Увидишь:
   - Общее количество действий
   - Разрешённые / заблокированные действия
   - Причины блокировок с количеством

### Шаг 8: Журнал аудита

1. Перейди в раздел **Журнал аудита**
2. Фильтруй по дате, типу действия, программе, результату
3. Каждая запись содержит: время, действие, актив, результат, ссылку на правило
4. Экспортируй в **JSON** для доказательства соблюдения правил

---

## 5. Управление несколькими программами

- Импортируй несколько программ bug bounty
- Переключайся между ними — правила и scope загружаются автоматически
- Каждая программа изолирована: правила одной не влияют на другую
- Dashboard показывает сводку по всем программам

---

## 6. Безопасность системы

- JWT-аутентификация на всех эндпоинтах
- Блокировка аккаунта после 3 неудачных попыток входа (15 минут)
- Данные в SQLite (шифрование на уровне ОС)
- Append-only журнал аудита (записи нельзя изменить или удалить)
- Очистка сессии при логауте

---

## 7. Тестирование

```bash
cd backend
py -m pytest tests/ -v
```

228 тестов покрывают все модули: аутентификацию, парсер, compliance, сканер, отчёты, аудит, API.

---

## 8. Переменные окружения

| Переменная | Описание | По умолчанию |
|---|---|---|
| `JWT_SECRET_KEY` | Секрет для подписи JWT | `dev-secret-key-change-in-production` |
| `JWT_EXPIRATION_MINUTES` | Время жизни токена (мин) | `60` |
| `DATABASE_URL` | URL базы данных | `sqlite:///./bugbounty.db` |
| `ALLOWED_ORIGINS` | CORS origins (через запятую) | `*` |
| `VITE_API_URL` | URL бэкенда для фронтенда | (пусто, используется proxy) |

**Для продакшена обязательно смени `JWT_SECRET_KEY`!**

---

## 9. API эндпоинты

| Метод | URL | Описание |
|---|---|---|
| POST | `/api/auth/login` | Вход |
| POST | `/api/auth/logout` | Выход |
| POST | `/api/programs` | Импорт программы |
| GET | `/api/programs` | Список программ |
| GET | `/api/programs/{id}` | Детали программы |
| PUT | `/api/programs/{id}` | Обновление программы |
| PATCH | `/api/programs/{id}/archive` | Архивирование |
| GET | `/api/programs/{id}/assets` | Активы программы |
| POST | `/api/programs/{id}/scans` | Запуск сканирования |
| GET | `/api/scans/{id}` | Статус сканирования |
| GET | `/api/scans/{id}/progress` | Прогресс сканирования |
| GET | `/api/vulnerabilities` | Список уязвимостей |
| GET | `/api/vulnerabilities/{id}` | Детали уязвимости |
| POST | `/api/vulnerabilities/{id}/report` | Генерация отчёта |
| GET | `/api/reports/{id}` | Просмотр отчёта |
| GET | `/api/reports/{id}/export` | Экспорт (md/pdf) |
| GET | `/api/compliance/{program_id}` | Статус соответствия |
| GET | `/api/audit` | Журнал аудита |
| GET | `/api/audit/export` | Экспорт журнала (JSON) |
