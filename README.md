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

---

## 10. AI-Driven Scan (Stage 2)

Stage 2 — это **интеллектуальный анализ** результатов обычного сканирования с помощью LLM (DeepSeek). Он автоматически генерирует и проверяет гипотезы об уязвимостях.

### Как это работает

```
Stage 1 (обычное сканирование)          Stage 2 (AI-анализ)
┌─────────────────────────────┐        ┌─────────────────────────────────────┐
│ nuclei, nmap, nikto,        │        │  1. Извлечение технологий           │
│ sqlmap, httpx, gobuster...  │───────▶│  2. Генерация гипотез (LLM)         │
│                             │        │  3. Выполнение запросов             │
│ Находки: headers, ports,    │        │  4. Анализ ответов (LLM)            │
│ vulns, fingerprints...      │        │  5. Подтверждение уязвимостей       │
└─────────────────────────────┘        └─────────────────────────────────────┘
```

### Фазы Stage 2

#### Фаза 1: Извлечение технологий (`tech_extraction`)

LLM анализирует сырые данные Stage 1 и определяет используемые технологии:

```
Входные данные:
  "Server: nginx/1.18.0"
  "X-Powered-By: PHP/7.4"
  WordPress fingerprint

Результат:
  - nginx v1.18.0 (CVE-2021-23017)
  - PHP v7.4.3
  - WordPress v5.8
```

#### Фаза 2: Генерация гипотез (`hypothesis_testing`)

На основе технологий и находок LLM генерирует гипотезы для проверки:

```json
{
  "vulnerability_type": "sql_injection",
  "description": "Параметр 'id' может быть уязвим к SQL-инъекции",
  "target_url": "https://example.com/api/users?id=1",
  "rationale": "Обнаружен PHP + MySQL, параметр id передаётся в запрос без валидации"
}
```

#### Фаза 3: Выполнение запросов

Для каждой гипотезы создаётся тестовый HTTP-запрос:

```
GET /api/users?id=1' OR '1'='1
```

Перед выполнением проверяется:
- **Compliance** — не нарушает ли запрос правила программы
- **Rate Limit** — не превышен ли лимит запросов
- **Supervised Mode** — нужно ли одобрение пользователя

#### Фаза 4: Анализ ответов (`analysis`)

LLM анализирует ответ сервера и определяет, подтверждена ли уязвимость:

```
Ответ: HTTP 200, тело содержит данные других пользователей
Вердикт: ПОДТВЕРЖДЕНО (confidence: 85%)
```

Если уязвимость подтверждена — создаётся AIFinding с полным PoC.

### Итеративный процесс

Stage 2 работает итеративно — каждая итерация углубляет анализ:

```
Итерация 0: Базовые гипотезы из Stage 1
    ↓ (нашли SQL-инъекцию)
Итерация 1: Проверяем другие параметры, пробуем обход WAF
    ↓ (нашли ещё 2 точки входа)
Итерация 2: Пробуем эксплуатацию, извлечение данных
    ↓
(до max_iterations или пока есть гипотезы)
```

### Настройки

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `max_iterations` | 3 | Максимум итераций анализа |
| `max_requests` | 50 | Максимум HTTP-запросов к цели |
| `rate_limit` | 5.0 | Запросов в секунду |
| `supervised_mode` | false | Требовать одобрение каждого запроса |

### API эндпоинты Stage 2

| Метод | URL | Описание |
|---|---|---|
| POST | `/api/scans/{id}/ai-analyze` | Запуск AI-анализа |
| GET | `/api/scans/{id}/ai-status` | Статус и прогресс |
| POST | `/api/scans/{id}/ai-stop` | Остановка (Kill Switch) |
| GET | `/api/ai/scans/{id}/stage2/findings` | Найденные уязвимости |
| GET | `/api/ai/scans/{id}/stage2/technologies` | Извлечённые технологии |
| GET | `/api/ai/scans/{id}/stage2/audit` | Audit Trail решений AI |

### Пример запуска

```bash
# Запуск AI-анализа
curl -X POST http://localhost:8000/api/scans/{scan_id}/ai-analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "supervised_mode": false,
    "max_iterations": 3,
    "max_requests": 50,
    "rate_limit": 5.0
  }'

# Проверка статуса
curl http://localhost:8000/api/scans/{scan_id}/ai-status \
  -H "Authorization: Bearer $TOKEN"
```

### Пример ответа статуса

```json
{
  "status": "running",
  "current_phase": "hypothesis_testing",
  "percent_complete": 45,
  "stats": {
    "technologies_found": 5,
    "hypotheses_generated": 20,
    "hypotheses_tested": 9,
    "requests_executed": 15,
    "requests_blocked": 2,
    "findings_confirmed": 2
  },
  "ai_findings": [
    {
      "id": "ai_abc123",
      "vulnerability_type": "sql_injection",
      "severity": "high",
      "confidence": 0.85,
      "description": "SQL-инъекция в параметре id"
    }
  ]
}
```

### Настройка LLM провайдера

Stage 2 использует DeepSeek API. Настройка:

**Вариант 1: Переменная окружения**
```bash
export DEEPSEEK_API_KEY=sk-your-api-key
```

**Вариант 2: Через API**
```bash
curl -X PUT http://localhost:8000/api/ai/settings \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "deepseek",
    "api_key": "sk-your-api-key",
    "model": "deepseek-chat"
  }'
```

### Безопасность Stage 2

- **Compliance Check** — каждый запрос проверяется на соответствие правилам программы
- **Rate Limiting** — защита от случайного DDoS цели
- **Kill Switch** — мгновенная остановка через `/ai-stop`
- **Supervised Mode** — ручное одобрение каждого запроса
- **Audit Trail** — полный лог всех решений AI с обоснованием

### Использование в UI

1. Запустите обычное сканирование (Stage 1)
2. Дождитесь завершения
3. На странице деталей сканирования нажмите **"Запустить"** в секции "ИИ-анализ (Stage 2)"
4. Наблюдайте за прогрессом в реальном времени
5. Новые уязвимости появятся в общем списке с пометкой AI


---

## 11. Docker деплой

### Сборка и запуск

```bash
# Создание сети
docker network create bugbounty-net

# Бэкенд
docker build -t bug-bounty-backend ./backend
docker run -d \
  --name backend \
  --network bugbounty-net \
  -p 8000:8000 \
  -e DEEPSEEK_API_KEY=sk-your-key \
  bug-bounty-backend

# Фронтенд
docker build -t bug-bounty-frontend ./frontend
docker run -d \
  --name bb-frontend \
  --network bugbounty-net \
  -p 80:80 \
  bug-bounty-frontend
```

### Обновление

```bash
cd ~/bug-bounty
git pull origin master

# Пересборка бэкенда
docker build -t bug-bounty-backend ./backend
docker stop backend && docker rm backend
docker run -d --name backend --network bugbounty-net -p 8000:8000 -e DEEPSEEK_API_KEY=sk-xxx bug-bounty-backend

# Пересборка фронтенда
docker build -t bug-bounty-frontend ./frontend
docker stop bb-frontend && docker rm bb-frontend
docker run -d --name bb-frontend --network bugbounty-net -p 80:80 bug-bounty-frontend
```

---

## 12. Инструменты сканирования

Docker-образ бэкенда включает следующие инструменты безопасности:

| Инструмент | Назначение | Статус |
|------------|------------|--------|
| **nmap** | Сканирование портов и сервисов | ✅ Установлен |
| **nuclei** | Поиск уязвимостей по шаблонам | ✅ Установлен |
| **nikto** | Сканирование веб-серверов | ✅ Установлен |
| **sqlmap** | Поиск SQL-инъекций | ✅ Установлен |
| **httpx** | Проверка живых хостов, технологии | ✅ Установлен |
| **subfinder** | Поиск поддоменов | ✅ Установлен |
| **gobuster** | Перебор директорий | ✅ Установлен |
| **ffuf** | Фаззинг веб-приложений | ✅ Установлен |
| **gau** | Сбор исторических URL (Wayback) | ✅ Установлен |
| **wafw00f** | Определение WAF | ✅ Установлен |
| **whatweb** | Fingerprinting технологий | ⚠️ Опционально (Ruby) |
| **wpscan** | Сканирование WordPress | ⚠️ Опционально (Ruby) |

### Порядок выполнения при сканировании

1. **httpx** — проверка доступности, определение технологий
2. **wafw00f** — определение WAF
3. **subfinder** — поиск поддоменов
4. **nmap** — сканирование портов
5. **nuclei** — поиск уязвимостей по шаблонам
6. **nikto** — сканирование веб-сервера
7. **gobuster** — перебор директорий
8. **gau** — сбор исторических URL
9. **ffuf** — фаззинг параметров
10. **sqlmap** — проверка SQL-инъекций (если найдены параметры)

---

## 13. База знаний уязвимостей

Система автоматически обогащает найденные уязвимости информацией:

- **Описание** — что это за уязвимость
- **Шаги воспроизведения** — как проверить
- **Оценка влияния** — потенциальный ущерб (CVSS-подобная оценка)
- **Рекомендации** — как исправить
- **Ссылки** — OWASP, CWE, документация

### Поддерживаемые типы уязвимостей

- Missing SRI (Subresource Integrity)
- HTTP Security Headers (CSP, HSTS, X-Frame-Options, etc.)
- SQL Injection
- XSS (Cross-Site Scripting)
- Open Ports
- Subdomain Takeover
- Historical URLs / Information Disclosure
- WAF Detection
- Technology Fingerprint
- CORS Misconfiguration
- Directory Listing
- Git Config Exposure
- Sensitive Files Exposure
- SSL/TLS Issues

---

## 14. Лицензия

MIT License
