FROM python:3.12-slim

# System tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl git perl libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/*

# nikto (from git — not in Debian Trixie repos)
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# nuclei (pre-built binary — faster than go install)
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(curl -sSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v)_linux_amd64.zip -o /tmp/nuclei.zip \
    && apt-get update && apt-get install -y --no-install-recommends unzip && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip && apt-get purge -y unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Python security tools (optional — skip failures)
RUN pip install --no-cache-dir sqlmap 2>/dev/null || true

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create default user on first run
RUN python -c "\
from app.core.database import init_db, SessionLocal; \
from app.core.auth import hash_password; \
from app.models.database import User; \
import uuid; \
init_db(); \
db = SessionLocal(); \
db.add(User(id=str(uuid.uuid4()), username='admin', password_hash=hash_password('admin'))); \
db.commit(); db.close(); \
print('Default user created: admin/admin')"

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
