FROM python:3.12-slim

# System tools + Ruby for whatweb/wpscan
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl git perl libnet-ssleay-perl \
    ruby ruby-dev build-essential libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev zlib1g-dev \
    unzip wget \
    && rm -rf /var/lib/apt/lists/*

# nikto (from git — not in Debian Trixie repos)
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# nuclei (pre-built binary)
RUN NUCLEI_VERSION=$(curl -sSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ && rm /tmp/nuclei.zip

# httpx (pre-built binary)
RUN HTTPX_VERSION=$(curl -sSL https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" -o /tmp/httpx.zip \
    && unzip /tmp/httpx.zip -d /usr/local/bin/ && rm /tmp/httpx.zip

# subfinder (pre-built binary)
RUN SUBFINDER_VERSION=$(curl -sSL https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" -o /tmp/subfinder.zip \
    && unzip /tmp/subfinder.zip -d /usr/local/bin/ && rm /tmp/subfinder.zip

# gobuster (pre-built binary)
RUN GOBUSTER_VERSION=$(curl -sSL https://api.github.com/repos/OJ/gobuster/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/OJ/gobuster/releases/download/v${GOBUSTER_VERSION}/gobuster_Linux_x86_64.tar.gz" -o /tmp/gobuster.tar.gz \
    && tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin/ gobuster && rm /tmp/gobuster.tar.gz

# ffuf (pre-built binary)
RUN FFUF_VERSION=$(curl -sSL https://api.github.com/repos/ffuf/ffuf/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" -o /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf && rm /tmp/ffuf.tar.gz

# gau (pre-built binary)
RUN GAU_VERSION=$(curl -sSL https://api.github.com/repos/lc/gau/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_amd64.tar.gz" -o /tmp/gau.tar.gz \
    && tar -xzf /tmp/gau.tar.gz -C /usr/local/bin/ gau && rm /tmp/gau.tar.gz

# dalfox (pre-built binary)
RUN DALFOX_VERSION=$(curl -sSL https://api.github.com/repos/hahwul/dalfox/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox_${DALFOX_VERSION}_linux_amd64.tar.gz" -o /tmp/dalfox.tar.gz \
    && tar -xzf /tmp/dalfox.tar.gz -C /usr/local/bin/ dalfox && rm /tmp/dalfox.tar.gz

# Python security tools
RUN pip install --no-cache-dir sqlmap wafw00f 2>/dev/null || true

# Ruby security tools (whatweb, wpscan)
RUN gem install whatweb --no-document 2>/dev/null || true
RUN gem install wpscan --no-document 2>/dev/null || true

# Create wordlist directory with common wordlist
RUN mkdir -p /usr/share/wordlists \
    && curl -sSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -o /usr/share/wordlists/common.txt

# Cleanup
RUN apt-get purge -y build-essential && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

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
