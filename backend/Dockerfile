FROM python:3.12-slim

# System tools + Ruby for whatweb/wpscan + Perl modules for nikto + fonts for PDF
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl git perl libnet-ssleay-perl libjson-perl \
    ruby ruby-dev build-essential libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev zlib1g-dev \
    unzip wget fontconfig \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Install Montserrat font from Google Fonts
RUN mkdir -p /usr/share/fonts/truetype/montserrat \
    && curl -sSL "https://github.com/JulietaUla/Montserrat/raw/master/fonts/ttf/Montserrat-Regular.ttf" -o /usr/share/fonts/truetype/montserrat/Montserrat-Regular.ttf \
    && curl -sSL "https://github.com/JulietaUla/Montserrat/raw/master/fonts/ttf/Montserrat-Bold.ttf" -o /usr/share/fonts/truetype/montserrat/Montserrat-Bold.ttf \
    && fc-cache -fv

# nikto (from git — not in Debian Trixie repos)
# Requires additional perl modules for full functionality
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && perl -MCPAN -e 'install JSON' 2>/dev/null || true

# nuclei (pre-built binary)
RUN NUCLEI_VERSION=$(curl -sSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ && rm /tmp/nuclei.zip

# httpx (pre-built binary) - renamed to httpx-pd to avoid conflict with Python httpx
RUN HTTPX_VERSION=$(curl -sSL https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" -o /tmp/httpx.zip \
    && unzip -o /tmp/httpx.zip -d /tmp/ && mv /tmp/httpx /usr/local/bin/httpx-pd && rm /tmp/httpx.zip

# subfinder (pre-built binary)
RUN SUBFINDER_VERSION=$(curl -sSL https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" -o /tmp/subfinder.zip \
    && unzip -o /tmp/subfinder.zip -d /usr/local/bin/ && rm /tmp/subfinder.zip

# gobuster (pre-built binary) - extract and find binary
RUN GOBUSTER_VERSION=$(curl -sSL https://api.github.com/repos/OJ/gobuster/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/OJ/gobuster/releases/download/v${GOBUSTER_VERSION}/gobuster_Linux_x86_64.tar.gz" -o /tmp/gobuster.tar.gz \
    && mkdir -p /tmp/gobuster && tar -xzf /tmp/gobuster.tar.gz -C /tmp/gobuster \
    && cp /tmp/gobuster/gobuster /usr/local/bin/gobuster 2>/dev/null || cp /tmp/gobuster/*/gobuster /usr/local/bin/gobuster 2>/dev/null || find /tmp/gobuster -type f -name "gobuster" -exec cp {} /usr/local/bin/gobuster \; \
    && chmod +x /usr/local/bin/gobuster && rm -rf /tmp/gobuster /tmp/gobuster.tar.gz

# ffuf (pre-built binary)
RUN FFUF_VERSION=$(curl -sSL https://api.github.com/repos/ffuf/ffuf/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" -o /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ && rm /tmp/ffuf.tar.gz

# gau (pre-built binary)
RUN GAU_VERSION=$(curl -sSL https://api.github.com/repos/lc/gau/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_amd64.tar.gz" -o /tmp/gau.tar.gz \
    && mkdir -p /tmp/gau && tar -xzf /tmp/gau.tar.gz -C /tmp/gau \
    && find /tmp/gau -name "gau" -type f -exec mv {} /usr/local/bin/gau \; \
    && chmod +x /usr/local/bin/gau && rm -rf /tmp/gau /tmp/gau.tar.gz

# dalfox - XSS scanner (download binary directly)
RUN curl -sSL "https://github.com/hahwul/dalfox/releases/latest/download/dalfox_linux_amd64" -o /usr/local/bin/dalfox \
    && chmod +x /usr/local/bin/dalfox \
    || echo "dalfox installation skipped"

# === NEW TOOLS FOR DEEP SCANNING ===

# trufflehog - secret scanner for git repos
RUN TRUFFLEHOG_VERSION=$(curl -sSL https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" -o /tmp/trufflehog.tar.gz \
    && mkdir -p /tmp/trufflehog && tar -xzf /tmp/trufflehog.tar.gz -C /tmp/trufflehog \
    && find /tmp/trufflehog -name "trufflehog" -type f -exec cp {} /usr/local/bin/trufflehog \; \
    && chmod +x /usr/local/bin/trufflehog && rm -rf /tmp/trufflehog /tmp/trufflehog.tar.gz \
    || echo "trufflehog installation skipped"

# gitleaks - secret scanner
RUN GITLEAKS_VERSION=$(curl -sSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -o /tmp/gitleaks.tar.gz \
    && mkdir -p /tmp/gitleaks && tar -xzf /tmp/gitleaks.tar.gz -C /tmp/gitleaks \
    && find /tmp/gitleaks -name "gitleaks" -type f -exec cp {} /usr/local/bin/gitleaks \; \
    && chmod +x /usr/local/bin/gitleaks && rm -rf /tmp/gitleaks /tmp/gitleaks.tar.gz \
    || echo "gitleaks installation skipped"

# assetfinder - subdomain discovery
RUN curl -sSL "https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-amd64-0.1.1.tgz" -o /tmp/assetfinder.tgz \
    && tar -xzf /tmp/assetfinder.tgz -C /usr/local/bin/ && rm /tmp/assetfinder.tgz \
    || echo "assetfinder installation skipped"

# katana - web crawler
RUN KATANA_VERSION=$(curl -sSL https://api.github.com/repos/projectdiscovery/katana/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip" -o /tmp/katana.zip \
    && unzip -o /tmp/katana.zip -d /usr/local/bin/ && rm /tmp/katana.zip \
    || echo "katana installation skipped"

# dnsx - DNS toolkit
RUN DNSX_VERSION=$(curl -sSL https://api.github.com/repos/projectdiscovery/dnsx/releases/latest | grep tag_name | cut -d'"' -f4 | tr -d v) \
    && curl -sSL "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_amd64.zip" -o /tmp/dnsx.zip \
    && unzip -o /tmp/dnsx.zip -d /usr/local/bin/ && rm /tmp/dnsx.zip \
    || echo "dnsx installation skipped"

# testssl.sh - SSL/TLS scanner
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl \
    || echo "testssl installation skipped"

# Python security tools (some may fail, that's ok)
RUN pip install --no-cache-dir sqlmap wafw00f 2>/dev/null || true
RUN pip install --no-cache-dir arjun 2>/dev/null || echo "arjun skipped"
RUN pip install --no-cache-dir git+https://github.com/devanshbatham/ParamSpider.git 2>/dev/null || echo "paramspider skipped"

# Ruby security tools (whatweb, wpscan) - optional, may fail
RUN gem install whatweb --no-document 2>/dev/null || echo "whatweb skipped"
RUN gem install wpscan --no-document 2>/dev/null || echo "wpscan skipped"

# === CMS SCANNERS ===

# joomscan - Joomla scanner (Perl)
RUN git clone --depth 1 https://github.com/OWASP/joomscan.git /opt/joomscan \
    && ln -s /opt/joomscan/joomscan.pl /usr/local/bin/joomscan \
    && chmod +x /opt/joomscan/joomscan.pl \
    || echo "joomscan installation skipped"

# droopescan - Drupal/SilverStripe/WordPress scanner
RUN pip install --no-cache-dir droopescan 2>/dev/null || echo "droopescan skipped"

# === INJECTION TOOLS ===

# commix - command injection exploiter
RUN pip install --no-cache-dir commix 2>/dev/null || echo "commix skipped"

# tplmap - SSTI scanner
RUN git clone --depth 1 https://github.com/epinna/tplmap.git /opt/tplmap \
    && pip install --no-cache-dir -r /opt/tplmap/requirements.txt 2>/dev/null || true \
    && ln -s /opt/tplmap/tplmap.py /usr/local/bin/tplmap \
    && chmod +x /opt/tplmap/tplmap.py \
    || echo "tplmap installation skipped"

# === JWT & AUTH TOOLS ===

# jwt_tool - JWT analyzer
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
    && pip install --no-cache-dir -r /opt/jwt_tool/requirements.txt 2>/dev/null || true \
    && ln -s /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool \
    && chmod +x /opt/jwt_tool/jwt_tool.py \
    || echo "jwt_tool installation skipped"

# === HTTP SMUGGLING ===

# smuggler - HTTP request smuggling detector
RUN git clone --depth 1 https://github.com/defparam/smuggler.git /opt/smuggler \
    && ln -s /opt/smuggler/smuggler.py /usr/local/bin/smuggler \
    && chmod +x /opt/smuggler/smuggler.py \
    || echo "smuggler installation skipped"

# === CORS SCANNER ===

# CORScanner - CORS misconfiguration scanner
RUN git clone --depth 1 https://github.com/chenjj/CORScanner.git /opt/corscanner \
    && pip install --no-cache-dir -r /opt/corscanner/requirements.txt 2>/dev/null || true \
    && ln -s /opt/corscanner/cors_scan.py /usr/local/bin/corscanner \
    && chmod +x /opt/corscanner/cors_scan.py \
    || echo "corscanner installation skipped"

# Create wordlist directory with multiple wordlists
RUN mkdir -p /usr/share/wordlists \
    && curl -sSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -o /usr/share/wordlists/common.txt \
    && curl -sSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt -o /usr/share/wordlists/directories-medium.txt \
    && curl -sSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api-endpoints.txt -o /usr/share/wordlists/api-endpoints.txt \
    && curl -sSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt -o /usr/share/wordlists/lfi.txt \
    && curl -sSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -o /usr/share/wordlists/subdomains.txt

# Cleanup
RUN apt-get purge -y build-essential && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# LLM API keys for AI analysis (Stage 2)
# Set via docker run -e ANTHROPIC_API_KEY=... or docker-compose
# Claude Opus 4.6 (Anthropic) - primary, DeepSeek - fallback
ENV ANTHROPIC_API_KEY=""
ENV DEEPSEEK_API_KEY=""

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
