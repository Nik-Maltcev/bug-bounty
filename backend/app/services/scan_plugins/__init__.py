"""Пакет плагинов сканирования.

Содержит базовый класс ScanPlugin и реализации для разных типов активов:
- WebScanPlugin — веб-приложения (заглушка)
- SmartContractScanPlugin — смарт-контракты (заглушка)
- ApiScanPlugin — API-эндпоинты (заглушка)
- RealWebPlugin — реальное веб-сканирование (nmap, nuclei, nikto, sqlmap)
- RealContractPlugin — реальный анализ контрактов (slither, mythril)
- RealApiPlugin — реальное API-сканирование (ZAP, фаззинг)
"""

from app.services.scan_plugins.base import ScanPlugin
from app.services.scan_plugins.web_plugin import WebScanPlugin
from app.services.scan_plugins.smart_contract_plugin import SmartContractScanPlugin
from app.services.scan_plugins.api_plugin import ApiScanPlugin
from app.services.scan_plugins.real_web_plugin import RealWebPlugin
from app.services.scan_plugins.real_contract_plugin import RealContractPlugin
from app.services.scan_plugins.real_api_plugin import RealApiPlugin

__all__ = [
    "ScanPlugin",
    "WebScanPlugin",
    "SmartContractScanPlugin",
    "ApiScanPlugin",
    "RealWebPlugin",
    "RealContractPlugin",
    "RealApiPlugin",
]
