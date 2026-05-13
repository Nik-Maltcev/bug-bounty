"""Базовый класс для плагинов сканирования.

Определяет интерфейс, который должны реализовать все плагины сканирования.
Каждый плагин обрабатывает определённый тип актива (web, smart_contract, api).
"""

from abc import ABC, abstractmethod
from typing import Callable

from app.models.schemas import Asset, AssetType, RawFinding, ScanConfig

# Type alias for progress callback: (tool_name, tool_index, total_tools) -> None
ProgressCallback = Callable[[str, int, int], None]


class ScanPlugin(ABC):
    """Базовый класс для плагинов сканирования."""

    @abstractmethod
    def get_asset_type(self) -> AssetType:
        """Тип актива, который обрабатывает плагин."""
        ...

    @abstractmethod
    def get_check_names(self) -> list[str]:
        """Возвращает список названий проверок, выполняемых плагином."""
        ...

    @abstractmethod
    def scan(
        self, 
        asset: Asset, 
        config: ScanConfig,
        progress_callback: ProgressCallback | None = None,
    ) -> list[RawFinding]:
        """Выполняет сканирование актива.

        Args:
            asset: актив для сканирования.
            config: конфигурация сканирования.
            progress_callback: опциональный callback для обновления прогресса.
                Принимает (tool_name, tool_index, total_tools).

        Returns:
            Список сырых находок.
        """
        ...
