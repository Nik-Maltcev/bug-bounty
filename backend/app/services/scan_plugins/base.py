"""Базовый класс для плагинов сканирования.

Определяет интерфейс, который должны реализовать все плагины сканирования.
Каждый плагин обрабатывает определённый тип актива (web, smart_contract, api).
"""

from abc import ABC, abstractmethod

from app.models.schemas import Asset, AssetType, RawFinding, ScanConfig


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
    def scan(self, asset: Asset, config: ScanConfig) -> list[RawFinding]:
        """Выполняет сканирование актива.

        Args:
            asset: актив для сканирования.
            config: конфигурация сканирования.

        Returns:
            Список сырых находок.
        """
        ...
