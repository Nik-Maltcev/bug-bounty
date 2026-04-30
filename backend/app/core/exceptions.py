"""Иерархия исключений Сканера сайтов.

Содержит все пользовательские исключения системы:
- SiteScannerError — базовое исключение
- ParseError — ошибка парсинга (HTTP 400)
- ComplianceViolationError — нарушение правил (HTTP 403)
- ScanError — ошибка сканирования (HTTP 500)
- InsufficientDataError — недостаточно данных (HTTP 422)
- AuthenticationError — ошибка аутентификации (HTTP 401)
- AccountLockedError — аккаунт заблокирован (HTTP 423)
"""

from datetime import datetime


class SiteScannerError(Exception):
    """Базовое исключение системы Сканера сайтов."""

    pass


# Обратная совместимость
BugBountyAgentError = SiteScannerError


class ParseError(SiteScannerError):
    """Ошибка парсинга программы.

    Возникает, когда невозможно извлечь данные из предоставленного источника.
    """

    def __init__(self, source: str, reason: str):
        self.source = source
        self.reason = reason
        super().__init__(f"Ошибка парсинга '{source}': {reason}")


class ComplianceViolationError(SiteScannerError):
    """Нарушение правил программы.

    Возникает при попытке выполнить действие, запрещённое правилами.
    """

    def __init__(self, action: str, rule: str, reason: str):
        self.action = action
        self.rule = rule
        self.reason = reason
        super().__init__(
            f"Действие '{action}' заблокировано правилом '{rule}': {reason}"
        )


class ScanError(SiteScannerError):
    """Ошибка сканирования.

    Возникает при критической ошибке во время сканирования сайта.
    """

    def __init__(self, scan_id: str, stage: str, reason: str):
        self.scan_id = scan_id
        self.stage = stage
        self.reason = reason
        super().__init__(
            f"Ошибка сканирования '{scan_id}' на этапе '{stage}': {reason}"
        )


class InsufficientDataError(SiteScannerError):
    """Недостаточно данных для генерации отчёта.

    Содержит список полей, которые необходимо заполнить.
    """

    def __init__(self, missing_fields: list[str]):
        self.missing_fields = missing_fields
        super().__init__(
            f"Недостаточно данных. Отсутствующие поля: {', '.join(missing_fields)}"
        )


class AuthenticationError(SiteScannerError):
    """Ошибка аутентификации.

    Возникает при неверных учётных данных или отсутствии токена.
    """

    pass


class AccountLockedError(AuthenticationError):
    """Аккаунт заблокирован после неудачных попыток входа.

    Содержит время, до которого аккаунт заблокирован.
    """

    def __init__(self, locked_until: datetime):
        self.locked_until = locked_until
        super().__init__(
            f"Аккаунт заблокирован до {locked_until.isoformat()}"
        )
