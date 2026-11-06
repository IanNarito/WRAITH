"""PluginRegistry: discovers BaseCheck subclasses under ``wraith.checks`` at runtime."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import re
from collections.abc import Sequence

from wraith.checks.base import BaseCheck
from wraith.models import Severity

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")


class RegistryError(ValueError):
    """Unknown, duplicate, or misdeclared check."""


class PluginRegistry:
    def __init__(self, package: str = "wraith.checks") -> None:
        self._package = package
        self._checks: dict[str, type[BaseCheck]] | None = None

    @property
    def checks(self) -> dict[str, type[BaseCheck]]:
        """All discovered check classes by name, sorted by name."""
        if self._checks is None:
            self._checks = self._discover()
        return self._checks

    def _discover(self) -> dict[str, type[BaseCheck]]:
        package = importlib.import_module(self._package)
        found: dict[str, type[BaseCheck]] = {}
        for info in pkgutil.iter_modules(package.__path__, prefix=f"{self._package}."):
            try:
                module = importlib.import_module(info.name)
            except Exception as exc:
                raise RegistryError(f"failed to load check module {info.name}: {exc}") from exc
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BaseCheck)
                    and obj is not BaseCheck
                    and obj.__module__ == module.__name__
                    and not inspect.isabstract(obj)
                ):
                    _validate(obj)
                    if obj.name in found:
                        raise RegistryError(
                            f"duplicate check name {obj.name!r} in {found[obj.name].__module__} "
                            f"and {obj.__module__}"
                        )
                    found[obj.name] = obj
        return dict(sorted(found.items()))

    def select(
        self,
        include: Sequence[str] = (),
        exclude: Sequence[str] = (),
        *,
        safe_mode: bool = True,
    ) -> list[BaseCheck]:
        """Instantiate the checks to run, honoring --checks / --exclude and safe mode."""
        available = self.checks
        unknown = [n for n in (*include, *exclude) if n not in available]
        if unknown:
            raise RegistryError(
                f"unknown check(s): {', '.join(unknown)}. Available: {', '.join(available)}"
            )
        if include:
            names = list(dict.fromkeys(include))
        else:
            names = [n for n, cls in available.items() if cls.enabled_by_default]
        excluded = set(exclude)

        selected: list[BaseCheck] = []
        for name in names:
            if name in excluded:
                continue
            cls = available[name]
            if cls.requires_aggressive and safe_mode:
                if include:
                    raise RegistryError(f"check {name!r} can change state; it needs --aggressive")
                continue
            selected.append(cls())
        return selected


def _validate(cls: type[BaseCheck]) -> None:
    for attr in ("name", "severity_hint", "description"):
        if not hasattr(cls, attr):
            raise RegistryError(f"{cls.__module__}.{cls.__name__} is missing {attr!r}")
    if not _NAME_RE.match(cls.name):
        raise RegistryError(f"check name {cls.name!r} must be snake_case")
    if not isinstance(cls.severity_hint, Severity):
        raise RegistryError(f"{cls.name}: severity_hint must be a Severity")
