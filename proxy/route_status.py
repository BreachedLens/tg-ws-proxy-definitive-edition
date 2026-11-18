"""Last successfully used Telegram transport and update listeners."""
from __future__ import annotations

from typing import Callable, List

_active_route = ""
_listeners: List[Callable[[str], None]] = []


def get_active_route() -> str:
    return _active_route


def clear_active_route() -> None:
    set_active_route("")


def set_active_route(route: str) -> None:
    global _active_route
    _active_route = str(route)
    for listener in tuple(_listeners):
        try:
            listener(_active_route)
        except Exception:
            # A tray/UI listener must not affect proxy connection handling.
            pass


def add_route_listener(listener: Callable[[str], None]) -> None:
    if listener not in _listeners:
        _listeners.append(listener)


def remove_route_listener(listener: Callable[[str], None]) -> None:
    try:
        _listeners.remove(listener)
    except ValueError:
        pass
