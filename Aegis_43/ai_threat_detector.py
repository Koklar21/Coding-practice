from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Tuple

from .ai_threat_detector import EventContext, SequenceWindow


@dataclass
class RollingWindowConfig:
    window_seconds: float = 60.0
    max_events_per_key: int = 200
    max_payloads: int = 50


class RollingWindowStore:
    """
    Keeps short rolling windows per (identity, ip).
    Also keeps recent payloads for mutation/entropy scoring.
    """

    def __init__(self, cfg: Optional[RollingWindowConfig] = None) -> None:
        self.cfg = cfg or RollingWindowConfig()
        self._events: Dict[Tuple[str, str], Deque[EventContext]] = defaultdict(deque)
        self._payloads: Dict[Tuple[str, str], Deque[bytes]] = defaultdict(deque)

    def add(self, e: EventContext) -> None:
        key = (e.source_identity, e.source_ip)
        q = self._events[key]
        q.append(e)
        while len(q) > self.cfg.max_events_per_key:
            q.popleft()

        # payloads tracked separately
        if e.payload:
            pq = self._payloads[key]
            pq.append(e.payload)
            while len(pq) > self.cfg.max_payloads:
                pq.popleft()

        self._prune(key)

    def window(self, identity: str, ip: str) -> SequenceWindow:
        key = (identity, ip)
        self._prune(key)
        win = SequenceWindow()
        for e in self._events[key]:
            win.add_event(e)
        return win

    def payloads(self, identity: str, ip: str) -> List[bytes]:
        key = (identity, ip)
        self._prune(key)
        return list(self._payloads[key])

    def _prune(self, key: Tuple[str, str]) -> None:
        now = time.time()
        cutoff = now - self.cfg.window_seconds
        q = self._events[key]
        while q and q[0].timestamp < cutoff:
            q.popleft()

        # payloads: we don’t have timestamps on them, so keep bounded only
        # that’s fine because max_payloads is small