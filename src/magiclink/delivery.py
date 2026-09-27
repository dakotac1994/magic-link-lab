"""Simulated email/SMS delivery with failure injection.

Real deployments plug in SendGrid/Twilio/etc. here. The lab simulates the
provider: every send lands in an in-memory outbox (so the demo and tests can
read the link back), with a configurable failure rate and a primary/secondary
failover pair -- the same pattern used in notification-lab.
"""

import random
from dataclasses import dataclass, field


@dataclass
class SentMessage:
    identifier: str
    channel: str
    link: str
    provider: str


class Provider:
    """One delivery provider (e.g. 'sendgrid' or 'twilio')."""

    def __init__(self, name: str, fail_rate: float = 0.0,
                 rng: random.Random | None = None):
        self.name = name
        self.fail_rate = fail_rate
        self._rng = rng or random.Random()
        self.outbox: list[SentMessage] = []

    def send(self, identifier: str, channel: str, link: str) -> bool:
        """Simulate a send. Returns False on injected failure."""
        if self._rng.random() < self.fail_rate:
            return False
        self.outbox.append(SentMessage(identifier, channel, link, self.name))
        return True


class DeliveryService:
    """Try the primary provider, fall back to secondary on failure."""

    def __init__(self, primary: Provider, secondary: Provider | None = None):
        self.primary = primary
        self.secondary = secondary
        self.failover_count = 0

    def deliver(self, identifier: str, channel: str, link: str) -> str:
        """Deliver a magic link; returns the name of the provider that
        succeeded. Raises RuntimeError if every provider fails."""
        if self.primary.send(identifier, channel, link):
            return self.primary.name
        self.failover_count += 1
        if self.secondary and self.secondary.send(identifier, channel, link):
            return self.secondary.name
        raise RuntimeError(f"all delivery providers failed for {identifier}")

    @property
    def outbox(self) -> list[SentMessage]:
        msgs = list(self.primary.outbox)
        if self.secondary:
            msgs += self.secondary.outbox
        return msgs

    def last_link_for(self, identifier: str) -> str | None:
        """Test/demo helper: read back the most recent link sent to someone."""
        ident = identifier.strip().lower()
        for msg in reversed(self.outbox):
            if msg.identifier == ident:
                return msg.link
        return None


def default_delivery() -> DeliveryService:
    return DeliveryService(Provider("sendgrid"), Provider("mailgun"))
