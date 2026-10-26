"""WinSentinel service container."""

from __future__ import annotations

from dataclasses import dataclass, field

from core.auditor import Auditor
from core.dns_manager import DNSManager
from core.firewall_manager import FirewallManager
from core.hardener import Hardener
from core.policy_manager import PolicyManager
from core.security_tools import PassphraseGenerator


@dataclass(slots=True)
class Services:
    policy_manager: PolicyManager = field(default_factory=PolicyManager)
    firewall_manager: FirewallManager = field(default_factory=FirewallManager)
    dns_manager: DNSManager = field(default_factory=DNSManager)
    auditor: Auditor = field(init=False)
    hardener: Hardener = field(init=False)
    passphrases: PassphraseGenerator = field(default_factory=PassphraseGenerator)

    def __post_init__(self) -> None:
        self.auditor = Auditor(policy_manager=self.policy_manager)
        self.hardener = Hardener(
            auditor=self.auditor,
            dns_manager=self.dns_manager,
            firewall_manager=self.firewall_manager,
            policy_manager=self.policy_manager,
        )
