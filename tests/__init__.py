"""Unit tests for the WinSentinel core engine.

Run with::

    python -m unittest discover -s tests -v

These tests are read-only. They never change firewall, DNS, Defender, UAC,
or registry settings; system calls are replaced with deterministic fakes.
"""

