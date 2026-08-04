"""Test package marker.

Present so the suite is importable as ``tests.*`` — several modules do
``from tests.conftest import FakeLLM`` to share fake LLM/tool doubles, which
fails to collect without this file.
"""
