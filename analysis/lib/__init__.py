"""Typed helper library for the Olaitan analysis pipeline (Story 5.5).

Each module owns one concern (one statistical or aggregation responsibility) so
the AC5 per-helper unit tests stay clean and ``mypy --strict`` can check each
signature in isolation. ``analyse.py`` is a thin ``main()`` that composes them.
"""
