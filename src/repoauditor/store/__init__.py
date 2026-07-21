"""Findings store — the only module allowed to touch SQLite.

See CLAUDE.md: no other module opens a connection, writes SQL, or knows the DB path.
"""
