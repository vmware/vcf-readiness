"""Ephemeral remote execution on Linux jump hosts.

The web server stays on 127.0.0.1. This package SSHes out to a jump host
and runs a short-lived copy of the collector under /tmp.
"""
