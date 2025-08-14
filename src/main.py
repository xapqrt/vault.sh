"""Program entry point (CLI dispatcher).

Stealth routing is handled within CLI commands; main remains a thin wrapper.
"""
from __future__ import annotations
from src.cli.commands import cli

def main():  # pragma: no cover - thin wrapper
	cli()

if __name__ == '__main__':  # pragma: no cover
	main()

