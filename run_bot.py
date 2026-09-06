"""
Launcher for Website Security Health-Check Telegram Bot.
Usage: python run_bot.py
"""
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.bot.main import main

if __name__ == "__main__":
    main()
