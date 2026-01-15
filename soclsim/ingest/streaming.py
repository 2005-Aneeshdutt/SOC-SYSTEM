"""Streaming log ingestion with auto-refresh support."""

from __future__ import annotations

import time
from pathlib import Path
from threading import Thread
from typing import Callable, Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from soclsim.logs.real_parsers import parse_real_log, detect_log_format
from soclsim.logs.parsers import NormalizedEvent


class LogFileHandler(FileSystemEventHandler):
    """Watch for new log files and parse them."""
    
    def __init__(self, callback: Callable[[list[NormalizedEvent]], None], log_dir: Path):
        self.callback = callback
        self.log_dir = log_dir
        self.processed_files = set()
    
    def on_created(self, event):
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        if file_path in self.processed_files:
            return
        
        # Wait a bit for file to be fully written
        time.sleep(1)
        
        try:
            events = list(parse_real_log(file_path))
            if events:
                self.callback(events)
                self.processed_files.add(file_path)
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")


def start_streaming_ingestion(
    log_dir: str | Path,
    callback: Callable[[list[NormalizedEvent]], None],
    check_interval: float = 5.0
) -> Observer:
    """Start watching a directory for new log files and ingest them.
    
    Args:
        log_dir: Directory to watch for log files
        callback: Function to call with parsed events
        check_interval: How often to check for new files (seconds)
        
    Returns:
        Observer instance (call stop() to stop watching)
    """
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    
    handler = LogFileHandler(callback, log_path)
    observer = Observer()
    observer.schedule(handler, str(log_path), recursive=False)
    observer.start()
    
    return observer

