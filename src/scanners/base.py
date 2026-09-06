import abc
import asyncio
import logging
import shutil
from typing import List, Optional, Dict, Any, Tuple

from ..database.models import Finding, Severity

logger = logging.getLogger(__name__)


class BaseScanner(abc.ABC):
    """Abstract base class for security scanners."""

    def __init__(self, name: str, custom_bin_path: str = ""):
        self.name = name
        self.custom_bin_path = custom_bin_path.strip()

    def get_executable(self, default_cmd: str) -> Optional[str]:
        """Find the executable path from custom configuration or system PATH."""
        if self.custom_bin_path:
            return self.custom_bin_path
        return shutil.which(default_cmd)

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Check whether the scanner tool/service is available for use."""
        pass

    @abc.abstractmethod
    async def scan(self, domain: str, **kwargs: Any) -> List[Finding]:
        """Execute the scan against the authorized domain and return normalized findings."""
        pass

    async def run_subprocess(
        self,
        args: List[str],
        timeout: int = 180,
        cwd: Optional[str] = None
    ) -> Tuple[int, str, str]:
        """Execute a scanner CLI command safely as a background subprocess."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return (
                proc.returncode or 0,
                stdout_b.decode("utf-8", errors="replace"),
                stderr_b.decode("utf-8", errors="replace")
            )
        except asyncio.TimeoutError:
            logger.warning(f"Scanner {self.name} timed out after {timeout}s on command {args}")
            try:
                proc.kill()
            except Exception:
                pass
            return (-1, "", f"Scanner timed out after {timeout} seconds")
        except Exception as e:
            logger.error(f"Error running subprocess for {self.name}: {e}")
            return (-1, "", str(e))
