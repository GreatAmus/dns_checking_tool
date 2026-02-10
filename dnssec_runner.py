import subprocess
from dataclasses import dataclass
from typing import List, Sequence, Optional


@dataclass(frozen=True)
class CommandResult:
    cmd: List[str]
    output: str
    timed_out: bool = False


class CommandRunner:
    """Small wrapper around subprocess.run with timeouts and consistent output."""

    def __init__(self, timeout_seconds: int = 20):
        self.timeout_seconds = int(timeout_seconds)

    def run(self, cmd: Sequence[str], timeout_seconds: Optional[int] = None) -> CommandResult:
        cmd_list = list(cmd)
        t = self.timeout_seconds if timeout_seconds is None else int(timeout_seconds)
        try:
            p = subprocess.run(cmd_list, capture_output=True, text=True, timeout=t)
            out = ((p.stdout or "") + "\n" + (p.stderr or "")).strip()
            return CommandResult(cmd=cmd_list, output=out, timed_out=False)
        except subprocess.TimeoutExpired:
            return CommandResult(cmd=cmd_list, output=f"[timeout after {t}s] {' '.join(cmd_list)}", timed_out=True)

    def dig(self, args: Sequence[str], timeout_seconds: Optional[int] = None) -> CommandResult:
        return self.run(["dig", *list(args)], timeout_seconds=timeout_seconds)

    def delv(self, args: Sequence[str], timeout_seconds: Optional[int] = None) -> CommandResult:
        return self.run(["delv", *list(args)], timeout_seconds=timeout_seconds)
