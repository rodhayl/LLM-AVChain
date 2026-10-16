from __future__ import annotations

import os
import subprocess

PATTERNS = (
    "avchain.scripts.start_services",
    "avchain.ledger.service:app",
    "avchain.evidence.service:app",
    "avchain.consensus.service:app",
    "avchain.coverage.service:app",
    "avchain.validator.worker",
    "avchain.agent.worker",
    "streamlit run src/avchain/dashboard/app.py",
)


def _matching_process_ids() -> list[int]:
    if os.name != "nt":
        return []

    script = r"""
$patterns = @(
  'avchain.scripts.start_services',
  'avchain.ledger.service:app',
  'avchain.evidence.service:app',
  'avchain.consensus.service:app',
  'avchain.coverage.service:app',
  'avchain.validator.worker',
  'avchain.agent.worker',
  'streamlit run src/avchain/dashboard/app.py'
)
Get-CimInstance Win32_Process |
Where-Object { $_.CommandLine } |
ForEach-Object {
  $cmd = $_.CommandLine
  foreach ($pattern in $patterns) {
    if ($cmd -like ('*' + $pattern + '*')) {
      $_.ProcessId
      break
    }
  }
}
"""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        check=False,
    )
    process_ids: list[int] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.isdigit():
            process_ids.append(int(line))
    return process_ids


def stop_services() -> int:
    current_pid = os.getpid()
    seen: set[int] = set()
    process_ids: list[int] = []
    for process_id in _matching_process_ids():
        if process_id == current_pid or process_id in seen:
            continue
        seen.add(process_id)
        process_ids.append(process_id)
    for process_id in process_ids:
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process_id)],
                capture_output=True,
                check=False,
            )
        except OSError:
            continue
    return len(process_ids)


def main() -> None:
    stopped = stop_services()
    print(f"Stopped {stopped} LLM-AVChain process(es).")


if __name__ == "__main__":
    main()
