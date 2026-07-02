"""Filesystem scanning logic for removable media."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime
from pathlib import Path

from backend.database.malware_repository import MalwareHashRepository
from backend.models.scan import DeviceInfo, FileFinding, ScanReport, ScanSummary
from backend.scanner.risk_engine import RiskEngine


class FileScanner:
    """Scan a mounted filesystem and classify files by risk."""

    def __init__(self, repository: MalwareHashRepository, engine: RiskEngine | None = None) -> None:
        self.repository = repository
        self.engine = engine or RiskEngine()

    def scan_mount_path(self, mount_path: str, device: DeviceInfo | None = None) -> ScanReport:
        started_at = datetime.now()
        high_risk: list[FileFinding] = []
        medium_risk: list[FileFinding] = []
        low_risk: list[FileFinding] = []
        structural_flags: list[str] = []
        total_files = 0
        risk_score = 0

        for root, _, files in os.walk(mount_path):
            for filename in files:
                total_files += 1
                file_path = Path(root) / filename
                lower_name = filename.lower()
                size = self._safe_file_size(file_path)

                rule_applied = False

                if self.engine.is_suspicious_extension(lower_name):
                    high_risk.append(
                        FileFinding(
                            path=str(file_path),
                            size=size,
                            reason="Executable file",
                            category="high",
                            score_delta=3,
                        )
                    )
                    risk_score += 3
                    rule_applied = True
                elif self.engine.is_autorun(lower_name):
                    high_risk.append(
                        FileFinding(
                            path=str(file_path),
                            size=size,
                            reason="Autorun file",
                            category="high",
                            score_delta=5,
                        )
                    )
                    structural_flags.append("Autorun file detected")
                    risk_score += 5
                    rule_applied = True
                elif self.engine.is_hidden(filename):
                    medium_risk.append(
                        FileFinding(
                            path=str(file_path),
                            size=size,
                            reason="Hidden file",
                            category="medium",
                            score_delta=1,
                        )
                    )
                    risk_score += 1
                    rule_applied = True
                elif self.engine.is_double_extension(lower_name):
                    if self.engine.is_suspicious_extension(lower_name):
                        high_risk.append(
                            FileFinding(
                                path=str(file_path),
                                size=size,
                                reason="Double extension executable",
                                category="high",
                                score_delta=4,
                            )
                        )
                        risk_score += 4
                    else:
                        medium_risk.append(
                            FileFinding(
                                path=str(file_path),
                                size=size,
                                reason="Double extension file",
                                category="medium",
                                score_delta=2,
                            )
                        )
                        risk_score += 2
                    rule_applied = True

                sha256_hash = self._calculate_sha256(file_path)
                if sha256_hash:
                    signature = self.repository.lookup(sha256_hash)
                    if signature is not None:
                        high_risk.append(
                            FileFinding(
                                path=str(file_path),
                                size=size,
                                reason=f"Malware Detected: {signature.signature}",
                                category="high",
                                score_delta=10,
                            )
                        )
                        risk_score += 10
                        rule_applied = True

                if not rule_applied:
                    low_risk.append(
                        FileFinding(
                            path=str(file_path),
                            size=size,
                            reason="Normal file",
                            category="low",
                            score_delta=0,
                        )
                    )

        summary = ScanSummary(
            total_files=total_files,
            risk_score=risk_score,
            structural_flags=structural_flags,
        )
        return ScanReport(
            mount_path=mount_path,
            started_at=started_at,
            finished_at=datetime.now(),
            summary=summary,
            high_risk=high_risk,
            medium_risk=medium_risk,
            low_risk=low_risk,
            device=device,
        )

    @staticmethod
    def _safe_file_size(file_path: Path) -> int:
        try:
            return file_path.stat().st_size
        except OSError:
            return 0

    @staticmethod
    def _calculate_sha256(file_path: Path) -> str | None:
        sha256 = hashlib.sha256()
        chunk_size = 1024 * 1024
        try:
            with file_path.open("rb") as file_handle:
                while True:
                    chunk = file_handle.read(chunk_size)
                    if not chunk:
                        break
                    sha256.update(chunk)
        except OSError:
            return None
        return sha256.hexdigest()