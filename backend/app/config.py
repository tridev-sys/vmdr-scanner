from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All settings are read from VMDR_* environment variables (or backend/.env)."""

    model_config = SettingsConfigDict(env_prefix="VMDR_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./data/vmdr.db"

    # Scratch space for per-run target files and nuclei output.
    # Must be on storage shared by API and worker: the API reads live output from here.
    scan_workdir: Path = Path("data/scans")
    nuclei_bin: str = "/usr/local/bin/nuclei"
    nuclei_rate_limit: int = 50
    nuclei_concurrency: int = 10
    # Hosts Nuclei works on in parallel per template (Nuclei's own default is 25).
    nuclei_bulk_size: int = 50
    # Targets per Nuclei process, and how many processes run at once within one scan run.
    scan_chunk_size: int = 10
    scan_parallel_chunks: int = 3
    # Newest CVE years are scanned first (0 disables). Templates live under <dir>/**/cves/<year>.
    recent_cve_years: int = 2
    # Scans that may run at the same time. Runs with overlapping targets never run together.
    max_concurrent_runs: int = 5
    # Scan reports older than this are deleted by the worker.
    report_retention_days: int = 5
    nuclei_templates_dir: str = "/home/vmdr/nuclei-templates"
    nuclei_retries: int = 1
    nuclei_timeout: int = 5
    nuclei_severities: str = "critical,high,medium"
    nuclei_run_timeout_s: int = 6 * 3600
    nuclei_template_update_timeout_s: int = 1800

    template_update_hours: int = 24
    full_scan_cron: str = "0 2 * * *"
    # A finding must be missing from this many consecutive completed cycles before it is RESOLVED.
    resolve_after_misses: int = 2
    worker_poll_seconds: float = 3.0

    # If set, mutating API calls require the X-API-Key header.
    api_key: str | None = None
    cors_origins: str = "http://localhost:5173"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def severity_list(self) -> list[str]:
        return [s.strip().lower() for s in self.nuclei_severities.split(",") if s.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
