import tempfile
import unittest
from pathlib import Path

from src.core.database import NetworkDatabase
from src.core.models import ScanJobState, validate_scan_job_transition


class ScanJobStateTests(unittest.TestCase):
    def test_valid_transition_and_terminal_state(self):
        validate_scan_job_transition(ScanJobState.NEW, ScanJobState.VALIDATING)
        with self.assertRaises(ValueError):
            validate_scan_job_transition(ScanJobState.NEW, ScanJobState.RUNNING)
        with self.assertRaises(ValueError):
            validate_scan_job_transition(ScanJobState.COMPLETED, ScanJobState.RUNNING)

    def test_scan_job_state_is_typed_string_enum(self):
        self.assertEqual(ScanJobState.RUNNING.value, "RUNNING")
        self.assertEqual(ScanJobState("FAILED"), ScanJobState.FAILED)


class ScanJobPersistenceTests(unittest.TestCase):
    def test_job_lifecycle_is_persisted_and_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            with NetworkDatabase(Path(directory) / "jobs.db") as database:
                job_id = database.create_scan_job("job-1", created_at="2026-01-01T00:00:00+00:00")
                database.update_scan_job_state(job_id, ScanJobState.VALIDATING)
                database.update_scan_job_state(job_id, "QUEUED")
                database.update_scan_job_state(job_id, ScanJobState.RUNNING)
                job = database.update_scan_job_state(
                    job_id, ScanJobState.FAILED, error_message="scanner failed"
                )

                self.assertEqual(job["state"], "FAILED")
                self.assertEqual(job["error_message"], "scanner failed")
                self.assertEqual(database.fetch_scan_job(job_id)["id"], "job-1")
                self.assertEqual(database.fetch_scan_jobs(ScanJobState.FAILED)[0]["id"], "job-1")
                with self.assertRaises(ValueError):
                    database.update_scan_job_state(job_id, ScanJobState.COMPLETED)

