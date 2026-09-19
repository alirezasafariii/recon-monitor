from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from analysis_engine import run_analysis
from core import APP_VERSION, AppPaths, Database, json_dumps, utc_now
from passive_evidence_extractor import extract_passive_family_evidence
from stages import _httpx_record


class PassiveCloudStorageEvidenceTests(unittest.TestCase):
    def test_s3_listing_requires_container_root_xml_success(self):
        exposed = extract_passive_family_evidence(
            endpoint="https://acme-bucket.s3.amazonaws.com/",
            target="acme-bucket.s3.amazonaws.com",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "application/xml",
                "content_length": 4096,
                "response_xml_root": "ListBucketResult",
            },
        )
        self.assertTrue(exposed["cloud_object_listing_public_observed"])
        self.assertNotIn(
            "sensitive_cloud_object_publicly_readable_observed",
            exposed,
        )

        metadata_only = extract_passive_family_evidence(
            endpoint="https://acme-bucket.s3.amazonaws.com/?location",
            target="acme-bucket.s3.amazonaws.com",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "application/xml",
                "content_length": 128,
                "response_body": (
                    "<LocationConstraint "
                    "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                    "eu-west-1</LocationConstraint>"
                ),
            },
        )
        self.assertNotIn(
            "cloud_object_listing_public_observed",
            metadata_only,
        )

        ambiguous_root = extract_passive_family_evidence(
            endpoint="https://acme-bucket.s3.amazonaws.com/",
            target="acme-bucket.s3.amazonaws.com",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "application/xml",
                "content_length": 128,
            },
        )
        self.assertNotIn(
            "cloud_object_listing_public_observed",
            ambiguous_root,
        )

        gcs_listing = extract_passive_family_evidence(
            endpoint="https://storage.googleapis.com/acme-public",
            target="storage.googleapis.com",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "application/xml",
                "content_length": 1024,
                "response_body": (
                    "<?xml version=\"1.0\"?>"
                    "<ListBucketResult><Name>acme-public</Name>"
                    "</ListBucketResult>"
                ),
            },
        )
        self.assertTrue(
            gcs_listing["cloud_object_listing_public_observed"]
        )

        gcs_metadata = extract_passive_family_evidence(
            endpoint="https://storage.googleapis.com/acme-public?acl",
            target="storage.googleapis.com",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "application/xml",
                "content_length": 512,
                "response_body": "<AccessControlPolicy />",
            },
        )
        self.assertNotIn(
            "cloud_object_listing_public_observed",
            gcs_metadata,
        )

        website_like = extract_passive_family_evidence(
            endpoint="https://acme-bucket.s3.amazonaws.com/",
            target="acme-bucket.s3.amazonaws.com",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "text/html",
                "content_length": 4096,
            },
        )
        self.assertNotIn(
            "cloud_object_listing_public_observed",
            website_like,
        )

        route_only = extract_passive_family_evidence(
            endpoint="https://acme-bucket.s3.amazonaws.com/",
            target="acme-bucket.s3.amazonaws.com",
            details={"content_type": "application/xml"},
        )
        self.assertNotIn(
            "cloud_object_listing_public_observed",
            route_only,
        )

    def test_sensitive_cloud_object_requires_public_non_html_response(self):
        exposed = extract_passive_family_evidence(
            endpoint="https://storage.googleapis.com/acme-private/.env",
            target="storage.googleapis.com",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "text/plain",
                "content_length": 512,
            },
        )
        self.assertTrue(
            exposed["sensitive_cloud_object_publicly_readable_observed"]
        )

        benign = extract_passive_family_evidence(
            endpoint="https://storage.googleapis.com/acme-private/logo.png",
            target="storage.googleapis.com",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "image/png",
                "content_length": 512,
            },
        )
        self.assertNotIn(
            "sensitive_cloud_object_publicly_readable_observed",
            benign,
        )

        html_catch_all = extract_passive_family_evidence(
            endpoint="https://storage.googleapis.com/acme-private/.env",
            target="storage.googleapis.com",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "text/html",
                "content_length": 512,
            },
        )
        self.assertNotIn(
            "sensitive_cloud_object_publicly_readable_observed",
            html_catch_all,
        )

    def test_signed_or_denied_storage_is_control_evidence_not_public_exposure(self):
        signed = extract_passive_family_evidence(
            endpoint=(
                "https://acme-bucket.s3.amazonaws.com/.env"
                "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
                "&X-Amz-Credential=test"
                "&X-Amz-Signature=deadbeef"
            ),
            target="acme-bucket.s3.amazonaws.com",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "text/plain",
                "content_length": 512,
            },
        )
        self.assertTrue(signed["signed_access_required"])
        self.assertNotIn(
            "sensitive_cloud_object_publicly_readable_observed",
            signed,
        )

        denied = extract_passive_family_evidence(
            endpoint="https://account.blob.core.windows.net/private/secrets.json",
            target="account.blob.core.windows.net",
            details={
                "status_code": 403,
                "reachable": True,
                "content_type": "application/xml",
                "content_length": 256,
            },
        )
        self.assertTrue(denied["cloud_storage_private_policy_observed"])
        self.assertNotIn(
            "sensitive_cloud_object_publicly_readable_observed",
            denied,
        )

    def test_azure_listing_requires_explicit_list_operation(self):
        listing = extract_passive_family_evidence(
            endpoint=(
                "https://account.blob.core.windows.net/public"
                "?restype=container&comp=list"
            ),
            target="account.blob.core.windows.net",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "application/xml",
                "content_length": 4096,
            },
        )
        self.assertTrue(listing["cloud_object_listing_public_observed"])

        root_without_list = extract_passive_family_evidence(
            endpoint="https://account.blob.core.windows.net/public",
            target="account.blob.core.windows.net",
            details={
                "status_code": 200,
                "reachable": True,
                "content_type": "application/xml",
                "content_length": 4096,
            },
        )
        self.assertNotIn(
            "cloud_object_listing_public_observed",
            root_without_list,
        )

    def _project(self):
        temp = tempfile.TemporaryDirectory()
        paths = AppPaths.from_root(Path(temp.name))
        paths.ensure()
        db = Database(paths.db)
        now = utc_now()
        target = "acme-bucket.s3.amazonaws.com"
        db.execute(
            "INSERT INTO runs(id,version,status,started_at,finished_at,target_selector,target_count) "
            "VALUES('RUN-CLOUD',?,'success',?,?,?,1)",
            (APP_VERSION, now, now, target),
        )
        db.execute(
            "INSERT INTO run_targets(run_id,target,policy_hash,status,current_stage,started_at,finished_at,run_dir,baseline) "
            "VALUES('RUN-CLOUD',?,'policy','success','report',?,?,?,1)",
            (target, now, now, str(paths.output / "RUN-CLOUD")),
        )
        return temp, paths, db, now, target

    def test_httpx_listing_root_survives_storage_into_raw_analysis(self):
        temp, paths, db, now, target = self._project()
        try:
            listing = f"https://{target}/"
            db.execute(
                "INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    target,
                    listing,
                    "absolute_url",
                    "file",
                    95,
                    json_dumps([{"category": "file", "confidence": 95}]),
                    json_dumps(["stored cloud storage listing surface"]),
                    json_dumps(["httpx-fingerprint"]),
                    now,
                    now,
                    "RUN-CLOUD",
                ),
            )
            db.execute(
                "INSERT INTO endpoint_validations(target,endpoint,resolved_url,method,status_code,content_type,reachable,confidence,checked_at,last_run_id,error) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    target,
                    listing,
                    listing,
                    "GET",
                    200,
                    "application/xml",
                    1,
                    95,
                    now,
                    "RUN-CLOUD",
                    "",
                ),
            )

            parsed_url, record = _httpx_record(
                {
                    "url": listing,
                    "status_code": 200,
                    "content_type": "application/xml",
                    "content_length": 4096,
                    "webserver": "AmazonS3",
                    "extracts": {
                        "xml-root": [
                            "<?xml version=\"1.0\"?><ListBucketResult"
                        ]
                    },
                }
            )
            self.assertEqual(parsed_url, listing)
            self.assertEqual(
                record["response_xml_root"],
                "listbucketresult",
            )
            db.upsert_fingerprint(
                target,
                parsed_url,
                record,
                "fp-listing-root",
                "RUN-CLOUD",
            )
            stored = db.one(
                "SELECT response_xml_root FROM fingerprints "
                "WHERE target=? AND url=?",
                (target, listing),
            )
            self.assertEqual(
                stored["response_xml_root"],
                "listbucketresult",
            )

            result = run_analysis(paths, db, "RUN-CLOUD", target)
            rows = db.all(
                "SELECT endpoint FROM bug_candidates "
                "WHERE analysis_id=? AND bug_family='cloud_storage_exposure'",
                (result["analysis_id"],),
            )
            self.assertIn(
                listing,
                [str(row["endpoint"]) for row in rows],
            )
        finally:
            db.close()
            temp.cleanup()

    def _insert_surface(
        self,
        db,
        now,
        target,
        *,
        endpoint,
        status,
        content_type,
        content_length,
    ):
        db.execute(
            "INSERT INTO endpoint_intelligence(target,endpoint,kind,primary_category,confidence,categories_json,reasons_json,sources_json,first_seen,last_seen,last_run_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                target,
                endpoint,
                "absolute_url",
                "file",
                90,
                json_dumps([{"category": "file", "confidence": 90}]),
                json_dumps(["stored cloud storage surface"]),
                json_dumps(["passive-cloud-storage-test"]),
                now,
                now,
                "RUN-CLOUD",
            ),
        )
        db.execute(
            "INSERT INTO endpoint_validations(target,endpoint,resolved_url,method,status_code,content_type,reachable,confidence,checked_at,last_run_id,error) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                target,
                endpoint,
                endpoint,
                "GET",
                status,
                content_type,
                1,
                95,
                now,
                "RUN-CLOUD",
                "",
            ),
        )
        db.execute(
            "INSERT INTO fingerprints(target,url,fingerprint_hash,status_code,title,webserver,technologies_json,content_type,content_length,first_seen,last_seen,last_run_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                target,
                endpoint,
                "fp-" + str(abs(hash(endpoint))),
                status,
                "",
                "AmazonS3",
                "[]",
                content_type,
                content_length,
                now,
                now,
                "RUN-CLOUD",
            ),
        )

    def test_raw_analysis_promotes_only_concrete_public_cloud_storage_evidence(self):
        temp, paths, db, now, target = self._project()
        try:
            listing = f"https://{target}/"
            sensitive = f"https://{target}/backups/terraform.tfstate"
            benign = f"https://{target}/assets/logo.png"
            denied = f"https://{target}/private/secrets.json"

            self._insert_surface(
                db,
                now,
                target,
                endpoint=listing,
                status=200,
                content_type="application/xml",
                content_length=4096,
            )
            self._insert_surface(
                db,
                now,
                target,
                endpoint=sensitive,
                status=200,
                content_type="application/octet-stream",
                content_length=8192,
            )
            self._insert_surface(
                db,
                now,
                target,
                endpoint=benign,
                status=200,
                content_type="image/png",
                content_length=2048,
            )
            self._insert_surface(
                db,
                now,
                target,
                endpoint=denied,
                status=403,
                content_type="application/xml",
                content_length=512,
            )

            result = run_analysis(paths, db, "RUN-CLOUD", target)
            runtime = result["bug_candidates"]["detection_runtime"]
            self.assertIn(
                "cloud_storage_exposure",
                set(runtime["potential_finding_families"]),
            )

            rows = db.all(
                "SELECT endpoint FROM bug_candidates "
                "WHERE analysis_id=? AND bug_family='cloud_storage_exposure' "
                "ORDER BY endpoint",
                (result["analysis_id"],),
            )
            endpoints = [str(row["endpoint"]) for row in rows]
            self.assertNotIn(
                listing,
                endpoints,
                "root XML metadata without stored ListBucketResult must not "
                "be promoted as a public object listing",
            )
            self.assertIn(sensitive, endpoints)
            self.assertNotIn(benign, endpoints)
            self.assertNotIn(denied, endpoints)
            self.assertEqual(runtime["active_requests_added"], 0)
            self.assertFalse(runtime["collector_behavior_changed"])
        finally:
            db.close()
            temp.cleanup()


if __name__ == "__main__":
    unittest.main()
