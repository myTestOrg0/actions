import json
from datetime import date

from harbor_helper.common import WorkflowError
from harbor_helper.vex_scope import scope_documents, scope_vex
from support import TemporaryTestCase

TODAY = date(2026, 11, 25)


def statement(name, repos=("lidofinance/widget",), expires="2027-01-23", status="not_affected"):
    result = {"vulnerability": {"name": name}, "products": [{"@id": "pkg:npm/next@12.3.7"}], "status": status}
    if repos is not None:
        result["whitelist_repositories"] = list(repos)
    if expires is not None:
        result["whitelist_expires"] = expires
    return result


class VexScopeTests(TemporaryTestCase):
    def write(self, *statements):
        self.repo = self.root / "vex" / "repositories" / "internal" / "0.1"
        (self.repo / "pkg/npm/next").mkdir(parents=True)
        (self.repo / "pkg/npm/next/vex.json").write_text(json.dumps({"statements": list(statements)}))
        (self.repo / "index.json").write_text(json.dumps({"packages": [
            {"id": "pkg:npm/next", "location": "pkg/npm/next/vex.json", "format": "openvex"}]}))

    def names(self):
        index = json.loads((self.repo / "index.json").read_text())
        if not index["packages"]:
            return []
        document = json.loads((self.repo / "pkg/npm/next/vex.json").read_text())
        return [s["vulnerability"]["name"] for s in document["statements"]]

    def test_keeps_only_own_unexpired_statements(self):
        self.write(statement("GHSA-own"), statement("GHSA-other", repos=["lidofinance/other"]),
                   statement("GHSA-expired", expires="2026-11-24"), statement("GHSA-lastday", expires="2026-11-25"),
                   statement("GHSA-unscoped", repos=None, expires=None),
                   statement("CVE-affected", repos=None, expires=None, status="affected"))
        scope_documents(self.repo, "lidofinance/widget", TODAY)
        self.assertEqual(self.names(), ["GHSA-own", "GHSA-lastday", "CVE-affected"])

    def test_empty_document_removed_from_index(self):
        self.write(statement("GHSA-other", repos=["lidofinance/other"]))
        scope_documents(self.repo, "lidofinance/widget", TODAY)
        self.assertEqual(self.names(), [])
        self.assertFalse((self.repo / "pkg/npm/next/vex.json").exists())

    def test_bad_expiry_fails_closed(self):
        self.write(statement("GHSA-x", expires="23.01.2027"))
        with self.assertRaises(WorkflowError):
            scope_documents(self.repo, "lidofinance/widget", TODAY)

    def test_missing_index_fails_closed(self):
        self.repo = self.root / "nothing"
        with self.assertRaises(WorkflowError):
            scope_documents(self.repo, "lidofinance/widget", TODAY)

    def test_command_writes_summary(self):
        self.write(statement("GHSA-own", expires="2099-01-01"))
        summary = self.root / "summary.md"
        scope_vex({"GITHUB_REPOSITORY": "lidofinance/widget", "VEX_CACHE_DIR": str(self.root),
                   "GITHUB_STEP_SUMMARY": str(summary)})
        self.assertIn("GHSA-own", summary.read_text())
