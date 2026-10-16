"""Owned inert fixtures and fixed templates for the bounded lab only.

Adapted as data from VSCodeAntivir's install-hook/canary/egress test families.
No sample payload, credential path, external destination, or third-party code
is copied or executed. The application and extension remain separate projects.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from avchain.incident.models import (
    ActionTemplate,
    RemediationPackage,
    TransferCaseContext,
    TransferGrant,
    TransferObservation,
)
from avchain.utils.helpers import compute_sha256

CANARY = "AVCHAIN_OWNED_LAB_CANARY_NO_SECRET"
HOOK_BODY = """from pathlib import Path
import http.client
import os
# Owned fixture: reads only its adjacent artificial token and uses loopback.
data = Path(__file__).with_name("AVCHAIN_CANARY.txt").read_text()
connection = http.client.HTTPConnection(
    "127.0.0.1", int(os.environ["AVCHAIN_DEMO_PORT"]), timeout=3
)
connection.request("POST", "/owned-canary", body=data)
connection.getresponse().read()
connection.close()
"""


def transfer_case(
    observation: TransferObservation, *, grant_transfer: bool
) -> TransferCaseContext:
    """The lab operator supplies one concrete grant record, never a verdict."""
    resource_id = compute_sha256(b"AVCHAIN_CANARY.txt")
    return TransferCaseContext(
        resource_artifact_id=resource_id,
        grant_records_complete=True,
        grants=[
            TransferGrant(
                actor_artifact_id=observation.actor_artifact_id,
                resource_artifact_id=resource_id,
            )
        ]
        if grant_transfer
        else [],
        observation=observation,
    )


def create_lab_fixture(
    root: Path, *, variant: bool = False, benign: bool = False
) -> None:
    root.mkdir(parents=True, exist_ok=False)
    hook = "prepare" if variant else "postinstall"
    filename = "setup_check.py" if variant else "install_check.py"
    body = "print('ordinary local build')\n" if benign else HOOK_BODY
    if variant and not benign:
        body = "# Held-out filename and lifecycle hook; same safe behavior.\n" + body
    (root / filename).write_text(body)
    (root / "package.json").write_text(
        json.dumps(
            {
                "name": "owned-lab-project",
                "version": "0.0.0",
                "private": True,
                "scripts": {hook: f"python3 {filename}"},
            },
            indent=2,
        )
    )
    (root / "AVCHAIN_CANARY.txt").write_text(CANARY)


def draft_lab_package(
    entry_id: UUID, evidence_digests: list[str]
) -> RemediationPackage:
    now = datetime.now(UTC)
    return RemediationPackage(
        package_id="owned-hook-containment",
        version=1,
        entry_id=entry_id,
        title="Contain a validated install-hook canary simulation",
        rationale=(
            "Local, reversible containment of a demonstrated lab behavior; "
            "not a malware verdict."
        ),
        evidence_digests=evidence_digests,
        issued_at=now,
        expires_at=now + timedelta(hours=1),
        actions=[
            ActionTemplate(
                action_id="disable-hook",
                operation="disable_npm_hook",
                required_tags=["install_hook_manifest"],
            ),
            ActionTemplate(
                action_id="quarantine-hook",
                operation="quarantine_file",
                required_tags=["install_hook_target", "canary_read", "loopback_egress"],
            ),
        ],
        source_references=[
            "https://github.com/rodhayl/VSCodeAntivir",
            "docs/INCIDENT_RESPONSE.md",
        ],
    )
