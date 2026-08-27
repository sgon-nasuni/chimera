# SPDX-FileCopyrightText: 2025-2026 Chimera-NAS Project Contributors
#
# SPDX-License-Identifier: Apache-2.0

"""End-to-end SMB pipeline test.

Drives the full multi-protocol lifecycle against a live daemon: create a user
with an SMB password, mount a memfs backend, expose it as an SMB share, connect
over SMB with the real smbclient binary, and verify the mount-in-use (409)
guard before tearing everything down.

Management operations go through the Python SDK client (what the CLI wraps);
the data path uses the system smbclient.
"""

import os
import shutil
import subprocess

import pytest
from chimera_admin import ChimeraAdminError

USER = "testuser1"
PASSWORD = "systest"
MOUNT = "smbmount"
SHARE = "smb1"
SHARE_PATH = "/smbmount"

# The daemon binds the privileged SMB port 445, and smbclient must be present.
# Skip cleanly elsewhere rather than fail.
pytestmark = [
    pytest.mark.skipif(
        shutil.which("smbclient") is None, reason="smbclient not installed"
    ),
    pytest.mark.skipif(
        os.geteuid() != 0,
        reason="daemon must bind privileged SMB port 445 (needs root)",
    ),
]


def _smbclient(host, share, user, password, command, timeout=30):
    """Run a single smbclient command against the server.

    Mirrors the invocation proven in the C smbclient_auth_test.c NTLM test:
    ``smbclient //host/share -U user%password -c '<command>'`` with no extra
    flags. Returns the CompletedProcess.
    """
    return subprocess.run(
        [
            "smbclient",
            f"//{host}/{share}",
            "-U",
            f"{user}%{password}",
            "-c",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class TestSmbPipeline:
    """Exercise the user -> mount -> share -> SMB access -> teardown flow."""

    def test_full_smb_pipeline(self, client, chimera_server):
        """Walk the entire pipeline end to end against the session daemon."""
        host, _ = chimera_server

        created = {"user": False, "mount": False, "share": False}
        try:
            # 1. User with an SMB password (stored plaintext; the server
            #    computes the NTLM hash on the fly).
            client.create_user(USER, uid=1000, gid=1000, smbpasswd=PASSWORD)
            created["user"] = True

            # 2. memfs mount; appears in the VFS namespace at /smbmount.
            client.create_mount(MOUNT, module="memfs", path="fs0")
            created["mount"] = True

            # 3. SMB share backed by that mount.
            client.create_share(SHARE, SHARE_PATH)
            created["share"] = True

            # 4. Data path: authenticate over SMB and list the share root.
            result = _smbclient(host, SHARE, USER, PASSWORD, "ls")
            assert result.returncode == 0, (
                "smbclient ls failed (rc="
                f"{result.returncode})\nstdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}"
            )

            # 5. Deleting the mount must fail while the share references it.
            with pytest.raises(ChimeraAdminError) as exc_info:
                client.delete_mount(MOUNT)
            assert exc_info.value.status_code == 409

            # 6. Remove the share, then the mount succeeds.
            client.delete_share(SHARE)
            created["share"] = False

            client.delete_mount(MOUNT)
            created["mount"] = False

            client.delete_user(USER)
            created["user"] = False
        finally:
            # Best-effort cleanup so a mid-test failure does not leak resources
            # into the session daemon shared with the other test modules.
            if created["share"]:
                try:
                    client.delete_share(SHARE)
                except ChimeraAdminError:
                    pass
            if created["mount"]:
                try:
                    client.delete_mount(MOUNT)
                except ChimeraAdminError:
                    pass
            if created["user"]:
                try:
                    client.delete_user(USER)
                except ChimeraAdminError:
                    pass


class TestSmbDefaultDataFork:
    """Regression test for issue #1476.

    "file::$DATA" (empty stream name, $DATA type) names a file's DEFAULT data
    fork per MS-FSCC 2.1.5.1.1 -- it is not an alternate data stream, and must
    always be openable even with named streams (ADS) disabled, which is the
    session daemon's default ("named_streams" is unset).  A genuine alternate
    stream ("file:altstream") must still be rejected in that configuration.
    """

    USER = "testuser1476"
    PASSWORD = "systest1476"
    MOUNT = "smbmount1476"
    SHARE = "smb1476"
    SHARE_PATH = "/smbmount1476"

    def test_default_data_fork_and_named_stream(self, client, chimera_server, tmp_path):
        host, _ = chimera_server

        created = {"user": False, "mount": False, "share": False}
        try:
            client.create_user(self.USER, uid=1001, gid=1001, smbpasswd=self.PASSWORD)
            created["user"] = True

            client.create_mount(self.MOUNT, module="memfs", path="fs0")
            created["mount"] = True

            client.create_share(self.SHARE, self.SHARE_PATH)
            created["share"] = True

            src = tmp_path / "src.txt"
            src.write_text("issue-1476")

            result = _smbclient(
                host, self.SHARE, self.USER, self.PASSWORD, f"put {src} readme.txt"
            )
            assert result.returncode == 0, (
                f"put failed (rc={result.returncode})\nstdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}"
            )

            # The default data fork, spelled out explicitly, must open like the
            # plain file (issue #1476) even though named streams are disabled.
            dst = tmp_path / "out.txt"
            result = _smbclient(
                host, self.SHARE, self.USER, self.PASSWORD,
                f"get readme.txt::$DATA {dst}"
            )
            assert result.returncode == 0, (
                "get of the default data fork (readme.txt::$DATA) failed "
                f"(rc={result.returncode})\nstdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}"
            )
            assert dst.read_text() == "issue-1476"

            # A genuine alternate data stream must still be rejected while
            # named streams remain disabled -- this behavior must not change.
            result = _smbclient(
                host, self.SHARE, self.USER, self.PASSWORD,
                "get readme.txt:altstream out2.txt"
            )
            assert result.returncode != 0
            assert "OBJECT_NAME_INVALID" in result.stdout + result.stderr

            client.delete_share(self.SHARE)
            created["share"] = False

            client.delete_mount(self.MOUNT)
            created["mount"] = False

            client.delete_user(self.USER)
            created["user"] = False
        finally:
            if created["share"]:
                try:
                    client.delete_share(self.SHARE)
                except ChimeraAdminError:
                    pass
            if created["mount"]:
                try:
                    client.delete_mount(self.MOUNT)
                except ChimeraAdminError:
                    pass
            if created["user"]:
                try:
                    client.delete_user(self.USER)
                except ChimeraAdminError:
                    pass
