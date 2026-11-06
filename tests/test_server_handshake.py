"""TLS handshake integration test for the remote trust witness."""

from __future__ import annotations

import base64
import ipaddress
import ssl
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

from remote_trust_bridge import RemoteTrustBridge
from sensor_trust_server import build_server


class ServerTLSHandshakeTests(unittest.TestCase):
    """Exercise the real client against a TLS-wrapped loopback server."""

    def test_tls_handshake_and_signed_genesis_head(self) -> None:
        transport_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
        ])
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(transport_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=7))
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False,
            )
            .sign(transport_key, hashes.SHA256())
        )

        signing_key = ed25519.Ed25519PrivateKey.generate()
        raw_signing_key = signing_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        encoded_signing_key = base64.urlsafe_b64encode(raw_signing_key).rstrip(b"=").decode("ascii")
        trusted_public_key = signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            certificate_path = directory / "server.crt"
            private_key_path = directory / "server.key"
            database_path = directory / "witness.sqlite3"
            certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            private_key_path.write_bytes(
                transport_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

            server = build_server(
                database_path=database_path,
                host="127.0.0.1",
                port=0,
                auth_token="tls-integration-secret",
                private_key_value=encoded_signing_key,
                key_id="tls-integration-key",
                certfile_path=str(certificate_path),
                keyfile_path=str(private_key_path),
            )
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            try:
                self.assertEqual(
                    cast(ssl.SSLSocket, server.socket).context.minimum_version,
                    ssl.TLSVersion.TLSv1_2,
                )
                client_tls_context = ssl.create_default_context(cafile=str(certificate_path))
                client = RemoteTrustBridge(
                    base_url=f"https://127.0.0.1:{server.server_address[1]}",
                    token="tls-integration-secret",
                    target_id="tls-handshake-sensor",
                    trusted_public_keys={"tls-integration-key": trusted_public_key},
                    ssl_context=client_tls_context,
                )

                head = client.fetch_expected_chain_head()

                self.assertEqual(head.target_id, "tls-handshake-sensor")
                self.assertEqual(head.sequence, 0)
                self.assertEqual(head.chain_hash, "0" * 64)
                self.assertEqual(head.checkpoint_id, "genesis")
                self.assertEqual(head.key_id, "tls-integration-key")
            finally:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=5)
                self.assertFalse(server_thread.is_alive(), "TLS witness server did not stop cleanly.")

    def test_non_loopback_bind_requires_tls(self) -> None:
        with self.assertRaisesRegex(ValueError, "TLS is required"):
            build_server(
                host="0.0.0.0",
                port=0,
                auth_token="production-config-test",
                private_key_value="not-needed-before-bind-validation",
            )


if __name__ == "__main__":
    unittest.main()
