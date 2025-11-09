import argparse
import os
import sys
from datetime import datetime
from typing import List, Optional

import trustme

# ISO 8601
DATE_FORMAT = "%Y-%m-%d"


def main(argv: Optional[List[str]] = None) -> None:
    if argv is None:
        argv = sys.argv[1:]  # pragma: no cover (used in tests)

    parser = argparse.ArgumentParser(prog="trustme")
    parser.add_argument(
        "-d",
        "--dir",
        default=os.getcwd(),
        help="Directory where certificates and keys are written to. Defaults to cwd.",
    )
    parser.add_argument(
        "-i",
        "--identities",
        nargs="*",
        default=("localhost", "127.0.0.1", "::1"),
        help="Identities for the certificate. Defaults to 'localhost 127.0.0.1 ::1'.",
    )
    parser.add_argument(
        "--common-name",
        nargs=1,
        default=None,
        help="Also sets the deprecated 'commonName' field (only for the first identity passed).",
    )
    parser.add_argument(
        "-x",
        "--expires-on",
        default=None,
        help="Set the date the certificate will expire on (in YYYY-MM-DD format).",
        metavar="YYYY-MM-DD",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Doesn't print out helpful information for humans.",
    )
    parser.add_argument(
        "-k",
        "--key-type",
        choices=list(t.name for t in trustme.KeyType),
        default="ECDSA",
    )

    args = parser.parse_args(argv)
    cert_dir = args.dir
    identities = [str(identity) for identity in args.identities]
    common_name = str(args.common_name[0]) if args.common_name else None
    expires_on = (
        None
        if args.expires_on is None
        else datetime.strptime(args.expires_on, DATE_FORMAT)
    )
    quiet = args.quiet
    key_type = trustme.KeyType[args.key_type]

    if not os.path.isdir(cert_dir):
        raise ValueError(f"--dir={cert_dir} is not a directory")
    if len(identities) < 1:
        raise ValueError("Must include at least one identity")

    # Generate the CA certificate
    ca = trustme.CA(key_type=key_type)
    cert = ca.issue_cert(
        *identities, common_name=common_name, not_after=expires_on, key_type=key_type
    )

    # Write the certificate and private key the server should use
    server_key = os.path.join(cert_dir, "server.key")
    server_cert = os.path.join(cert_dir, "server.pem")
    cert.private_key_pem.write_to_path(path=server_key)
    with open(server_cert, mode="w") as f:
        f.truncate()
    for blob in cert.cert_chain_pems:
        blob.write_to_path(path=server_cert, append=True)

    # Write the certificate the client should trust
    client_cert = os.path.join(cert_dir, "client.pem")
    ca.cert_pem.write_to_path(path=client_cert)

    if not quiet:
        idents = "', '".join(identities)
        print(f"Generated a certificate for '{idents}'")
        print("Configure your server to use the following files:")
        print(f"  cert={server_cert}")
        print(f"  key={server_key}")
        print("Configure your client to use the following files:")
        print(f"  cert={client_cert}")
