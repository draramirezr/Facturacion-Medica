"""Descarga XSD oficial DGII y calcula SHA-256 (LF)."""
import hashlib
import sys
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "https://dgii.gov.do"
PATH = (
    "/cicloContribuyente/facturacion/comprobantesFiscalesElectronicosE-CF/"
    "Documentacin sobre eCF/Documentación Técnica (XSD)/"
)


def canonical_bytes(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def download(filename: str, dest: Path) -> str:
    url = BASE + urllib.parse.quote(PATH + filename, safe="/:%")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    data = urllib.request.urlopen(req, timeout=120).read()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    digest = hashlib.sha256(canonical_bytes(data)).hexdigest()
    print(f"OK {dest.name} bytes={len(data)} sha256={digest}")
    return digest


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1] / "ecf" / "schemas"
    which = sys.argv[1] if len(sys.argv) > 1 else "32"
    if which == "32":
        download("e-CF 32 v.1.0.xsd", root / "e-CF-32-v1.0.xsd")
    elif which == "31":
        download("e-CF 31 v.1.0.xsd", root / "e-CF-31-v1.0.xsd.verify")
    else:
        raise SystemExit("uso: download_ecf_xsd.py [31|32]")