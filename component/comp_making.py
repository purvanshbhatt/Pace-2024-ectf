from pathlib import Path
import re
import secrets
from pathlib import Path
import hashlib
import hmac
import re


def _read_file(path: Path) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _parse_define(text: str, name: str) -> str:
    pattern = rf"#define\s+{re.escape(name)}\s+(.+)"
    match = re.search(pattern, text)
    if not match:
        raise ValueError(f"Missing {name} in ectf_params.h")
    return match.group(1).strip()


def _parse_c_array(text: str, name: str) -> bytes:
    pattern = rf"{re.escape(name)}\s*\[[^\]]+\]\s*=\s*\{{([^}}]+)\}}"
    match = re.search(pattern, text)
    if not match:
        raise ValueError(f"Missing {name} in global_secrets.h")
    values = [v.strip() for v in match.group(1).split(",") if v.strip()]
    return bytes(int(v, 16) for v in values)


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def _format_bytes(name: str, data: bytes) -> str:
    hex_representation = ", ".join(f"0x{b:02X}" for b in data)
    return f"static const uint8_t {name}[{len(data)}] = {{ {hex_representation} }};"


def main() -> None:
    params_text = _read_file(Path("./inc/ectf_params.h"))
    secrets_text = _read_file(Path("../deployment/global_secrets.h"))

    component_id_str = _parse_define(params_text, "COMPONENT_ID")
    component_id = int(component_id_str, 16)

    deployment_id = _parse_c_array(secrets_text, "DEPLOYMENT_ID")
    kmaster = _parse_c_array(secrets_text, "KMASTER")

    info = b"KC" + component_id.to_bytes(4, "big")
    kc = _hkdf_sha256(kmaster, deployment_id, info, 16)

    with open(Path("./inc/component_secrets.h"), "w", encoding="utf-8") as fh:
        fh.write("#ifndef COMPONENT_SECRETS_H\n")
        fh.write("#define COMPONENT_SECRETS_H\n\n")
        fh.write("#include <stdint.h>\n\n")
        fh.write(_format_bytes("COMPONENT_KC", kc) + "\n")
        fh.write(_format_bytes("COMPONENT_DEPLOYMENT_ID", deployment_id) + "\n\n")
        fh.write("#endif\n")

    legacy_key = _hkdf_sha256(kmaster, deployment_id, b"LEGACY_KEY", 16)
    legacy_mask = _hkdf_sha256(kmaster, deployment_id, b"LEGACY_MASK", 16)
    legacy_final = _hkdf_sha256(kmaster, deployment_id, b"LEGACY_FINAL", 16)

    with open(Path("./inc/key.h"), "w", encoding="utf-8") as fh:
        fh.write("#ifndef __KEY__\n")
        fh.write("#define __KEY__\n")
        fh.write("#include <stdint.h>\n\n")
        fh.write("extern const uint8_t KEY_SHARE[16];\n")
        fh.write("extern const uint8_t MASK[16];\n")
        fh.write("extern const uint8_t FINAL_MASK[16];\n")
        fh.write("#endif\n")

    with open(Path("./src/key.c"), "w", encoding="utf-8") as fh:
        fh.write("#include \"key.h\"\n")
        fh.write(_format_bytes("KEY_SHARE", legacy_key) + "\n")
        fh.write(_format_bytes("MASK", legacy_mask) + "\n")
        fh.write(_format_bytes("FINAL_MASK", legacy_final) + "\n")


if __name__ == "__main__":
    main()
