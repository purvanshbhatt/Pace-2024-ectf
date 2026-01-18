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


def _parse_hex_list(value: str):
    return [int(item.strip(), 16) for item in value.split(",") if item.strip()]


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

    pin = _parse_define(params_text, "AP_PIN").strip('"')
    token = _parse_define(params_text, "AP_TOKEN").strip('"')
    component_ids = _parse_hex_list(_parse_define(params_text, "COMPONENT_IDS"))

    deployment_id = _parse_c_array(secrets_text, "DEPLOYMENT_ID")
    kmaster = _parse_c_array(secrets_text, "KMASTER")

    pin_salt = _hkdf_sha256(kmaster, deployment_id, b"PIN_SALT", 16)
    token_salt = _hkdf_sha256(kmaster, deployment_id, b"TOKEN_SALT", 16)
    pin_hash = hashlib.sha256(pin.encode("utf-8") + pin_salt).digest()
    token_hash = hashlib.sha256(token.encode("utf-8") + token_salt).digest()

    component_entries = []
    for cid in component_ids:
        info = b"KC" + cid.to_bytes(4, "big")
        kc = _hkdf_sha256(kmaster, deployment_id, info, 16)
        component_entries.append((cid, kc))

    with open(Path("./inc/ap_secrets.h"), "w", encoding="utf-8") as fh:
        fh.write("#ifndef AP_SECRETS_H\n")
        fh.write("#define AP_SECRETS_H\n\n")
        fh.write("#include <stdint.h>\n\n")
        fh.write(_format_bytes("AP_DEPLOYMENT_ID", deployment_id) + "\n")
        fh.write(_format_bytes("AP_PIN_SALT", pin_salt) + "\n")
        fh.write(_format_bytes("AP_TOKEN_SALT", token_salt) + "\n")
        fh.write(_format_bytes("AP_PIN_HASH", pin_hash) + "\n")
        fh.write(_format_bytes("AP_TOKEN_HASH", token_hash) + "\n\n")
        fh.write("typedef struct {\n")
        fh.write("    uint32_t component_id;\n")
        fh.write("    uint8_t kc[16];\n")
        fh.write("} ap_component_key_t;\n\n")
        fh.write(f"#define AP_COMPONENT_KEY_COUNT {len(component_entries)}\n\n")
        fh.write("static const ap_component_key_t AP_COMPONENT_KEYS[AP_COMPONENT_KEY_COUNT] = {\n")
        for cid, kc in component_entries:
            fh.write(f"    {{ 0x{cid:08X}, {{ {', '.join(f'0x{b:02X}' for b in kc)} }} }},\n")
        fh.write("};\n\n")
        fh.write("#endif\n")

    legacy_key = _hkdf_sha256(kmaster, deployment_id, b"LEGACY_KEY", 16)
    legacy_mask1 = _hkdf_sha256(kmaster, deployment_id, b"LEGACY_M1", 16)
    legacy_mask2 = _hkdf_sha256(kmaster, deployment_id, b"LEGACY_M2", 16)
    legacy_final1 = _hkdf_sha256(kmaster, deployment_id, b"LEGACY_F1", 16)
    legacy_final2 = _hkdf_sha256(kmaster, deployment_id, b"LEGACY_F2", 16)

    with open(Path("./inc/key.h"), "w", encoding="utf-8") as fh:
        fh.write("#ifndef __KEY__\n")
        fh.write("#define __KEY__\n")
        fh.write("#include <stdint.h>\n\n")
        fh.write("extern const uint8_t KEY_SHARE[16];\n")
        fh.write("extern const uint8_t M1[16];\n")
        fh.write("extern const uint8_t F1[16];\n")
        fh.write("extern const uint8_t M2[16];\n")
        fh.write("extern const uint8_t F2[16];\n")
        fh.write("#endif\n")

    with open(Path("./src/key.c"), "w", encoding="utf-8") as fh:
        fh.write("#include \"key.h\"\n")
        fh.write(_format_bytes("KEY_SHARE", legacy_key) + "\n")
        fh.write(_format_bytes("M1", legacy_mask1) + "\n")
        fh.write(_format_bytes("F1", legacy_final1) + "\n")
        fh.write(_format_bytes("M2", legacy_mask2) + "\n")
        fh.write(_format_bytes("F2", legacy_final2) + "\n")


if __name__ == "__main__":
    main()
