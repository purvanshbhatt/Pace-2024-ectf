import secrets
from pathlib import Path


def format_bytes(name, byte_stream) -> str:
    hex_representation = ", ".join([f"0x{byte:02X}" for byte in byte_stream])
    return f"static const uint8_t {name}[{len(byte_stream)}] = {{ {hex_representation} }};"


def write_global_secrets(output_path: Path) -> None:
    deployment_id = secrets.token_bytes(16)
    kmaster = secrets.token_bytes(32)

    with open(output_path, "w") as fh:
        fh.write("#ifndef GLOBAL_SECRETS_H\n")
        fh.write("#define GLOBAL_SECRETS_H\n\n")
        fh.write("#include <stdint.h>\n\n")
        fh.write("#define DEPLOYMENT_ID_LEN 16\n")
        fh.write("#define KMASTER_LEN 32\n\n")
        fh.write(format_bytes("DEPLOYMENT_ID", deployment_id) + "\n")
        fh.write(format_bytes("KMASTER", kmaster) + "\n\n")
        fh.write("#endif\n")


if __name__ == "__main__":
    write_global_secrets(Path("global_secrets.h"))
