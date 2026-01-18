import argparse
import re
import sys
import time
import serial

INFO_RE = re.compile(r"%info: ((.|\n|\r)*?)%")
SUCCESS_RE = re.compile(r"%success: ((.|\n|\r)*?)%")
ERROR_RE = re.compile(r"%error: ((.|\n|\r)*?)%")
ACK_RE = re.compile(r"%ack%")


def read_until_status(ser, timeout=5.0):
    end = time.time() + timeout
    buf = ""
    while time.time() < end:
        buf += ser.read().decode("utf-8", errors="ignore")
        if SUCCESS_RE.search(buf):
            return "success", buf
        if ERROR_RE.search(buf):
            return "error", buf
    return "timeout", buf


def send_cmd_sequence(ser, inputs, timeout=5.0):
    for msg in inputs:
        ser.write(msg.encode())
        time.sleep(0.05)
    return read_until_status(ser, timeout=timeout)


def test_wrong_pin(ser, component_id):
    status, output = send_cmd_sequence(ser, ["attest\r", "000000\r", f"{component_id}\r"], timeout=5.0)
    assert status == "error", f"Expected error for wrong PIN, got {status}\n{output}"


def test_wrong_token(ser):
    status, output = send_cmd_sequence(
        ser,
        ["replace\r", "deadbeefdeadbeef\r", "0x11111199\r", "0x11111124\r"],
        timeout=5.0,
    )
    assert status == "error", f"Expected error for wrong token, got {status}\n{output}"


def main():
    parser = argparse.ArgumentParser(description="Minimal host abuse tests")
    parser.add_argument("-a", "--application-processor", required=True)
    parser.add_argument("-c", "--component", required=True)
    args = parser.parse_args()

    ser = serial.Serial(
        port=args.application_processor,
        baudrate=115200,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        bytesize=serial.EIGHTBITS,
        timeout=0.5,
    )

    try:
        test_wrong_pin(ser, args.component)
        test_wrong_token(ser)
        print("Abuse tests passed")
    finally:
        ser.close()


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc))
        sys.exit(1)
