# Build + Flash Runbook (2024 eCTF)

This runbook uses the official eCTF host/build tools (unaltered). All commands must run from the repo root.

## Build (clean, reproducible)
```bash
ectf_build_depl -d .

ectf_build_ap -d . -on ap -od build -p 123456 -t 0123456789abcdef -c 2 -ids "0x11111124,0x11111125" -b "AP boot"

ectf_build_comp -d . -on comp -od build -id 0x11111124 -b "C1 boot" -al "McLean" -ad "08/08/08" -ac "Fritz"

ectf_build_comp -d . -on comp -od build -id 0x11111125 -b "C2 boot" -al "McLean" -ad "08/08/08" -ac "Fritz"
```

Expected outputs:
- Each build emits a `build/` folder containing `.elf`, `.bin`, and `.img` artifacts.
- The AP build prints “Loaded project.mk” and completes without errors.
- Each component build prints “Loaded project.mk” and completes without errors.

## Flash
Flash the bootloader (once per board) and then the firmware images:
```bash
ectf_update --infile build/firmware.img --port <AP_SERIAL>
ectf_update --infile build/firmware.img --port <COMP1_SERIAL>
ectf_update --infile build/firmware.img --port <COMP2_SERIAL>
```

## Host Flows
```bash
ectf_list -a <AP_SERIAL>

ectf_boot -a <AP_SERIAL>

ectf_attestation -a <AP_SERIAL> -p 123456 -c 0x11111124

ectf_replace -a <AP_SERIAL> -t 0123456789abcdef -i 0x11111126 -o 0x11111124
```

Expected flow indicators:
- LIST prints `P>` provisioned IDs and `F>` responsive IDs and ends with `List` success.
- BOOT prints `0xID>boot message` per component and `Boot` success.
- ATTEST prints `C>0xID` and attestation fields, then `Attest` success.
- REPLACE prints `Replace` success and old ID no longer responds.

## Clean
```bash
make -C deployment clean
```

This removes generated deployment secrets. Re-run `ectf_build_depl -d .` before building AP/Components again.
