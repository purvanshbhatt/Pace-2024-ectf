# eCTF MISC System - Pace University

This repository houses the design of a secure eCTF MISC system for the 2024 competition developed by Team PACE.

## Key Features

- Robust Security: Employs a secure communication protocol to safeguard attestation data, ensuring confidentiality and integrity during communication between system components.
- Flexible Component Replacement: Supports secure replacement of medical components, promoting system maintainability.
- Clear and Transparent Design: Prioritizes code clarity, detailed design explanations, and transparency to discourage security-by-obscurity practices.

## Layout

- `application_processor`: Contains the application processor code and its Makefile.
- `component`: Houses the component code and its corresponding Makefile.
- `deployment`: Stores code pertinent to deployment secret generation.
- `ectf_tools` (DO NOT MODIFY): Precludes unauthorized modifications, safeguarding the integrity of host and build tools.
- `wolfssl`: Designated location for the WolfSSL cryptographic library, a crucial component for secure communication.
- `shell.nix`, `custom_nix_pkgs`, `analog-openocd.nix`: Nix environment configuration files essential for the build process.

## Usage and Requirements

### Building

The eCTF Tools within a Nix environment are employed to build the firmware.
For development purposes, a build environment can be manually configured using nix-shell.

### Host Tools

Written in Python, these tools can be installed using Poetry (poetry install).

- `List`: Generates a list of connected components (ectf_list).
- `Boot`: Initiates the booting process for the entire system (ectf_boot).
- `Replace`: Facilitates secure replacement of components (ectf_replace).
- `Attestation`: Retrieves confidential attestation data (ectf_attestation).

### Development and Deployment

Refer to the Document and the codebase itself for in-depth guidance on system architecture, security features, and the deployment process.

## Documentation

We prioritize comprehensive documentation to enhance understanding and maintainability:

- Well-Commented Code: Code files are supplemented with clear explanations to promote readability and understanding.
- Design Documents: These documents provide detailed overviews of the system's architecture and the rationale behind security choices.
- README.md: Offers a high-level summary of the system, along with usage instructions.

## Example Usage (eCTF Tools)

```Bash

#Building the deployment 
ectf_build_depl -d .

# Building the Application Processor
ectf_build_ap -d . -on ap --p 123456 -c 2 -ids "0x11111124, 0x11111125" -b "Test boot message" -t 0123456789abcdef -od build

# Building a Component
ectf_build_comp -d . -on comp -od build -id 0x11111125 -b "Component boot" -al "McLean" -ad "08/08/08" -ac "Fritz"
Use code with caution.
```

## Flashing

Drag and drop the provided bootloader onto the DAPLink interface.
Utilize ectf_update to flash the application processor or component images onto the target devices.

## Important Notes
Our design adheres to the competition's documentation standards, emphasizing clarity and transparency.
Teams are advised to refrain from modifying any files within the ectf_tools directory to preserve system integrity.

## Contact/Support

For any inquiries or issues, please reach out to the Pace University eCTF team
