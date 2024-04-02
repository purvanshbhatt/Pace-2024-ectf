from pathlib import Path
import secrets
import re, csv, os, sys

# ------------------------------ This is for key generation ------------------------------

def create_k2(stream_length=16):
    return secrets.token_bytes(stream_length)

def change_byte_to_const(byte_stream, name)->str:
    hex_representation = ', '.join([f'0x{byte:02X}' for byte in byte_stream])
    macro_string = f"const uint8_t {name}[16] = {{ {hex_representation} }};"
    return macro_string

def change_byte_to_noconst(byte_stream, name)->str:
    hex_representation = ', '.join([f'0x{byte:02X}' for byte in byte_stream])
    macro_string = f"uint8_t {name}[16] = {{ {hex_representation} }};"
    return macro_string

# ------------------------------ this is for file Writing and modification --------------------------------------

shares = []
macro_information = {}

def get_ids(ap_macro):
    pattern = r"0x[\da-fA-F]+"
    ids = re.findall(pattern, ap_macro)
    return ids

def get_cnt(ap_macro):
    pattern = r"#define COMPONENT_CNT\s*([\d,]+)"
    match = re.search(pattern, ap_macro)
    if match:
        component_cnt = match.group(1)
        return component_cnt
    else:
        print("No match found.")

def get_boot_message(ap_macro):
    pattern = r'#define AP_BOOT_MSG\s*"([^"]+)"'
    match = re.search(pattern, ap_macro)
    if match:
        boot_message = match.group(1)
        return boot_message
    else:
        print("No match found.")

def get_token(ap_macro):
    pattern = r'#define AP_TOKEN\s*"([^"]+)"'
    match = re.search(pattern, ap_macro)
    if match:
        boot_message = match.group(1)
        return boot_message
    else:
        print("No match found.")

def get_pin(ap_macro):
    pattern = r'#define AP_PIN\s*"([^"]+)"'
    match = re.search(pattern, ap_macro)
    if match:
        boot_message = match.group(1)
        return boot_message
    else:
        print("No match found.")

def extract_info():
    fh = open(Path("./inc/ectf_params.h"), "r")
    lines = fh.readlines()
    fh.close()
    macro_information["pin"] = get_pin(lines[2])
    macro_information["token"] = get_token(lines[3])
    macro_information["ids"] = get_ids(lines[4])
    macro_information["cnt"] = get_cnt(lines[5])
    macro_information["message"] = get_boot_message(lines[6])
    return

def get_file_paths() -> list:
    ids = macro_information["ids"]
    count = macro_information["cnt"]
    if count == "1":
        return [ids[0] + ".txt", count]
    else:
        return [ids[0] + ".txt", ids[1] + ".txt", count]

def file_exist(file_path)->bool:
    if file_path.exists():
        return True
    else:
        return False

def read_key_from_files(file_paths: list) -> None:
    comp_val=0
    k2=create_k2(16)
    masks=['', '', '', '']
    for index in range(len(macro_information["ids"])):
        comp_val += 1
        if file_exist(Path(f"../deployment/{macro_information['ids'][index]}.txt")):
            fh = open(f"../deployment/{macro_information['ids'][index]}.txt", "r")
            lines = fh.readlines()
            fh.close()
            masks[index]=lines[1] 
            masks[index + 2]=lines[2]
        else:
            masks[index]=change_byte_to_const("0000000000000000".encode(),f'M{index + 1}')
            masks[index + 2]=change_byte_to_const("0000000000000000".encode(),f'F{index + 1}')

    fh = open("./inc/key.h", "w")
    fh.write("#ifndef __KEY__\n")
    fh.write("#define __KEY__\n")
    fh.write("#include <stdint.h> \n")
    fh.write(change_byte_to_const(k2,"KEY_SHARE")+"\n")
    if comp_val==1:
        fh.write(masks[0].replace("MASK", "M1"))
        fh.write(masks[2].replace("FINAL_MASK", "F1"))
        masks[1]=change_byte_to_const("0000000000000000".encode(),f'M{2}')
        masks[3]=change_byte_to_const("0000000000000000".encode(),f'F{2}')
        fh.write(masks[1].replace("MASK", "M2")+"\n")
        fh.write(masks[3].replace("FINAL_MASK", "F2")+"\n")
    else:
        fh.write(masks[0].replace("MASK", "M1"))
        fh.write(masks[2].replace("FINAL_MASK", "F1"))
        fh.write(masks[1].replace("MASK", "M2"))
        fh.write(masks[3].replace("FINAL_MASK", "F2")+"\n")
    fh.write("#endif\n")
    fh.close()

def get_secret_key_from_csv(filename, row):
    with open(filename, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for i, line in enumerate(reader):
            if i == row:
                return line[0]

def component_id_to_i2c_addr(component_id):
    COMPONENT_ADDR_MASK = 0x000000FF
    return component_id & COMPONENT_ADDR_MASK

def write_key_to_files():
    indexs = []
    for i in range(int(macro_information["cnt"])):
        indexs.append(component_id_to_i2c_addr(int(macro_information["ids"][i], 16)))
    mask = []
    final = []
    if file_exist(Path(f"../deployment/pace.csv")):
        for i in indexs:
            mask.append(get_secret_key_from_csv(Path(f"../deployment/pace.csv"), 69*2))
            final.append(get_secret_key_from_csv(Path(f"../deployment/pace.csv"), 69*2+1))
    else:
        print("No file")
        print("ERROR")
        return
    k2 = secrets.token_bytes(16)
    fh = open("./inc/key.h", "w")
    fh.write("#ifndef __KEY__\n")
    fh.write("#define __KEY__\n")
    fh.write("#include <stdint.h> \n")
    fh.write("extern uint8_t KEY_SHARE[16];\n")
    fh.write("extern const uint8_t M1[16];\n")
    fh.write("extern const uint8_t F1[16];\n")
    fh.write("#endif\n")
    fh.close()
    fh = open("./src/key.c", "w")
    fh.write("#include \"key.h\" \n")
    fh.write(change_byte_to_noconst(k2,"KEY_SHARE")+"\n")
    if len(indexs) == 1:
        fh.write(mask[0].replace("MASK", "M1") + "\n")
        fh.write(final[0].replace("FINAL_MASK", "F1") + "\n")
    else:
        fh.write(mask[0].replace("MASK", "M1") + "\n")
        fh.write(final[0].replace("FINAL_MASK", "F1") + "\n")
    fh.close()

if __name__ == "__main__":
    extract_info()
    write_key_to_files()
