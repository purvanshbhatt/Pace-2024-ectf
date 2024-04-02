from pathlib import Path
import re
import secrets
import os
import csv
import sys



# this is for deployment
macro_information={}

# End of Global Data Definition: 

def get_id(macro):
    pattern = r'#define COMPONENT_ID (0x[\da-fA-F]+)'
    match = re.search(pattern, macro)
    if match:
        # Extract the number from the matched group
        number = match.group(1)
        return number
    else:
        print("Number not found in the string.")
        
def get_boot_message(macro):
    pattern = r'#define COMPONENT_BOOT_MSG\s*"([^"]+)"'
    match = re.search(pattern, macro)
    
    # Check if a match is found
    if match:
        boot_message = match.group(1)
        return boot_message
    else:
        print("No match found.")

def get_atts_loc(macro):
    pattern = r'#define ATTESTATION_LOC\s*"([^"]+)"'
    match = re.search(pattern, macro)
    
    # Check if a match is found
    if match:
        boot_message = match.group(1)
        return boot_message
    else:
        print("No match found.")

def get_atts_date(macro):
    pattern = r'#define ATTESTATION_DATE\s*"([^"]+)"'
    match = re.search(pattern, macro)
    
    # Check if a match is found
    if match:
        boot_message = match.group(1)
        return boot_message
    else:
        print("No match found.")

def get_atts_customer(macro):
    pattern = r'#define ATTESTATION_CUSTOMER\s*"([^"]+)"'
    match = re.search(pattern, macro)
    
    # Check if a match is found
    if match:
        boot_message = match.group(1)
        return boot_message
    else:
        print("No match found.")

        
def extract_info():
    fh = open(Path("./inc/ectf_params.h"), "r")
    lines = fh.readlines()
    fh.close()
    macro_information["ids"]=get_id(lines[2])
    macro_information["message"]=get_boot_message(lines[3])
    macro_information["location"]=get_atts_loc(lines[4])
    macro_information["date"]=get_atts_date(lines[5])
    macro_information["customer"]=get_atts_customer(lines[6])
    return 

def file_exist(file_path)->bool:
    if file_path.exists():
        return True
    else:
        return False


    
def Read_files()->None:
    if file_exist(Path(f"../deployment/{hex(int(macro_information['ids']))}.txt")):
        fh = open(f"../deployment/{hex(int(macro_information['ids']))}.txt", "r")
        lines = fh.readlines()
        fh.close()
        macro_information["share"]=lines[1]
        macro_information["mask"]=lines[2]
        macro_information["final"]=lines[3]
    else:
        macro_information["share"]=changebyte("0000000000000000".encode(),'KEY_SHARE')
        macro_information["mask"]=changebyte("0000000000000000".encode(),'MASK')
        macro_information["final"]=changebyte("0000000000000000".encode(),'FINAL_MASK')

def changebyte(byte_stream, name)->str:
    hex_representation = ', '.join([f'0x{byte:02X}' for byte in byte_stream])
    macro_string = f"const uint8_t {name}[16] = {{ {hex_representation} }};"
    return macro_string

def change_byte_to_noconst(byte_stream, name)->str:
    hex_representation = ', '.join([f'0x{byte:02X}' for byte in byte_stream])
    macro_string = f"uint8_t {name}[16] = {{ {hex_representation} }};"
    return macro_string

def getkey(filename, row):
    with open(filename, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for i, line in enumerate(reader):
            if i == row:
                return line[0]
            
def component_id_to_i2c_addr(component_id):
    component_id = int(component_id, 16)
    component_id &= 0xFF
    return component_id

def wrkey(index)->None:

    index = int(index)
    key_share = secrets.token_bytes(16)
    if file_exist(Path(f"../deployment/pace.csv")):
        mask = getkey(Path(f"../deployment/pace.csv"), index*2)
        final = getkey(Path(f"../deployment/pace.csv"), index*2+1)
    else:
        print("No file found")
        print("error")
        return

    fh = open("inc/key.h", "w")
    fh.write("#ifndef __KEY__\n")
    fh.write("#define __KEY__\n")
    fh.write("#include <stdint.h> \n")
    fh.write("extern uint8_t KEY_SHARE[16];\n")
    fh.write("extern const uint8_t MASK[16];\n")
    fh.write("extern const uint8_t FINAL_MASK[16];\n")
    fh.write("#endif\n")
    fh.close()
    fh = open("src/key.c", "w")
    fh.write("#include \"key.h\" \n")
    fh.write(change_byte_to_noconst(key_share,"KEY_SHARE"))
    fh.write('\n')
    fh.write(mask)
    fh.write('\n')
    fh.write(final)
    fh.write('\n')
    fh.close()
# ------------------------------ End of Previous Deinition, this is the main file -----------------------------------
def get_nums():
    file_path = Path("../component/count.txt")
    if not os.path.exists(file_path):
        with open(file_path, "w") as f:
            pass
        return 1

    with open(file_path, "r+") as f:
        lines = f.readlines()
        num = -1
        if len(lines)!=0:
            num = int(lines[-1].split()[1])
            #print(num)
        num+=1
        ret = str(hex(int(macro_information['ids']))) + " " + str(num) + "\n"
        #print(ret)
        f.write(ret)
    return num

if __name__ == "__main__":
    extract_info()
    index = component_id_to_i2c_addr(macro_information['ids'])
    wrkey(95)
