import csv
import os
import sys
import secrets
from pathlib import Path

def changebyte(byte_stream, name)->str:
    hex_representation = ', '.join([f'0x{byte:02X}' for byte in byte_stream])
    macro_string = f"const uint8_t {name}[16] = {{ {hex_representation} }};"
    return macro_string

def generate_csv(filename, rows):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for i in range(0,rows,2):
            writer.writerow([changebyte(secrets.token_bytes(16), "MASK")])
            writer.writerow([changebyte(secrets.token_bytes(16), "FINAL_MASK")])
    csvfile.close()

def getkey(filename, row):
    with open(filename, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for i, line in enumerate(reader):
            if i == row:
                print("Secret key: {}".format(line[0]))
                return line[0]

def get_nums():
    file_path = Path("../component/count.txt")
    if not os.path.exists(file_path):
        with open(file_path, "w") as f:
            pass
        
        return 1
    
if __name__ == '__main__':
   
    filename  = Path("pace.csv")
    rows = 1000
    generate_csv(filename, rows)
    get_nums()
    sys.exit(0)
