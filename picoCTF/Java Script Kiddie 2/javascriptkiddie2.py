#!/usr/bin/python3
#
# Solution for picoCTF "Java Script Kiddie 2" challenge
# Almost the same as #1, but has no shifting of ord() and only every other digit of key is used
#

bytes = ""
split_bytes = []
LEN = 16
PNG_HEADER = "89504E470D0A1A0A0000000D49484452" # first 16 PNG bytes. PNG Signature + IHDR Length + Chunk Type ("IHDR")
PNG_HEADER_DEC = ['137', '80', '78', '71', '13', '10', '26', '10', '0', '0', '0', '13', '73', '72', '68', '82'] # Same as above, but in decimal
key = ""

with open("./bytes") as file:
    for line in file:
        bytes += line

split_bytes = bytes.split()

for i in range(LEN):
    for keyval in range(10):
        shifter = keyval
        for j in range(int(len(split_bytes) / 16) - 1):
            bytes_index = (((j + shifter) * LEN) % len(split_bytes)) + i
            if split_bytes[bytes_index] == PNG_HEADER_DEC[i]:
                print("split_bytes: {} | PNG_HEADER_DEC: {} | Key Value: {}".format(split_bytes[bytes_index], PNG_HEADER_DEC[i], j))
                key += str(j) + "0" # The key only uses every other digit. LEN 32 becomes 16
                break
            else:
                continue
        break

print("Key is: {}".format(key))
