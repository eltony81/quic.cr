# QPACK format checker
def decode_field(b):
    if (b & 0x80) == 0x80:
        return f"Indexed: static={(b & 0x40) != 0}, prefix=6"
    elif (b & 0xC0) == 0x40:
        return f"Literal with Name Ref: static={(b & 0x10) != 0}, prefix=4"
    elif (b & 0xE0) == 0x20:
        return f"Literal without Name Ref: N={(b & 0x10) != 0}"
    elif (b & 0xF0) == 0x10:
        return f"Indexed with Post-Base Index: prefix=4"
    elif (b & 0xF8) == 0x00:
        return f"Literal with Post-Base Name Ref: prefix=3"
    else:
        return "Unknown"

print(decode_field(0b11000000)) # Indexed Static
print(decode_field(0b01010000)) # Literal with Name Ref Static
print(decode_field(0b00100000)) # Literal without Name Ref
print(decode_field(0b00010000)) # Indexed Post-Base
print(decode_field(0b00000000)) # Literal Post-Base
