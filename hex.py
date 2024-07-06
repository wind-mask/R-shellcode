def print_file_as_hex_u8_array(filename):
    with open(filename, "rb") as file:
        bytes = file.read()
        hex_array = ", ".join("0x{:02x}".format(b) for b in bytes)
        print("[" + hex_array + "]")

if __name__ == "__main__":
    # 替换 'path/to/your/file' 为你的文件路径
    print_file_as_hex_u8_array("out/214.bin")