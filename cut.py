import subprocess
import sys

if __name__ == "__main__":
    # 从命令行参数获取cutsize
    if len(sys.argv) > 1:
        cutsize_str = sys.argv[1]
        # 支持16进制和十进制
        if cutsize_str.startswith("0x"):
            cutsize = int(cutsize_str, 16)
        else:
            cutsize = int(cutsize_str)
    else:
        print("Usage: python cut.py <cutsize>")
        sys.exit(1)
    # 打开文件
    with open("shellcode.bin", "rb") as file:
        # 定位到0x51字节之后的位置
        # file.seek(0x713 + 1)
        file.seek(0x491 + 1)
        # file.seek(0xD73 + 1)
        # 读取剩余的文件内容
        data = file.read()

        # 处理或保存data
        # 例如，打印数据
        # 保存到shellcode.b
        with open("rshellcode.bin", "wb") as output_file:
            output_file.write(data[:cutsize])
    command = (
        r".\ndisasm.exe -b 64 .\rshellcode.bin > .\rshellcode.S"
    )
    subprocess.run(command, shell=True)
