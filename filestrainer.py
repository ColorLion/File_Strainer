import pefile
from elftools.elf.elffile import ELFFile

filename = "test.exe"

# 실행파일 체크
def osCheck(filename):
    file = open(filename, 'rb')
    firstLine = file.readline()

    if b'MZ' in firstLine:
        print("Filename: " + filename)
        print("OS: windows")
        winBitChecker(filename)
        file.close()
        
    if b'ELF' in firstLine:
        print("Filename: " + filename)
        print("OS: linux")
        liBitChecker(file)
        file.close()

def winBitChecker(filename):
    pe = pefile.PE(filename, fast_load=True)

    if hex(pe.FILE_HEADER.Machine) == '0x14c':
        print("32bit") 
    else:
        print("64bit")

def liBitChecker(file):
    elf = ELFFile(file)
    flags = elf.header.e_ehsize
    if flags == 64:
        print("64bit")
    else:
        print("32bit")

osCheck(filename)