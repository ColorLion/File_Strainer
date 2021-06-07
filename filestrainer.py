import pefile
import elftools

filename = "lsd"

# 실행파일 체크
def osCheck(filename):
    file = open(filename, 'rb')
    firstLine = file.readline()

    if b'MZ' in firstLine:
        winBitChecker(filename)
        file.close()
        print("windows")

    if b'ELF' in firstLine:
        file.close()
        print("linux")

def winBitChecker(filename):
    pe = pefile.PE(filename, fast_load=True)

    if hex(pe.FILE_HEADER.Machine) == '0x14c':
        print("32bit") 
    else:
        print("64bit")

osCheck(filename)