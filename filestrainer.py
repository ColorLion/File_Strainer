import pefile
from elftools.elf.elffile import ELFFile
import argparse
import os

parser = argparse.ArgumentParser(description='Argparse Tutorial')
parser.add_argument('-d', '--dir', type=str, 
                    help='체크할 경로를 넣어주세요', default=os.getcwd())

args = parser.parse_args()
folder = args.dir
fileList = []

for filename in os.listdir(folder):
    if os.path.isfile(filename):
        fileList.append(folder + '\\' + filename)


packers_sections = {
        #The packer/protector/tools section names/keywords
        '.aspack': 'Aspack packer',
        '.adata': 'Aspack packer/Armadillo packer',
        'ASPack': 'Aspack packer',
        '.ASPack': 'ASPAck Protector',
        '.boom': 'The Boomerang List Builder (config+exe xored with a single byte key 0x77)',
        '.ccg': 'CCG Packer (Chinese Packer)',
        '.charmve': 'Added by the PIN tool',
        'BitArts': 'Crunch 2.0 Packer',
        'DAStub': 'DAStub Dragon Armor protector',
        '!EPack': 'Epack packer',
        'FSG!': 'FSG packer (not a section name, but a good identifier)',
        '.gentee': 'Gentee installer',
        'kkrunchy': 'kkrunchy Packer',
        '.mackt': 'ImpRec-created section',
        '.MaskPE': 'MaskPE Packer',
        'MEW': 'MEW packer',
        '.MPRESS1': 'Mpress Packer',
        '.MPRESS2': 'Mpress Packer',
        '.neolite': 'Neolite Packer',
        '.neolit': 'Neolite Packer',
        '.nsp1': 'NsPack packer',
        '.nsp0': 'NsPack packer',
        '.nsp2': 'NsPack packer',
        'nsp1': 'NsPack packer',
        'nsp0': 'NsPack packer',
        'nsp2': 'NsPack packer',
        '.packed': 'RLPack Packer (first section)',
        'pebundle': 'PEBundle Packer',
        'PEBundle': 'PEBundle Packer',
        'PEC2TO': 'PECompact packer',
        'PECompact2': 'PECompact packer (not a section name, but a good identifier)',
        'PEC2': 'PECompact packer',
        'pec1': 'PECompact packer',
        'pec2': 'PECompact packer',
        'PEC2MO': 'PECompact packer',
        'PELOCKnt': 'PELock Protector',
        '.perplex': 'Perplex PE-Protector',
        'PESHiELD': 'PEShield Packer',
        '.petite': 'Petite Packer',
        'petite': 'Petite Packer',
        '.pinclie': 'Added by the PIN tool',
        'ProCrypt': 'ProCrypt Packer',
        '.RLPack': 'RLPack Packer (second section)',
        '.rmnet': 'Ramnit virus marker',
        'RCryptor': 'RPCrypt Packer',
        '.RPCrypt': 'RPCrypt Packer',
        '.seau': 'SeauSFX Packer',
        '.sforce3': 'StarForce Protection',
        '.spack': 'Simple Pack (by bagie)',
        '.svkp': 'SVKP packer',
        'Themida': 'Themida Packer',
        '.Themida': 'Themida Packer',
        'Themida ': 'Themida Packer',
        '.taz': 'Some version os PESpin',
        '.tsuarch': 'TSULoader',
        '.tsustub': 'TSULoader',
        '.packed': 'Unknown Packer',
        'PEPACK!!': 'Pepack',
        '.Upack': 'Upack packer',
        '.ByDwing': 'Upack Packer',
        'UPX0': 'UPX packer',
        'UPX1': 'UPX packer',
        'UPX2': 'UPX packer',
        'UPX!': 'UPX packer',
        '.UPX0': 'UPX Packer',
        '.UPX1': 'UPX Packer',
        '.UPX2': 'UPX Packer',
        '.vmp0': 'VMProtect packer',
        '.vmp1': 'VMProtect packer',
        '.vmp2': 'VMProtect packer',
        'VProtect': 'Vprotect Packer',
        '.winapi': 'Added by API Override tool',
        'WinLicen': 'WinLicense (Themida) Protector',
        '_winzip_': 'WinZip Self-Extractor',
        '.WWPACK': 'WWPACK Packer',
        '.yP': 'Y0da Protector',
        '.y0da': 'Y0da Protector',
    }
packers_sections_lower = {x.lower(): x for x in packers_sections.keys()}

# 실행파일 체크
def osCheck(filename):
    outputList = []
    file = open(filename, 'rb')
    firstLine = file.readline()

    outputList.append(filename)

    if b'MZ' in firstLine:
        #print("windows")
        outputList.append("windows")
        outputList.append(winBitCheck(filename))
        outputList.append(winCompressCheck(filename))
        file.close()
        
    if b'ELF' in firstLine:
        #print("linux")
        outputList.append("linux")
        outputList.append(linBitCheck(file))
        #linCompressCheck(filename)
        file.close()
    return outputList

def winBitCheck(filename):
    pe = pefile.PE(filename, fast_load=True)

    if hex(pe.FILE_HEADER.Machine) == '0x14c':
        return "32"
    else:
        return "64"

def winCompressCheck(filename):
    #print(filename)
    exe = pefile.PE(filename, fast_load=True)
    matches = detect_packing([
        section.Name.decode(errors='replace',).rstrip('\x00') for section in exe.sections
    ])
    if matches:
        return "compressed"
        #print(matches)
    else:
        return "no"

def linCompressCheck(filename):
    elf = open(filename, 'rb')
    elfLine = elf.readline()

    matches = detect_packing([
        section.Name.decode(errors='replace',).rstrip('\x00') for section in elfLine
    ])
    '''
    for a in packers_sections_lower:
        #print(str(test.lower()))
        if a in str(elfLine.lower()):
            print('compressed')
            break
    print("no compression")
    '''

def linBitCheck(file):
    elf = ELFFile(file)
    flags = elf.elfclass
    if flags == 64:
        return "64"
    else:
        return "32"

def detect_packing(sections_of_pe):
    return [packers_sections_lower[x.lower()] for x in sections_of_pe if x.lower() in packers_sections_lower.keys()]

for i in fileList:
    #print(i.replace("\\", '\\\\'))
    print(osCheck(i))