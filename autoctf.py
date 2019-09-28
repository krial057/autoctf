from pyunpack import Archive
import os
import uuid
import shutil
import getopt
import sys
import re
import base64

config = {
    'input': './',
    'keepdecompressed': False,
    'flagformat': 'CTF{.*}'
}

flagPattern = None
indexOfFormatStart = None
flagB64Search = None
flagB64Encoded = ['', '', '']

def updateFlagPattern():
    global flagPattern
    global flagB64Search
    global flagB64Encoded
    flagPattern = re.compile(config['flagformat'].encode('utf-8'))
    indexOfFormatStart = config['flagformat'].find('{') #We suppose the flag content starts with a {
    flagB64Search = config['flagformat'][0:indexOfFormatStart+1]
    print("B64 flag search: "+flagB64Search)
    # https://mikeyveenstra.com/2017/07/27/searching-for-phrases-in-base64-encoded-strings/
    base = flagB64Search.encode('utf-8')[0:len(flagB64Search)-len(flagB64Search) % 3]
    flagB64Encoded[0] = base64.b64encode(base)
    flagB64Encoded[1] = base64.b64encode(b'a'+flagB64Search.encode('utf-8')[0:len(flagB64Search)+1-(len(flagB64Search)+1) % 3])[4:-4] #drop first and last b64 block
    flagB64Encoded[2] = base64.b64encode(b'aa'+flagB64Search.encode('utf-8')[0:len(flagB64Search)+2-(len(flagB64Search)+2) % 3])[4:-4] #drop first and last b64 block

def findFlagInRawText(bytes):
    result = flagPattern.search(bytes)
    if result is not None:
        print("***Found a flag: " + result.group(0).decode('utf-8'))

def findFlagAsBase64(bytes):
    counter = 0
    for encodedFlag in flagB64Encoded:
        index = bytes.find(encodedFlag)
        if index is not -1: 
            flagTilEnd = bytes[index-counter:]
            b64Pattern = re.compile(b'^[A-Za-z0-9+/\r\n]+={0,2}$')
            result = b64Pattern.search(flagTilEnd)
            if result is not None:
                print("***Found a flag: " + base64.b64decode(result.group(0)).decode('utf-8'))
        counter = counter + 4
   
    
    
def findFlag(bytes):
    findFlagInRawText(bytes) #find flag in raw text
    findFlagInRawText(bytes[::-1]) #find flag in reverse in raw text
    findFlagAsBase64(bytes)
    findFlagAsBase64(bytes[::-1])
    

def treatDir(dir):
    for f in os.listdir(dir):
        treatUnknown(dir + '/' + f)

def treatFile(file):
    print("- Analyizing file: " + file)
    f = open(file, 'rb')
    fData = f.read()
    findFlag(fData)
    
    tempid = uuid.uuid1().int
    tempFolder = "./temp_" + str(tempid)
    os.mkdir(tempFolder)
    isArchive = False
    try:
        Archive(file).extractall(tempFolder)
        isArchive = True
        print("  File is an archive. Extracting and analyzing contents.")
        treatDir(tempFolder)
    except:
        pass #Not an archive
    if not config['keepdecompressed'] or isArchive is False:
        shutil.rmtree(tempFolder)
 
def treatUnknown(path):
    if os.path.isdir(path):
        treatDir(path)
    elif os.path.isfile(path):
        treatFile(path)

def main(argv):
    try:
        opts, args = getopt.getopt(argv,"i:f:k",["input=","flagformat=", "keepdecompressed"])
    except getopt.GetoptError:
        print('autoctf.py -i <input> -f <flagformat> (-k)')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ('-i', '--input'):
            config['input'] = arg
        elif opt in ('-f', '--flagformat'):
            config['flagformat'] = arg
        elif opt in ('-k', '--keepdecompressed'):
            config['keepdecompressed'] = True
    updateFlagPattern()
    print('== Starting ==')
    treatUnknown(config['input'])
    print('== Finished ==')
 
if __name__ == "__main__":
    main(sys.argv[1:])
