# Secure Messenger

A Python client-server messaging application developed for CS 5173/4173 Computer Security. The program allows two users to exchange encrypted text messages, images, audio recordings, and general files through a graphical interface.

## **Features**

* TCP client-server communication

* DES-56-CBC encryption

* AES-128-CBC encryption

* PBKDF2 password-based key derivation

* PKCS padding

* HMAC-SHA256 message authentication

* Text, image, audio, and general file transfer

* Plaintext and ciphertext display

* Separate client and server graphical interfaces

* Received files saved into separate folders

### **Project Files**

* client_gui.py: client graphical interface and client networking
* server_gui.py: server graphical interface and server networking
* gui_common.py: shared graphical interface layout and helper methods
* encryption.py: key derivation, DES, AES, encryption, decryption, and HMAC
* message_format.py: JSON message formatting, Base64 file encoding, and file saving
* msg_handler.py: length-prefixed TCP message sending and receiving
* client.py: optional command-line client
* server.py: optional command-line server

## Requirements

* Python 3
* Tkinter
* cryptography
* pycryptodome

### Installing the Required Packages

Open a terminal in the project folder and run:

`pip install cryptography pycryptodome`

Tkinter is included with many Python installations. On macOS with Homebrew Python, it may need to be installed separately:

`brew install python-tk`

For a version-specific Homebrew Python installation, use the matching package, such as:

`brew install python-tk@3.14`

Test Tkinter with: `python -m tkinter` A small Tkinter test window should appear.

### Running the Program on One Computer

The server must be started before the client.

1. Start the Server

Run:
`python server_gui.py
`

In the server window:
* Leave the listening host as 0.0.0.0.
* Leave the port as 5001.
* Enter a shared password.
* Select either DES-56 or AES-128.

Click Start Server.

**The server status should change to Listening.**

2. Start the Client

Open a second terminal in the same project folder and run: `python client_gui.py
`

In the client window:

* Leave the server IP address as 127.0.0.1.
* Leave the port as 5001.
* Enter the same shared password used by the server.
* Select the same encryption mode used by the server.

Click Connect.

**The client and server status indicators should both change to Connected.**

## Sending Messages

The client and server can both send messages.

### Text Message

1. Type a message into the message box.
2. Click Send Text.
3. The plaintext appears in the conversation panel.
4. The encrypted Base64 ciphertext appears in the technical details panel.
5. The activity log confirms encryption and HMAC verification.

### Image

1. Click Attach Image.
2. Select an image file.
3. The image is encrypted, authenticated, and transmitted.
4. The receiving side saves the image in its received-files folder.

### Audio

1. Click Attach Audio.
2. Select an audio file.
3. The audio file is encrypted, authenticated, and transmitted.
4. The receiving side saves the audio file in its received-files folder.

### General File

1. Click Attach File.
2. Select a file.
3. The file is encrypted, authenticated, and transmitted.
4. The receiving side saves the file in its received-files folder.

## Received Files

Files received by the client are saved in:

`client_received_files/`

Files received by the server are saved in:

`server_received_files/`

The conversation panel displays the received filename and saved location.

## Running the Program on Two Computers

**Both computers must be connected to the same local network.**

**On the Server Computer**

Run: `server_gui.py`

* Keep the listening host set to 0.0.0.0.
* Use port 5001.
* Enter the shared password.
* Select the encryption mode.
* Click Start Server.

Find the server computer's local IP address.

**On macOS:**

`ipconfig getifaddr en0`

On Windows:

`ipconfig`

Look for the IPv4 address, such as:

192.168.1.14

**On the Client Computer**

Copy the project files to the client computer.

* Install the required Python packages.
* Run `client_gui.py.`
* Replace 127.0.0.1 with the server computer's local IP address.
* Use port 5001.
* Enter the same password as the server.
* Select the same encryption mode as the server.
* Click Connect.

If a firewall prompt appears on the server computer, allow Python to accept incoming network connections.

## Important Connection Settings

* The following values must match on both sides:
* Port number
* Shared password
* Encryption mode

### For local testing on one computer:

* Server listening host: 0.0.0.0
* Client server IP:      127.0.0.1
* Port:                  5001

For testing on two computers:

* Server listening host: 0.0.0.0
* Client server IP:      server computer's local IP address
* Port:                  5001

## Security Design

The shared password is not used directly as an encryption key. PBKDF2 derives the encryption and HMAC keys from the password.

Each encrypted message includes:
* A randomly generated initialization vector
* The ciphertext
* An HMAC-SHA256 authentication tag

The receiving side verifies the HMAC before accepting and displaying the decrypted message. If the password is incorrect or the protected message has been modified, the program reports a security error.

### Encryption Modes

**DES-56**
* Uses DES in CBC mode
* Uses an 8-byte key with 56 effective key bits
* Uses an 8-byte initialization vector

**AES-128**

* Uses AES in CBC mode
* Uses a 16-byte key
* Uses a 16-byte initialization vector

The client and server must select the same mode.

## Troubleshooting

### **Connection Refused**

Make sure:

* server_gui.py is running first
* the server has been started
* both sides use port 5001
* the client uses the correct server IP address
* the firewall allows incoming Python connections

### **Security Error**

Make sure:

* both sides use the same password
* both sides use the same encryption mode
* the message was not modified during transmission

### Tkinter Is Missing

On macOS with Homebrew Python, install the matching Tkinter package:

`brew install python-tk`

Then restart the IDE and test:

`python -m tkinter`

### File Transfer Appears Slow

Larger files require Base64 encoding, encryption, HMAC generation, and network transmission. The interface displays only a shortened ciphertext preview, but the complete ciphertext is still transmitted.

Closing the Program
* Use the Disconnect button to close the client connection.
* Use the Stop Server button to stop the server.
* Close both graphical windows after the connection and server have been stopped.

**Author**

Laura NguyenCS 5173/4173 Computer SecuritySummer 2026