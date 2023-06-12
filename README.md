# AES Shellcode Compiler

The AES Shellcode Compiler is a script that automates the process of encrypting shellcode using AES encryption and compiling it into a Windows DLL file. This can be useful for bypassing antivirus detection and executing custom shellcode payloads.

## Prerequisites

Before using the AES Shellcode Compiler, make sure you have the following prerequisites installed:

- Python 3
- `wget` command (for downloading files)
- Metasploit Framework's `msfvenom` command
- `x86_64-w64-mingw32-g++` compiler

## Installation

1. Clone the repository or download the script to your local machine.

2. Install the required dependencies mentioned in the Prerequisites section.

3. Ensure that the necessary commands (`wget`, `msfvenom`, and `x86_64-w64-mingw32-g++`) are properly installed and accessible in your system's PATH.

## Usage

1. Open a terminal or command prompt.

2. Navigate to the directory where the script is located.

3. Run the script using the following command:

   ```shell
   python3 AES_Shellcode_Compiler.py

The script will perform the following steps:

    - Download the AES encryption script (aes.py) from a specified GitHub repository.
    - Generate an OpenSSL certificate by running the openssl command.
    - Create an msfconfig.rc file with the necessary configuration for the Metasploit handler.
    - Generate the beacon.bin payload using msfvenom.
    - Execute aes.py with the beacon.bin payload to obtain the AES key and encrypted payload.
    - Create a C++ code template for decrypting the shellcode using the AES key.
    - Replace the placeholders in the C++ code template with the actual AES key and payload.
    - Save the C++ code to a file (helloworld.cpp).
    - Compile the C++ code using the x86_64-w64-mingw32-g++ compiler to generate the helloworld.dll file.
    - Remove unnecessary files (aes.py, aes.txt, beacon.bin, helloworld.cpp).
    - Execute msfconsole with the resource file (msfconfig.rc) to start the Metasploit handler.

After successful execution, helloworld.dll files will be generated in the same directory.


## Execution Instructions

1. Transfer the `helloworld.dll` file to the target machine.
2. Open a command prompt on the target machine.
3. Navigate to the directory where the `helloworld.dll` file is located.
4. Run the following command to execute the DLL:

```shell
rundll32.exe helloworld.dll, HelloWorld

