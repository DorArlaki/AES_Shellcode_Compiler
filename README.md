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
    - Modify the aes.py file to ensure compatibility with the C++ code template.
    - Generate the beacon.bin payload using msfvenom.
    - Execute the modified aes.py script to encrypt the beacon.bin payload.
    - Extract the AES key and encrypted payload from the output file.
    - Create a C++ code template with the extracted AES key and payload.
    - Compile the C++ code into a Windows DLL file (helloworld.dll).

After successful execution, helloworld.dll files will be generated in the same directory.


## Execution Instructions

1. Transfer the `helloworld.dll` file to the target machine.
2. Open a command prompt on the target machine.
3. Navigate to the directory where the `helloworld.dll` file is located.
4. Run the following command to execute the DLL:

```shell
rundll32.exe helloworld.dll, HelloWorld
```

## AES Script Modification Tool

The AES Script Modification Tool is a Python script that helps modify an AES script to evade Windows Defender detection. It achieves this by changing the checksum of the script.

## Features

- Modifies an AES script to alter the checksum and avoid detection by Windows Defender.
- Appends " Hello" to all `print` statements in the script to add a customizable string.

## Usage

1. Clone the repository or download the `modify_aes_script.py` script.
2. Place the AES script you want to modify in the same directory as `modify_aes_script.py`. Ensure the AES script file is named `AES_Shellcode_Compiler.py`.
3. Open a terminal or command prompt and navigate to the directory containing `modify_aes_script.py`.
4. Run the following command:

   ```shell
   python3 modify_aes_script.py
