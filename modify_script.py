import re

def modify_print_statements(aes_script):
    modified_script = re.sub(r'print\((.*?)\)', r'print(\1, "Hello")', aes_script)
    return modified_script

# Example usage:
with open('AES_Shellcode_Compiler.py', 'r') as file:
    aes_script = file.read()

modified_script = modify_print_statements(aes_script)

# Save the modified script to a new file
with open('TryMe.py', 'w') as file:
    file.write(modified_script)

print("The modified script has been saved as 'TryMe.py'.")
