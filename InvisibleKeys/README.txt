Usage:
1) InvisibleRegKeys.exe persist [path to malware executable to add to autoruns]
	This will add a hidden value to HKCU\Software\Microsoft\Windows\CurrentVersion\Run.
	The value will be mshta.exe, the Microsoft HTML Host, which takes Javascript as a command line arg and executes it.
	The Javascript references the registry key HKCU\software\WUV (which is created by InvisibleRegKeys).
	That key has the value "Tethering." 
	Tethering is Javascript blob that XOR decodes another Javascript blob, which Base64 decodes a Powershell script, which VirtualAllocs a RWX and executes sc (see InvisibleRegKeys.h), a small shellcode blob. 
	The shellcode is executing in the powershell.exe process context.
	The shellcode reads the default value for HKCU\software\WUV, which contains a hidden buffer. 
	The buffer will appear to be "(value not set)" in Regedit. 
	It actually is the malware, XOR encoded with a key that is generated when InvisibleRegKeys executes, and that is burned into the shellcode blob.
	The shellcode decodes the malware and loads it (with a small PE loader) in the context of the powershell process.
	At this point the malware can inject into another process and call exit process to kill Powershell. Or the module can return from its entry point, at which point the shellcode exits the process. After 20 minutes the Powershell process will exit either way (the sleep(1200) in InvisibleRegKeys.h controls this).
	Check out pe_loader.cpp. This is the same loader the shellcode uses. It allocates double the memory the PE file would normal need for being loaded, and copies the PE file in the extra space. This lets you reflectively load the PE when doing process injection. 

2) InvisibleRegKeys.exe unpersist 
	Deletes the hidden value in HKCU\Software\Microsoft\Windows\CurrentVersion\Run.
	Deletes HKCU\software\WUV.
	
As always, use this for research purposes only.