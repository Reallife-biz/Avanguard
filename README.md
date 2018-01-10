# Avanguard
## The Win32 Anti-Intrusion Library  
### This library prevents some of injection techniques, debugging and static analyzing.  
Both x32 and x64 supports and includes:
* Static code encryptor
* Many anti-debugging techniques (WinAPI, NativeAPI, SEH, assembler and memory tricks)
* PE Analyzer
* Memory analyzer
* Call-stack analyzer
* Anti-injection techinques (against of CreateRemoteThread, manual modules mapping, injection through APC and AppInit_DLLs, context switching)
* Memory protection (kernel callbacks, remapping)
* Anti-splicing (modules executable sections and imports table verifying)
* Anti-macros (virtual keyboard and mouse input - useful for online games)
* Kernel modules info
* Threads and modules callbacks
* Handles keeper - prevents managing your app from other processes due to close handles of your process in external apps (for example, CheatEngine or another memory editors)
* TLS support
### Using
All you need is to load Avanguard.dll as soon as possible, but you can achieve more effective protection due to manual protection calls in your app, you know. For exmaple, you can insert anti-debugging inlines into your code and manipulate your data according the results of the called functions (for example, you can broke the data pointers or stack if AD detects the debugger), or you can redefine the modules and threads callbacks to realize your own checking algorithm. And much, much more.
