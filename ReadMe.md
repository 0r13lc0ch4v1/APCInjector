# APCInjector

APCInjector is a Windows Kernel Driver written in C++ and supports Windows7-32bit.

The driver is waiting for a process to start loading when it does the driver tracks the dll loaded to the process and when ntdll.dll dll is loaded we want to insert the shellcode to the APC queue. 
After ntdll.dll dll is loaded the driver acquires the process thread, and inserts the injection shellcode to the APC queue that in turn will be executed in user-mode and inject the dll to the selected process.

I used this three sources for this project

* [rohitab - inject-dll-from-kernel-mode] - The structure for the APC injection driver.
* [writing_windows_shellcode] - The base for the shellcode.
* [Using (Modern) C++ in Driver Development] - This driver is written in C++ by this article inspiration.

### Todos

 - Write a logic to receive the processes names and the dll path from the user via Registry, IOCTL.
 - Write code to handle edge cases.
 - Find why the process name acquired by PsGetProcessImageFileName function is limited to 15 characters.
 - Make all the hardcoded parts more dynamic - it has a direct relationship with the first two TO-DOs

License
----

MIT

## disclaimer
I wrote this driver for study purposes only. 
I don't write drivers, and this is my (more or less), the first driver I ever wrote. 
Along the way, I deleted and added code so it is not my best work, but still, I think it can help the community.

**Free Software, Hell Yeah!**


   [rohitab - inject-dll-from-kernel-mode]: <https://www.rohitab.com/discuss/topic/40737-inject-dll-from-kernel-mode/>
   [writing_windows_shellcode]: <https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html>
   [Using (Modern) C++ in Driver Development]: <http://blogs.microsoft.co.il/pavely/2016/11/30/using-modern-c-in-driver-development/>