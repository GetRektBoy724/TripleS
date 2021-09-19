# TripleS - Stealing Syscall Stub, Modernized
TripleS or 3S is short for Syscall Stub Stealer. It freshly "steal" syscall stub straight from the disk. You can use TripleS for evading userland hooks from EDRs/AVs.TripleS doesnt invoke any unmanaged API, its all .NET's managed function. I cant say that its better than D/Invoke's GetSyscallStub, but in my opinion, its better.
Anyway, I suck at making description, so if you have any question,you can DM me on Discord.

## Story
I always hate the idea of hard-coding syscall stub on our malware, cause syscall is version dependent, and its kinda complicated to implement it on your code. And after I know that D/Invoke has a function to get the syscall stub from the disk, I challenged myself, can I make one too? And can I make it even better? Well, this is the result of that challenge. 

## Usage
1. Create a new instance of TripleS
```
TripleS syscallstealer = new TripleS();
```
2. Steal the syscall stub that you want (you can steal more syscall later on without creating a new instance again)
```
string[] requiredSyscalls = { "NtProtectVirtualMemory", "NtAllocateVirtualMemory", "NtCreateThreadEx", "NtWaitForSingleObject" };
syscallstealer.StealSyscallStub(requiredSyscalls);
```
3. Use the syscall stub while its hot (dont forget to prepare the delegate ;) )
```
NTAVM fSyscallNTAVM = (NTAVM)Marshal.GetDelegateForFunctionPointer(syscallstealer.StubAddressTable["NtAllocateVirtualMemory"], typeof(NTAVM));
NTPVM fSyscallNTPVM = (NTPVM)Marshal.GetDelegateForFunctionPointer(syscallstealer.StubAddressTable["NtProtectVirtualMemory"], typeof(NTPVM));
NTCTE fSyscallNTCTE = (NTCTE)Marshal.GetDelegateForFunctionPointer(syscallstealer.StubAddressTable["NtCreateThreadEx"], typeof(NTCTE));
NTWFSO fSyscallNTWFSO = (NTWFSO)Marshal.GetDelegateForFunctionPointer(syscallstealer.StubAddressTable["NtWaitForSingleObject"], typeof(NTWFSO));
```
If you still confused ,you can take a look at `main` function from `UsageExample` class,its a local shellcode injector function with TripleS implemented. This code uses C# 5,so it can be compiled with the built-in CSC from Windows 10. 

![TripleSUsageExample](https://user-images.githubusercontent.com/41237415/133930487-3f9c570a-73b1-4ca1-a47c-c5bc95233027.png)

## Note
- If you want to copy the code,Please dont forget to credit me.
- Github dont like my Sublime indentation settings so dont roast me please.
