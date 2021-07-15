# TripleS
TripleS or 3S is short for Syscall Stub Stealer.It freshly "steal" syscall stub straight from the disk.You can use TripleS for evading userland hooks from EDRs/AVs.
Anyway,i suck at making description,so if you have any question,you can DM me on Discord.

# Usage
Simply load the pre-compiled DLL or add the code function and call the `StealSyscallStub` or `StealSyscallStubSilently`(if you dont want any console prints) function from the `TripleS` class. You can load the pre-compiled DLL on Powershell with Reflection.Assembly too! This code uses C# 5,so it can be compiled with the built-in CSC from Windows 10.You can trim of the code that I give a `// ---code for usage example---` comment.If you dont know how to use TripleS,you can take a look at `UsageExample` function from `TripleS` class,its a local shellcode injector function.

![TripleSUsageExample](https://user-images.githubusercontent.com/41237415/125644009-9fab3a38-c353-415a-b164-1c609b994139.png)

# Note
- If you want to copy the code,Pls dont forget to credit me
- Github dont like my Sublime indentation settings so dont roast me pls
