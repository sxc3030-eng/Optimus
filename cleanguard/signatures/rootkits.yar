/*
    CleanGuard Pro - Rootkit Detection Rules
    Signatures for kernel-mode and user-mode rootkit techniques
    Last Updated: 2026-03-24
*/

rule Rootkit_SSDT_Hook
{
    meta:
        description = "Detects SSDT hooking techniques used by kernel-mode rootkits"
        severity = "critical"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "rootkit"

    strings:
        $ssdt1 = "KeServiceDescriptorTable" ascii wide nocase
        $ssdt2 = "KeServiceDescriptorTableShadow" ascii wide nocase
        $ssdt3 = "KiServiceTable" ascii wide nocase
        $hook1 = "ZwQuerySystemInformation" ascii wide nocase
        $hook2 = "NtQuerySystemInformation" ascii wide nocase
        $hook3 = "ZwQueryDirectoryFile" ascii wide nocase
        $hook4 = "NtQueryDirectoryFile" ascii wide nocase
        $hook5 = "ZwEnumerateValueKey" ascii wide nocase
        $hook6 = "NtEnumerateValueKey" ascii wide nocase
        $hook7 = "ZwQueryValueKey" ascii wide nocase
        $hook8 = "NtOpenProcess" ascii wide nocase
        $hook9 = "NtReadVirtualMemory" ascii wide nocase
        $mdl1 = "MmGetSystemRoutineAddress" ascii wide nocase
        $mdl2 = "MmMapIoSpace" ascii wide nocase
        $mdl3 = "MmCreateMdl" ascii wide nocase
        $mdl4 = "MmBuildMdlForNonPagedPool" ascii wide nocase
        $mdl5 = "MmMapLockedPages" ascii wide nocase
        $wp1 = "__writecr0" ascii wide nocase
        $wp2 = "cr0" ascii wide nocase
        $wp3 = "write_cr0" ascii wide nocase
        $wp4 = "cli" ascii wide nocase

    condition:
        (1 of ($ssdt*) and 2 of ($hook*)) or
        (1 of ($ssdt*) and 1 of ($mdl*)) or
        (2 of ($hook*) and 1 of ($wp*))
}

rule Rootkit_DriverLoad
{
    meta:
        description = "Detects suspicious kernel driver loading and device creation patterns"
        severity = "critical"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "rootkit"

    strings:
        $drv1 = "NtLoadDriver" ascii wide nocase
        $drv2 = "ZwLoadDriver" ascii wide nocase
        $drv3 = "NtUnloadDriver" ascii wide nocase
        $drv4 = "ZwUnloadDriver" ascii wide nocase
        $dev1 = "IoCreateDevice" ascii wide nocase
        $dev2 = "IoCreateSymbolicLink" ascii wide nocase
        $dev3 = "IoDeleteDevice" ascii wide nocase
        $dev4 = "IoDeleteSymbolicLink" ascii wide nocase
        $entry1 = "DriverEntry" ascii wide nocase
        $entry2 = "DriverUnload" ascii wide nocase
        $entry3 = "DriverObject" ascii wide nocase
        $entry4 = "DRIVER_OBJECT" ascii wide nocase
        $entry5 = "DEVICE_OBJECT" ascii wide nocase
        $irp1 = "IRP_MJ_CREATE" ascii wide nocase
        $irp2 = "IRP_MJ_DEVICE_CONTROL" ascii wide nocase
        $irp3 = "IoCompleteRequest" ascii wide nocase
        $irp4 = "IOCTL" ascii wide nocase
        $reg1 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services" ascii wide nocase
        $reg2 = "ImagePath" ascii wide nocase
        $reg3 = "\\Driver\\" ascii wide nocase
        $reg4 = "\\Device\\" ascii wide nocase
        $vuln1 = "\\??\\PhysicalMemory" ascii wide nocase
        $vuln2 = "\\Device\\PhysicalMemory" ascii wide nocase

    condition:
        (1 of ($drv*) and 1 of ($dev*)) or
        (1 of ($entry*) and 1 of ($dev*) and 1 of ($irp*)) or
        (1 of ($drv*) and 1 of ($reg*)) or
        any of ($vuln*)
}

rule Rootkit_HiddenProcess
{
    meta:
        description = "Detects process hiding via EPROCESS manipulation and DKOM techniques"
        severity = "critical"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "rootkit"

    strings:
        $proc1 = "NtQuerySystemInformation" ascii wide nocase
        $proc2 = "ZwQuerySystemInformation" ascii wide nocase
        $proc3 = "SystemProcessInformation" ascii wide nocase
        $proc4 = "SYSTEM_PROCESS_INFORMATION" ascii wide nocase
        $dkom1 = "PsActiveProcessHead" ascii wide nocase
        $dkom2 = "ActiveProcessLinks" ascii wide nocase
        $dkom3 = "EPROCESS" ascii wide nocase
        $dkom4 = "PsGetCurrentProcess" ascii wide nocase
        $dkom5 = "PsLookupProcessByProcessId" ascii wide nocase
        $dkom6 = "PsGetProcessId" ascii wide nocase
        $dkom7 = "PsGetProcessImageFileName" ascii wide nocase
        $unlink1 = "Flink" ascii wide nocase
        $unlink2 = "Blink" ascii wide nocase
        $unlink3 = "LIST_ENTRY" ascii wide nocase
        $unlink4 = "RemoveEntryList" ascii wide nocase
        $hide1 = "ObRegisterCallbacks" ascii wide nocase
        $hide2 = "PsSetCreateProcessNotifyRoutine" ascii wide nocase
        $hide3 = "PsSetCreateThreadNotifyRoutine" ascii wide nocase
        $hide4 = "PsSetLoadImageNotifyRoutine" ascii wide nocase

    condition:
        (1 of ($proc*) and 2 of ($dkom*)) or
        (2 of ($dkom*) and 1 of ($unlink*)) or
        (1 of ($proc*) and 1 of ($dkom*) and 1 of ($hide*))
}

rule Rootkit_BootSector
{
    meta:
        description = "Detects MBR/VBR modification and boot sector rootkit techniques"
        severity = "critical"
        author = "CleanGuard Pro"
        date = "2026-03-24"
        category = "rootkit"

    strings:
        $mbr1 = "\\\\.\\PhysicalDrive0" ascii wide nocase
        $mbr2 = "\\\\.\\PhysicalDrive" ascii wide nocase
        $mbr3 = "\\Device\\Harddisk0\\DR0" ascii wide nocase
        $mbr4 = "\\\\.\\PHYSICALDRIVE0" ascii wide nocase
        $disk1 = "CreateFileA" ascii wide nocase
        $disk2 = "CreateFileW" ascii wide nocase
        $disk3 = "WriteFile" ascii wide nocase
        $disk4 = "DeviceIoControl" ascii wide nocase
        $disk5 = "SetFilePointer" ascii wide nocase
        $ioctl1 = "IOCTL_DISK_GET_DRIVE_GEOMETRY" ascii wide nocase
        $ioctl2 = "IOCTL_DISK_GET_PARTITION_INFO" ascii wide nocase
        $ioctl3 = "FSCTL_LOCK_VOLUME" ascii wide nocase
        $ioctl4 = "FSCTL_DISMOUNT_VOLUME" ascii wide nocase
        $int1 = "int 13h" ascii wide nocase
        $int2 = "INT 13" ascii wide nocase
        $int3 = "int 0x13" ascii wide nocase
        $boot1 = { 55 AA }
        $boot2 = "bootmgr" ascii wide nocase
        $boot3 = "NTLDR" ascii wide nocase
        $boot4 = "BOOTMGR" ascii wide
        $boot5 = "winload" ascii wide nocase
        $vbr1 = "NTFS" ascii wide
        $vbr2 = "FAT32" ascii wide
        $sector1 = "sector" ascii wide nocase
        $sector2 = "MBR" ascii wide

    condition:
        (1 of ($mbr*) and 1 of ($disk*)) or
        (1 of ($mbr*) and 1 of ($ioctl*)) or
        (1 of ($int*) and 1 of ($boot*)) or
        (1 of ($mbr*) and $boot1)
}
