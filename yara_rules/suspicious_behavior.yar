rule Hidden_Executable {
    meta:
        description = "Detects executable files masquerading as documents"
        author = "Deloitte Threat Intelligence"
        reference = "https://attack.mitre.org/techniques/T1036/"
        severity = "high"
        mitre_attack_id = "T1036"
    
    strings:
        $mz_header = { 4D 5A }  // MZ header for PE files
        $elf_header = { 7F 45 4C 46 }  // ELF header for Linux
    
    condition:
        // Reference both strings in the condition
        ($mz_header at 0) or  // Windows PE signature at start of file
        ($elf_header at 0)    // Linux ELF signature at start of file
}

rule Process_Injection_Attempt {
    meta:
        description = "Detects common process injection patterns"
        author = "Deloitte Threat Intelligence"
        reference = "https://attack.mitre.org/techniques/T1055/"
        severity = "high"
        mitre_attack_id = "T1055"
    
    strings:
        $inject1 = "VirtualAllocEx" fullword
        $inject2 = "WriteProcessMemory" fullword
        $inject3 = "CreateRemoteThread" fullword
    
    condition:
        // At least 2 of the injection patterns
        2 of ($inject1, $inject2, $inject3)
}