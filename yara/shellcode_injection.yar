import "pe"

rule shellcode_injection
{
    meta:
        description = "Rule for detecting shellcode injection using CreateThread"
        author = "auteqia"
    strings:
	    $api1_01 = "VirtualAlloc"

	    $api_02 = "VirtualProtect"

        $api_03 = "CreateThread"


condition:
	// MZ at the beginning of file
        uint16(0) == 0x5a4d and

        pe.imports("kernel32.dll","VirtualAlloc") or
		pe.imports("kernel32.dll","VirtualProtect") or
		pe.imports("kernel32.dll","CreateThread") or