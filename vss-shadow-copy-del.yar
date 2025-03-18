rule Ransomware_WannaCry {

    meta:
        author = "auteqia"
        version = "1.0"
        description = "simple rule to detect strings from WannaCry ransomware related to Volume Shadow Copy"

    strings:
	$vssdel1 = "vssadmin delete shadows"
	$vssdel2 = "vssadmin delete shadows /all"
	$wmivssdel = "wmic shadowcopy delete"
	$wmi_vss_del_all = "wmic shadowcopy delete /all"
	$cmdargs = "-delete"

    condition:
        any of ($vssdel1, $vssdel2, $wmivssdel, $wmi_vss_del_all) or
        any of ($cmdargs)

}
