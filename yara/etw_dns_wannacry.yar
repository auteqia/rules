rule dns_wannacry_domain {
	strings:
		$s1 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide nocase
	condition:
		$s1
}
