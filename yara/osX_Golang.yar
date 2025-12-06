rule osx_GoLang
{
meta:
    author = "Josh Grunzweig"
    description = "Attempts to identify samples written in Go compiled for OSX."
    reference = "https://unit42.paloaltonetworks.com/the-gopher-in-the-room-analysis-of-golang-malware-in-the-wild/"
     strings:
        $Go = "go.buildid"
    condition:
        (
            uint32(0) == 0xfeedface or
            uint32(0) == 0xcefaedfe or
            uint32(0) == 0xfeedfacf or
            uint32(0) == 0xcffaedfe or 
            uint32(0) == 0xcafebabe or
            uint32(0) == 0xbebafeca
        ) and
        $Go
}