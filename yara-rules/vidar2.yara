rule Vidar
{
    meta:
        author = "hassanhashem20"
        description = "Detects Vidar Stealer"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar"
        modified = "2026-02-05"
        modifier = "Hassan Hashem"
    
    strings:
        $x1 = "Country: " ascii
        $x2 = "MachineID: " ascii
        $x3 = "Work Dir: " ascii
        $x4 = "[Hardware]" ascii
        $x5 = "[Processes]" ascii
        $x6 = "[Software]" ascii
    
    condition:
        $x1 and $x3 and $x4 and $x5 and $x6
}
