rule Lumma
{
    meta:
        author = "hassanhashem20"
        description = "Lumma3 system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "LummaC2, Build" ascii
        $x2 = "LID (Lumma ID):" ascii
        $x3 = "- ComputerNameDnsHostname:" ascii
        $x4 = "- ComputerNameNetBIOS:" ascii
        $x5 = "- Physical Installed Memory:" ascii
        $x6 = "NetBIOS:" ascii
        $x7 = "CPU Vendor:" ascii
        $x8 = "RAM Size:" ascii
        $x9 = "Local Date:" ascii
        $x10 = "- Elevated:" ascii

    condition:
        5 of ($x*)
}
