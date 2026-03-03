rule Lumma
{
    meta:
        author = "HassanHashem20"
        description = "Lumma2 system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "LummaC2, Build:" ascii
        $x2 = "LID (Lumma ID):" ascii
        $x3 = "- Screen resolution:" ascii
        $x4 = "- HWID:" ascii
        $x5 = "- OS Version:" ascii
        $x6 = "NetBIOS:" ascii
        $x7 = "CPU Vendor:" ascii
        $x8 = "RAM Size:" ascii
        $x9 = "Local Date:" ascii
        $x10 = "- Elevated:" ascii

    condition:
        5 of ($x*)
}
