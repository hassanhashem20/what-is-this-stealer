rule Lumma
{
    meta:
        author = "hassanhashem20"
        description = "Lumma system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "- LummaC2 Build:" ascii
        $x2 = "- LID:" ascii
        $x3 = "- Configuration:" ascii
        $x4 = "- Display resolution:" ascii
        $x5 = "- HWID:" ascii
        $x6 = "- OS Version:" ascii
        $x7 = "NetBIOS:" ascii
        $x8 = "CPU Vendor:" ascii
        $x9 = "RAM Size:" ascii
        $x10 = "Local Date:" ascii
        $x11 = "- Elevated:" ascii

    condition:
        6 of ($x*)
}