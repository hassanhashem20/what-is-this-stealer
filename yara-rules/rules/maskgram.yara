rule MaskGram
{
    meta:
        author = "HassanHashem20"
        description = "MaskGram stealer system information file"
        reference = "https://github.com/hassanhashem20/what-is-this-stealer"
    
    strings:
        $x1 = "Disk Space (C:):" ascii
        $x2 = "CPU Architecture:" ascii
        $x3 = "System Uptime:" ascii
        $x4 = "User Language:" ascii
        $x5 = "Free Space:" ascii
        $x6 = "Total RAM:" ascii

    condition:
        all of them
}