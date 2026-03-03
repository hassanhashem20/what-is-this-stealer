rule MacSync
{
    meta:
        author = "HassanHashem20"
        description = "MacSync stealer system information file"
        reference = "https://github.com/hassanhashem20/what-is-this-stealer"
    
    strings:
        $x1 = "MacSync Stealer" ascii
        $x2 = "Password:" ascii
        $x3 = "Graphics/Displays" ascii
        $x4 = "Build Tag:" ascii
        $x5 = "System Software Overview:" ascii
        $x6 = "Hyper-Threading Technology:" ascii
        $x7 = "Number of Processors:" ascii

    condition:
        5 of ($x*)
}