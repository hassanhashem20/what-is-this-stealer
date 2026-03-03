rule Misericorde
{
    meta:
        author = "HassanHashem20"
        description = "Misericorde Stealer system information file and it is still need some improvments after obtaining more rules"
        reference = "https://github.com/hassanhashem20/what-is-this-stealer"
        reference = "https://cryptolek.info/tag/misericorde-stealer/"
    strings:
        $x1 = "OS Product:" ascii
        $x2 = "Buildtag:" ascii
        $x3 = "Screensize:" ascii
        $x4 = "Hwid:" ascii
        $x5 = "[System]" ascii
        $x6 = "Screensize:" ascii
        

    condition:
        5 of ($x*)
}