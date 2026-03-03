rule MilleniumRAT
{
    meta:
        author = "HassanHashem20"
        description = "MilleniumRAT system information file"
        reference = "https://github.com/hassanhashem20/what-is-this-stealer"
        reference = "https://github.com/shienigma/Millenium-RAT"
    strings:
        $x1 = "🖥Computer info:" ascii
        $x2 = "📡Whois:" ascii
        $x3 = "Installed antivirus:" ascii
        $x4 = "Started as admin:" ascii
        $x5 = "System time:" ascii
        $x6 = "Millenium RAT," ascii
        $x7 = "⚙️Process list:" ascii
        $x8 = "ðŸ–¥Computer info:" ascii
        $x9 = "ðŸ›¡Security:" ascii
        $x10 = "ðŸ“¡Whois:" ascii
        $x11 = "ðŸ“¡Security:" ascii
        $x12 = "ðŸ“¡Whois:" ascii
        $x13 = "Computer info:" ascii
    condition:
        5 of ($x*)
}