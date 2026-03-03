rule EncryptHub
{
    meta:
        author = "HassanHashem20"
        description = "EncryptHub stealer system information file need improvments"
        reference = "https://github.com/hassanhashem20/what-is-this-stealer"
        reference = "https://web.archive.org/web/20250521182251/https://www.trendmicro.com/zh_hk/research/25/c/deep-dive-into-water-gamayun.html"
        reference = "https://g0njxa.medium.com/approaching-stealers-devs-a-brief-interview-with-encrypthub-fickle-stealer-518bde3b174f"
    strings:
        $x1 = "Fickle-encrypthub-" ascii
        $x2 = "OS Build:" ascii
        $x3 = "[Network Adapters]" ascii
        $x4 = "Manufacturer: " ascii
        $x5 = "Model: " ascii
        $x6 = "Uptime:" ascii
        $x7 = "Log Name :" ascii
        $x8 = "Build ID :" ascii
        

    condition:
        5 of ($x*)
}