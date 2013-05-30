virustotal
==========

Command-line utility to automatically lookup on VirusTotal all files recursively contained in a directory.
You can also specify the path to a single file directly:

    nex@localhost:~$ python vt.py --key <api> downloads/
    [*] (downloads/44491d810062e6ad517914f442d44368550c87a3ccafe593185d06b571253037
         downloads/duplicate_example): FOUND
        \_ Results: 43/46 DETECTED
           SHA256: 44491d810062e6ad517914f442d44368550c87a3ccafe593185d06b571253037
           Scan Date: 2013-05-13 05:20:45
           Signatures:
            Win32.Worm.Downadup.Gen
            Worm/W32.Kido.157798
            Win32.Worm.Conficker.B.3
            Artemis!FBD8778D87C0
            Riskware
            Riskware
            W32/Kido.ih
            Trojan.Win32.Kido.ieisa
            W32/Conficker!Generic
            W32.Downadup.B
            Conficker.FA
            Win32/Kido!generic
            WORM_DOWNAD.AD
            Win32:Rootkit-gen [Rtk]
            Win32.Conficker.worm
            [...]
    [*] (downloads/0f4a6e4132d55949b1b7257411fde6ba1caae6c155d564589e01832c0d7f99a3): FOUND
        \_ Results: 45/47 DETECTED
           SHA256: 0f4a6e4132d55949b1b7257411fde6ba1caae6c155d564589e01832c0d7f99a3
           Scan Date: 2013-05-30 04:56:13
           Signatures:
            Worm/W32.Kido.165141
            Win32.Worm.Conficker.B.3
            Artemis!7C84915A299F
            Worm.Conficker
            Trojan
            NetWorm
            W32/Kido.fk
            Trojan.Win32.Kido.cdstu
            W32/Conficker!Generic
            W32.Downadup.B
            Conficker.HQ
            Win32/Kido!generic
            WORM_DOWNAD.AD
            Win32:Rootkit-gen [Rtk]
            Win32.Banker
            Trojan.Dropper-18535
            Trojan.Win32.Genome.vnvd
            Worm.Generic.63025
            [...]
    [*] (downloads/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855): FOUND
    [*] (downloads/cfc5bef5b3a8bd21d5b9748832db14f6966154867c946564e003e0febf2b6c92): FOUND
        \_ Results: 45/47 DETECTED
           SHA256: cfc5bef5b3a8bd21d5b9748832db14f6966154867c946564e003e0febf2b6c92
           Scan Date: 2013-05-30 05:11:03
           Signatures:
            Worm.Generic.393285
            Worm/W32.Kido.165025
            Worm.Conficker.Gen
            W32/Conficker.worm.gen.a
            Worm.Conficker
            Riskware
            Riskware
            Trojan/Downloader.Kido.bj
            Trojan.Win32.Shadow.bdjonf
            W32/Conficker!Generic
            W32.Downadup.B
            Conficker.ESK
            Win32/Conficker
            WORM_DOWNAD.AD
            Win32:Confi [Wrm]
            Worm.Kido-25
            Net-Worm.Win32.Kido.ih
            Worm.Generic.393285
            Worm.Kido!Dya6ZOjm14U
            [...]