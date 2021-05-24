rule vba_malicious_obj_gen
{
    meta:
        description = "Detects Potentially Malicious Objects"
        created_by = "PaulK"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        date = "2021-05-24"        
        
    strings:
        //the following two ascii must be present in a macro code
        $keywords_1 = {52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00} //Root Entry   
        $keywords_2 = {5F 00 56 00 42 00 41 00 5F 00 50 00 52 00 4F 00 4A 00 45 00 43 00 54 00 00 00 00 00 00 00 00 00} //_VBA_PROJECT
        
        $autoopen_1 = "AutoExec" nocase
        $autoopen_2 = "AutoOpen" nocase
        $autoopen_3 = "AutoExit" nocase
        $autoopen_4 = "AutoClose" nocase
        $autoopen_5 = "Document_Close" nocase
        $autoopen_6 = "DocumentBeforeClose" nocase
        $autoopen_7 = "Document_Open" nocase
        $autoopen_8 = "Document_BeforeClose" nocase 
        $autoopen_9 = "Auto_Open" nocase
        $autoopen_10 = "Workbook_Open" nocase
        $autoopen_11 = "Workbook_Activate" nocase
        $autoopen_12 = "Auto_Close" nocase
        $autoopen_13 = "Workbook_Close" nocase
        $autoopen_14 = "_Painted" nocase //via ActiveX controls 

        
        $mal_keywords_1 = "Start-Process" nocase
        $mal_keywords_2 = "CreateObject" nocase  //It may have FP
        $mal_keywords_3 = "Run_"  //Commenting as it has FP
        $mal_keywords_4 = "powershell" nocase
        $mal_keywords_5 = "window hidden" nocase
        $mal_keywords_6 = "CallByName" //attempt to obfuscate strings
        $mal_keywords_7 = "Shell" //Commenting as it has FP
        $mal_keywords_8 = "Net.WebClient"
        $mal_keywords_9 = "URLDownloadToFileA"
        $mal_keywords_10 = "WScript.Shell" //It may have FP
        $mal_keywords_11 = "ShellExecute" 
        
        
        
        $not_qb_strings_1 = "Quickbooks"
        $not_qb_strings_2 = "payroll"
        

    condition:
        uint32(0) == 0xe011cfd0 and all of ($keywords*) and any of ($autoopen*) and any of ($mal_keywords*) and not any of ($not_qb_strings*)
        
}
