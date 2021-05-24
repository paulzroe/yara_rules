rule rtf_mal_object_gen
{
    meta:
        description = "Detects Possible Malicious Objects in RTF"
        created_by = "PaulK"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        date = "2021-05-24"
        
    strings:
        $obj_a = "\\objdata" //objdata control word
        $obj_b = "d0cf11e0a" //docfile magic
        
        $not_1 = "5363726970744272696467652e5363726970744272696467652e31" // ScriptBridge.ScriptBridge.1
        $not_2 = "10000000466f726d732e54657874426f782e3100f439b27100" // Forms.TextBox.1
        $not_3 = "*\\objclass PBrush}{\\*\\objdata 0105"    //PBrush Objects
        $not_4 = "*\\objclass Excel.Sheet.8}{\\*\\objdata 0105"
        $not_5 = "*\\objclass Equation.3}{\\*\\objdata 0105"  //Equation.3 object declared. Equation.3 object is a valid use
        $not_6 = "*\\objclass MSPhotoEd.3}{\\*\\" 
        $not_7 = "*\\objclass Package}{\\*\\objdata 0105" 
        $not_8 = "*\\objclass Forms.HTML:Hidden.1}{\\*\\objdata 0105"
        $not_9 = "*\\objclass Forms.CheckBox.1}{\\*\\objdata 0105"
        $not_10 = "*\\objclass MSDraw}{\\*\\objdata 0105"
        
        
    condition:
        uint32(0) == 0x74725c7b and all of ($obj*) and not any of ($not*)
        
        // To do: It is possible that RTF header is prepended with 0d 0a (8ce394d39c41c2b5640d81b4942cedaac73cd7c0838a70a07efacd7034cf36ab)
        // or just 0a
        
}