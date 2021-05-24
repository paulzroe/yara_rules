import pe

rule truncated_file
{
    meta:
        description = "Detects Truncated Windows PE file"
        created_by = "PaulK"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        date = "2021-05-24"

    condition:
        filesize < pe.sections[pe.number_of_sections - 1].raw_data_size + pe.sections[pe.number_of_sections -1].raw_data_offset
}


rule nsis_truncated_file
{

    meta:
        description = "Detects Truncated NSIS installer"
        created_by = "PaulK"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        date = "2021-05-24"

        strings:
                $nullsoft = "Nullsoft"

    condition:
        $nullsoft at (pe.sections[pe.number_of_sections - 1].raw_data_size + pe.sections[pe.number_of_sections -1].raw_data_offset + 8) and

        filesize < pe.sections[pe.number_of_sections - 1].raw_data_size + pe.sections[pe.number_of_sections -1].raw_data_offset +  int32(pe.sections[pe.number_of_sections - 1].raw_data_size + pe.sections[pe.number_of_sections -1].raw_data_offset + 0x18)
}
