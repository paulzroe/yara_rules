import "elf"
import "math"


rule truncated_segments :  truncated
{
    meta:
        description = "Detects Truncated ELF file"
        created_by = "PaulK"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        date = "2021-05-24"
		
	condition:
		for any i in (0..elf.number_of_segments - 1) : ( (elf.segments[i].offset + elf.segments[i].file_size)  > filesize)
		// and elf.number_of_sections == 0 and
		//elf.sh_entry_size == 0
}


//rule truncated_section_32bit_le :  truncated
//{
//	meta:
//		author = "Paul Kimayong"
//		filetype = "elf"
//		description = "Detect truncated ELF files by checking segment offsets and sizes"
//		version = "1.0"
//		date = "2019-03-07"
//	condition:
//		int32(0x20) > filesize and (elf.machine==elf.EM_M32 or elf.machine==elf.EM_386)
//}


rule truncated_segments_packed :  truncated
{
    meta:
        description = "Detects Truncated ELF file"
        created_by = "PaulK"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        date = "2021-05-24"

		
		
	condition:
		(elf.number_of_sections == 0 or elf.number_of_sections>1000) and elf.number_of_segments < 4  and math.entropy(300, 1000) >= 6.9 and 
		(elf.segments[0].offset + elf.segments[0].file_size > filesize)
		
		
}

rule truncated_segments_not_packed :  truncated
{
    meta:
        description = "Detects Truncated ELF file"
        created_by = "PaulK"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        date = "2021-05-24"
		
	condition:
		math.entropy(300, 1000) < 6.9 and 
		for any i in (0..elf.number_of_segments - 1) : ( (elf.segments[i].offset + elf.segments[i].file_size)  > filesize) 
		
		
		
}



//rule entropy_gt_69 : entropy
//{
//	meta:
//		author = "Paul Kimayong"
//		filetype = "elf"
//		description = "Detect truncated ELF files by checking segment offsets and sizes"
//		version = "1.0"
//		date = "2019-03-07"
//	condition:
//		math.entropy(300, 1000) >= 6.8 
//		
//		
//}
//
//rule entropy_lt_65 : entropy
//{
//	meta:
//		author = "Paul Kimayong"
//		filetype = "elf"
//		description = "Detect truncated ELF files by checking segment offsets and sizes"
//		version = "1.0"
//		date = "2019-03-07"
//	condition:
//		math.entropy(300, 1000) <= 6.8 
//		
//		
//}

//to detect truncated conditions:
//
//section_header_offset > filesize
//if sample_is_packed: 
//	first_segment[offset] + first_segment[size] > filesize

import "elf"
import "math"

rule upx_normal : packer
{
    meta:
        description = "Contains an unmodified UPX stub"
        created_by = "PaulK"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        date = "2021-05-24"
		
	strings:
		$upx = "UPX!"		
		
	condition:
		$upx in (0..380) and $upx in (filesize - 50 .. filesize) and math.entropy(300, 1000) >= 7 and
		(elf.number_of_sections == 0 or elf.number_of_sections>1000) and elf.number_of_segments < 4 

} 

rule upx_1 : packer

{
    meta:
        description = "UPX packed ELF file"
        created_by = "PaulK"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        date = "2021-05-24"
		
	strings:
		$upx = "UPX!"		
		$string1 = "PROT_EXEC|PROT_WRITE failed"		
		$string2 = "This file is packed with the UPX"
		
	condition:
		$upx in (0..380) and all of ($string*) and 
		(elf.number_of_sections == 0 or elf.number_of_sections>1000) and elf.number_of_segments < 4 

} 
rule generic_packer : packer
{
    meta:
        description = "Detects generic ELF packer"
        created_by = "PaulK"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        date = "2021-05-24"
		
		
	condition:
		
		(elf.number_of_sections == 0 or elf.number_of_sections>1000) and elf.number_of_segments < 4  and math.entropy(300, 1000) >= 7
		
} 

/*
rule mod_upx : packer
{
	meta:
		description = "Contains a modified UPX stub"
		
	strings:
		$mod_upx = "UPX!"		
		
	condition:
		uint32(uint16(0x2A)*uint16(0x2c) + uint32(0x1c) + 4) == 0x21585055 and $mod_upx in (filesize - 50 .. filesize) and math.entropy(300, 1000) >= 7 and
		(elf.number_of_sections == 0 or elf.number_of_sections>1000) and elf.number_of_segments < 4

} 

rule mod_upx_be : packer
{
	meta:
		description = "Contains a modified UPX stub"
		
	strings:
		$mod_upx = "UPX!"			
		
	condition:
		uint32(uint16be(0x2A)*uint16be(0x2c) + uint32be(0x1c) + 4) == 0x21585055 and $mod_upx in (filesize - 50 .. filesize) and math.entropy(300, 1000) >= 7 and
		(elf.number_of_sections == 0 or elf.number_of_sections>1000) and elf.number_of_segments < 4

} 




rule mod_upx : packer
{
	meta:
		description = "Contains a modified UPX stub"
		
	strings:
		$mod_upx = {0a 00 00 00}		
		
	condition:
		uint32(uint16(0x2A)*uint16(0x2c) + uint32(0x1c) + 4) == 0x0000000a and $mod_upx in (filesize - 50 .. filesize) and math.entropy(300, 1000) >= 7 and
		(elf.number_of_sections == 0 or elf.number_of_sections>1000) and elf.number_of_segments < 4

} 


rule mod_upx : packer
{
	meta:
		description = "Contains a modified UPX stub"
		
	//strings:
	//	$mod_upx = {0a 00 00 00}		
		
	condition:
		uint32(uint16(0x2A)*uint16(0x2c) + uint32(0x1c) + 4) == uint32(filesize - 0x24) and 
		uint32(uint16(0x2A)*uint16(0x2c) + uint32(0x1c) + 4) !=  0x21585055 and 
		uint32(uint16(0x2A)*uint16(0x2c) + uint32(0x1c) + 4) != 0x00000000 and 
		uint32(uint16(0x2A)*uint16(0x2c) + uint32(0x1c) + 4) != 0x214c534b and 
		math.entropy(300, 1000) >= 7 and
		(elf.number_of_sections == 0 or elf.number_of_sections>1000) and 
		elf.number_of_segments < 4

} 

rule mod_upx_be : packer
{
	meta:
		description = "Contains a modified UPX stub for Big Endian"
		
	//strings:
	//	$mod_upx = {0a 00 00 00}			
		
	condition:
		uint32(uint16be(0x2A)*uint16be(0x2c) + uint32be(0x1c) + 4) == uint32(filesize - 0x24) and 
		uint32(uint16be(0x2A)*uint16be(0x2c) + uint32be(0x1c) + 4) !=  0x21585055 and
		uint32(uint16be(0x2A)*uint16be(0x2c) + uint32be(0x1c) + 4) != 0x00000000 and		
		math.entropy(300, 1000) >= 7 and
		(elf.number_of_sections == 0 or elf.number_of_sections>1000) and elf.number_of_segments < 4

} 
*/

