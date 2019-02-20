#!/usr/bin/python

import os
import pefile
import mmap
import sys
from termcolor import colored

def calc_aligned_size(size,alignment_size):
	if size % alignment_size == 0:
		return int(size/alignment_size) * alignment_size
	else:
		return (int(size / alignment_size) + 1) * alignment_size

def addSection(FILE_PE,FILE_PE_MOD):
	new_section_size_of_raw_data = 0x1000
	new_section_virtual_size =     0xFB0

	pe=pefile.PE(FILE_PE)

	number_of_sections=pe.FILE_HEADER.NumberOfSections
	size_of_Image=pe.OPTIONAL_HEADER.SizeOfImage
	file_alignment=pe.OPTIONAL_HEADER.FileAlignment
	section_alignment=pe.OPTIONAL_HEADER.SectionAlignment


	# sizeof(struct SECTION_HEADER) = 40 byte
	new_section_offset=pe.sections[-1].get_file_offset()+40
	print(colored("\n---------------- FILE HEADER -----------------",'green'))
	print(colored("[Info] Number of sections:              ",'green') +colored(str(hex(number_of_sections)) +" byte",'green'))
	print(colored("[Info] sizeof(struct SECTION_HEADER):   ",'green')+colored("40 byte",'green'))
	print(colored("[+] New number of sections:             ",'green') +colored(str(hex(number_of_sections+1)) + " byte",'green',attrs=['bold']))

	# OPTIONAL HEADER MODIFICATION
	new_section_aligned_size=calc_aligned_size(new_section_virtual_size,section_alignment)
	new_SizeOfImage= size_of_Image + new_section_size_of_raw_data
	print(colored("\n---------------- OPTIONAL HEADER -------------",'green'))
	print(colored("Calculating SizeOfImage...",'green'))
	print(colored("[Info] SizeOfImage: \n  => sum(section[i].aligned_virtual_size)",'green'))
	print(colored("[Info] Old SizeOfImage:                 ",'green') +colored(str(hex(size_of_Image)) +" byte",'green'))
	print(colored("[+] New SizeOfImage:                    ",'green') +colored(str(hex(new_SizeOfImage)) + " byte",'green',attrs=['bold']))

	last_section = {"Virtual_Size":pe.sections[-1].Misc_VirtualSize, 
			"RVA":pe.sections[-1].VirtualAddress, 
			"SizeOfRawData":pe.sections[-1].SizeOfRawData, 
			"PointerToRawData":pe.sections[-1].PointerToRawData,
			"virtual_aligned_size":""
			}

	last_section["virtual_aligned_size"] = calc_aligned_size(last_section["Virtual_Size"],section_alignment)
	new_RVA=last_section["RVA"] + last_section["virtual_aligned_size"]
	# CODE | EXECUTE | READ | WRITE
	character=0x60000020

	section_name=".l4y3r8"+'\x00'

	print(colored("\n---------------- SECTION HEADER --------------",'green'))
	print(colored("New section name:                       ",'green')+colored(section_name,'green',attrs=['bold']))
	print(colored("New section RAW size     (your choice): ",'green')+colored(str(hex(new_section_size_of_raw_data)) + " byte",'green',attrs=['bold']))
	print(colored("New section virtual size (your choice): ",'green')+colored(str(hex(new_section_virtual_size)) + " byte",'green',attrs=['bold']))
	print(colored("New section characteristics (RX):       ",'green')+colored(str(hex(character)),'green',attrs=['bold']))
	print(colored("\nCalculating new section offset...",'green'))
	print(colored("[Info] Last section header offset:      ",'green') + colored(str(hex(pe.sections[-1].get_file_offset())) + " byte",'green'))
	print(colored("[+] New section header address:         ",'green') +colored(str(hex(new_section_offset)),'green',attrs=['bold']))
	print(colored("\nCalculating RVA....",'green'))
	print(colored("[Info] Section alignment size:          ",'green') +colored(str(hex(section_alignment))+" byte",'green'))
	print(colored("[Info] Last section RVA:                ",'green') +colored(str(hex(last_section["RVA"])) + " byte",'green'))
	print(colored("[Info] Last section virtual size:       ",'green') +colored(str(hex(last_section["Virtual_Size"]))+" byte",'green'))
	print(colored("[+] New section RVA:                    ",'green') +colored(str(hex(new_RVA))+" byte",'green',attrs=['bold']))
	
	new_pointer_to_raw_data=last_section["PointerToRawData"] + last_section["SizeOfRawData"]
	print(colored("\nCalculating Raw size...",'green'))
	print(colored("[Info] File alignment size:             ",'green') +colored(str(hex(file_alignment)) + " byte",'green'))
	print(colored("[Info] Last section SizeOfRawData:      ",'green') +colored(str(hex(last_section["SizeOfRawData"])) + "byte",'green'))
	print(colored("[Info] Last section PointerToRawData:   ",'green') +colored(str(hex(last_section["PointerToRawData"])) +" byte",'green'))
	print(colored("[+] New section PointerToRawData:       ",'green') +colored(str(hex(new_pointer_to_raw_data)) + " byte",'green',attrs=['bold']))


	print(colored("-----------------------------------------",'green'))
	print(colored("[+] Writing file "+FILE_PE_MOD+"...",'green',attrs=['bold']))

#Create the section
	
	pe.set_bytes_at_offset(new_section_offset,    section_name.encode())
	pe.set_dword_at_offset(new_section_offset+8,  new_section_virtual_size)
	pe.set_dword_at_offset(new_section_offset+12, new_RVA)
	pe.set_dword_at_offset(new_section_offset+16, new_section_size_of_raw_data)
	pe.set_dword_at_offset(new_section_offset+20, new_pointer_to_raw_data)
	NULL_BYTES=12*"\x00"
	pe.set_bytes_at_offset(new_section_offset+24, NULL_BYTES.encode())
	pe.set_dword_at_offset(new_section_offset+36, character)
	
# Increase number of sections in FILE_HEADER
	pe.FILE_HEADER.NumberOfSections+=1
# Set new SizeOfImage
	pe.OPTIONAL_HEADER.SizeOfImage = new_SizeOfImage
	#pe.write(FILE_PE.split(".")[0]+"_mod.exe")
	pe.write(FILE_PE_MOD)

def resizeFile(FILE_PATH,file_size):
	with open(FILE_PATH,"a+b") as fd:	
		map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
		map.resize(file_size+0x2000)
		map.close()
		

	
if (len(sys.argv) < 2):
	print("Usage: "+sys.argv[0]+" <exe_to_modify.exe>")
	exit(1)
else:	
	FILE_PE=sys.argv[1]
	FILE_PE_MOD=FILE_PE.split(".")[0]+"_mod.exe"
	print("Open file: "+FILE_PE)

file_size=os.path.getsize(FILE_PE)

addSection(FILE_PE,FILE_PE_MOD)

resizeFile(FILE_PE_MOD,file_size)
