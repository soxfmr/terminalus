#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import subprocess
import os
import re
import sys
import base64

output_dir = os.path.join('tmp', 'termius')

HELP="""
The terminal file has been converted into separated plist files in XML format.
  You cloud search for specific keywords such as 'CommandString' to detect
  potential malicious commands masqueraded in the sections of the plist files.

  For more details, please refer to: 
  https://medium.com/@metnew/exploiting-popular-macos-apps-with-a-single-terminal-file-f6c2efdfedaa
"""

def parse_terminal_file(file_path):
    # Step 2: Parse the file as XML
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    # Step 3: Get the 'dict' element
    dict_element = root.find('dict')
    
    # Step 4: Iterate over children of 'dict' element and store key-value pairs
    key_value_dict = {}
    dict_children = dict_element.findall('*')
    for i in range(len(dict_children) - 1):
        if dict_children[i].tag == 'key' and dict_children[i+1].tag == 'data':
            key = dict_children[i].text
            value = dict_children[i+1].text

            value = re.sub(r'\n\t', '', value)         
            value = base64.b64decode(bytes(value, 'utf-8'))

            key_value_dict[key] = value
    
    # Step 5: Create temporary files and write elemental values
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for key, value in key_value_dict.items():
        temp_file_path = os.path.join(output_dir, key) + '.plist'
        with open(temp_file_path, 'wb') as temp_file:
            temp_file.write(value)
        
        # Step 6: Run shell command to convert the temporary file to XML
        output_xml_file = os.path.join(output_dir, key) + '.xml'
        subprocess.run(['plutil', '-convert', 'xml1', '-o', output_xml_file, temp_file_path])
        
        # Remove temporary file
        os.remove(temp_file_path)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'{sys.argv[0]} <file.terminal>')
        sys.exit(-1)

	# Call the function to execute the steps
    parse_terminal_file(sys.argv[1])

    print('[+] Done')
    print(HELP)

