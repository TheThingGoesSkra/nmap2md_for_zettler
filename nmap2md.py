#!/usr/bin/env python

import re
import os
import sys
import xml.etree.ElementTree as ET
from optparse import OptionParser

import columns_definition

__version__ = "1.3"

def remove_code_blocks(content):
    content_cleaned = []
    code_block = False  
    for x in content:
        # detect code blocks, act accordingly
        if x[:3] == '```':
            code_block = not code_block
        elif not code_block:
            content_cleaned.append(x)

    return content_cleaned

def identify_headers(lines):
    headers = []
    re_hashtag_headers = r"^#+\ .*$"
    re_alternative_header_lvl1 = r"^=+ *$"
    re_alternative_header_lvl2 = r"^-+ *$"

    for i, line in enumerate(lines): 
        # identify headers by leading hashtags
        if re.search(re_hashtag_headers, line): 
            headers.append(line)
            
        ## identify alternative headers
        #elif re.search(re_alternative_header_lvl1, line): 
        #    headers.append('# ' + lines[i-1])    # unified h1 format
        #elif re.search(re_alternative_header_lvl2, line): 
        #    headers.append('## ' + lines[i-1])   # unified h2 format
            
    return headers

def identify_top_headers(lines):
    headers = []
    re_hashtag_headers = r"^# .*"

    for i, line in enumerate(lines): 
        # identify scripts headers by leading hashtags
        if re.search(re_hashtag_headers, line): 
            headers.append(line)
            
    return headers

parser = OptionParser(usage="%prog [options] file.xml", version="%prog " + __version__)

parser.add_option("-c", "--columns", default="Port,State,Service,Version,CPE", help="define a columns for the table")
parser.add_option(
    "--rc",
    "--row-cells",
    default="[port.number]/[port.protocol],[state],[service.name],[service.product] [service.version],[cpe]",
    help="define rows which will report certain data. Those rows: [port.number], [port.protocol], [state], "
         "[service.name], [service.product], [service.version] "
)
parser.add_option(
    "--print-empty",
    dest="print_empty",
    action="store_true",
    help="should addresses with no opened ports to be printed"
)
parser.add_option(
    "--sort",
    default="Port;asc",
    help="Sort results by provided row cell"
)

parser.add_option(
    "-n",
    dest="net_id",
    default="0",
    help="Give subnet id"
)
parser.set_defaults(print_empty=False)

(options, args) = parser.parse_args()

columns = options.columns.split(",")
row_cells = options.rc.split(",")

sorting = options.sort.split(";")
sorting_reverse = False

if len(sorting) == 2:
    try:
        if sorting[1] == 'desc':
            sorting_reverse = True
    except IndexError:
        print("[Err] Could not get sorting direction")
        print()
        sys.exit()

try:
    sorting_index = columns.index(sorting[0])
except ValueError:
    print("[Err] Please provide existing column")
    print()
    sys.exit()
except IndexError:
    print("[Err] No sorting value defined")
    print()
    sys.exit()

definitions = columns_definition.Element.build(columns_definition.definition)
hosts = {}
result = {}
port_scripts = {}
scripts={}
overview = {}

if len(columns) != len(row_cells):
    print("[Err] Columns and row cells amount should be equal")
    sys.exit()

try:
    tree = ET.parse(args[0])
except IndexError:
    print("[Err] No filename supplied as an argument")
    print()
    parser.print_help()
    sys.exit()
except IOError:
    print("[Err] Non-readable or non-existent file supplied as an argument")
    print()
    sys.exit()
except ET.ParseError:
    print("[Err] Something went wrong when parsing the XML file - perhaps it's corrupted/invalid?")
    print()
    sys.exit()

cpe_list=[]

for host in tree.getroot().findall("host"):
    script_port_infos = {}
    address = host.find("address").attrib["addr"]
    port_info = []
    ports = host.find("ports")
    infos={}
    ops = "Unknown"
    if host.find('os').find('osmatch') is not None:
       ops = ""
       temp=0
       for opsyst in host.find('os').findall('osmatch'):
            temp += 1
            if temp==5:
                 ops += opsyst.get('name') + "(" + opsyst.get('accuracy') + "%)\n"
                 break
            else:
                 ops += opsyst.get('name') + "(" + opsyst.get('accuracy') + "%)\n"
    if host.find('hostscript') is not None:
       for script in host.find("hostscript").findall('script'):
            title= "\n# "+script.get("id")+"\n"
            content= "## OUTPUT\n\n"
            content+=script.get("output")+"\n"
            content+="\n# RAW\n\n"
            content+=ET.tostring(script, encoding="unicode")+"\n"
            infos[title]=content
    if ports:
        for port in ports.findall("port"):
            script_infos={}
            for script in port.findall('script'):
                script_title= "\n\n# "+script.get("id")+"\n"
                script_content= "## OUTPUT\n\n"
                script_content+=str(script.get("output"))
                script_content+="\n\n## RAW\n\n"
                script_content+=ET.tostring(script, encoding="unicode")
                script_infos[script_title]=script_content
            script_port_infos[port.get('portid')] = script_infos
            cells = []

            for rc in row_cells:
                current_cell = rc
                for bc in re.findall("(\[[a-z\.*]+\])", rc):
                    for definition in definitions:
                        elem = definition.find(bc[1:-1])
                        if elem:
                            data=""
                            if elem.xpathfull()=="cpe":
                                service = port.find("service")
                                xml_element = service.find("cpe")
                                if xml_element is not None:
                                    data = xml_element.text
                                    if data not in cpe_list:
                                        cpe_list.append(data)
                            else:
                                xml_element = port.find(elem.xpathfull())
                                data = elem.data(xml_element)
                            if data is not None:
                                current_cell = current_cell.replace(bc, data)
                                break
                            break

                cells.append(current_cell)
            port_info.append(cells)
    scripts[address] = infos
    result[address] = port_info
    port_scripts[address] = script_port_infos
    hosts[address] = ops

# Start converting data to Markdown
# IP addresses are defined as a header
net_id=options.net_id
if os.path.isdir("/home/kali/Documents/notes/subnet_%s" % net_id) == True:
    print("subnet_%s already exists." % net_id)
else:
    print("subnet_%s created." % net_id)
    os.system("mkdir /home/kali/Documents/notes/subnet_%s" % net_id)
for address in result:
    md=""
    title=""
    if not options.print_empty and len(result[address]) == 0:
        continue
    if os.path.isdir("/home/kali/Documents/notes/subnet_%s/%s" % (net_id, address)) == True:
        print("%s already exists in subnet_%s." % (address, net_id))
    else:
        print("%s have been added in subnet_%s." % (address, net_id))
        os.system("mkdir /home/kali/Documents/notes/subnet_%s/%s" % (net_id, address))
    title += "%s %s\n\n" % ('# ' , address)
    md += "| %s |" % " | ".join(columns)
    md += "\n"

    # Adding +2 for 1 space on left and right sides
    md += "|%s|" % "|".join(map(lambda s: '-' * (len(s) + 2), columns))
    md += "\n"

    result[address] = sorted(
        result[address],
        key=lambda row: row[sorting_index],
        reverse=sorting_reverse
    )
    #os.system(" echo '"+scripts[address]+"' >> 'subnet_%s/%s/infos.md'" % (net_id,address))
    md_host=""
    md_host += "| %s |" % " | ".join(columns)
    md_host += "\n"
    md += "\n\n"
    # Adding +2 for 1 space on left and right sides
    md_host += "|%s|" % "|".join(map(lambda s: '-' * (len(s) + 2), columns))
    md_host += "\n"

    for port_info in result[address]:
        ver=""
        if port_info[3].strip()=="":
            ver="Unknown"
        else:
            ver=port_info[3].strip()
        #print("'/home/kali/Documents/notes/subnet_%s/%s/%s'" % (net_id,address,"_".join([port_info[0],port_info[2],ver]).replace("/","_").replace("*", "").replace(" ","-")))
        if os.path.isdir("/home/kali/Documents/notes/subnet_%s/%s/%s" % (net_id,address,"_".join([port_info[0],port_info[2],ver]).replace("/","_").replace("*", "").replace(" ","-").replace(";","").replace(")","").replace("(",""))) == True:
            print("Port %s already exists for %s in subnidentify_top_headerset_%s." % (port_info[0], address, net_id))
        else:
            print("Port %s created for %s in subnet_%s." % (port_info[0], address, net_id))
            os.system("mkdir '/home/kali/Documents/notes/subnet_%s/%s/%s'" % (net_id,address,"_".join([port_info[0],port_info[2],ver]).replace("/","_").replace("*", "").replace(" ","-").replace(";","").replace(")","").replace("(","")))
        #os.system(" echo '"+port_scripts[address][port_info[0].split("/")[0]]+"' > 'subnet_%s/%s/%s/infos.md'" % (net_id,address,"_".join(port_info).replace("/","_").replace("*", "").replace(" ","")[:-2]))
        try:
            if os.path.isfile("/home/kali/Documents/notes/subnet_%s/%s/infos.md" % (net_id,address)):
                text_file = open("/home/kali/Documents/notes/subnet_%s/%s/%s/infos.md" % (net_id,address,"_".join([port_info[0],port_info[2],ver]).replace("/","_").replace("*", "").replace(" ","-").replace(";","").replace(")","").replace("(","")), "a+")
                # Enumerate markdown titles
                text_file.seek(0)
                old_content = text_file.read()
                old_script_headers = identify_top_headers(remove_code_blocks(old_content.split("\n")))
                new_content=""
                new_scripts=port_scripts[address][port_info[0].split("/")[0]]
                for script, content in new_scripts.items():
                    if script.strip() not in old_script_headers:
                        new_content+=script+content
                text_file.write(new_content)
                text_file.close()
            else:
                text_file = open("/home/kali/Documents/notes/subnet_%s/%s/infos.md" % (net_id,address), "w")
                new_content=""
                new_scripts=port_scripts[address][port_info[0].split("/")[0]]
                for script, content in new_scripts.items():
                        new_content+=script+content
                text_file.write(new_content)
                text_file.close()
        except IOError as e:
            print(e)
        #print("subnet/%s/%s" % (address,"_".join(port_info).replace("/","_").replace("*", "")[:-2]))
        md_host += "| %s |" % " | ".join(port_info)
        md_host += "\n" 
        md += "| %s |" % " | ".join(port_info)
        md += "\n" 
    try:
        if os.path.isfile("/home/kali/Documents/notes/subnet_%s/%s/infos.md" % (net_id,address)):
            text_file = open("/home/kali/Documents/notes/subnet_%s/%s/infos.md" % (net_id,address), "a+")
            text_file.seek(0)
            old_content = text_file.read()
            old_script_headers = identify_top_headers(remove_code_blocks(old_content.split("\n")))
            new_content=""
            new_scripts=scripts[address]
            for script, content in new_scripts.items():
                if script.strip() not in old_script_headers:
                    new_content+=script+content
            text_file.write(new_content)
            text_file.close()
        else:
            text_file = open("/home/kali/Documents/notes/subnet_%s/%s/infos.md" % (net_id,address), "w")
            text_file.write("OS MATCH: "+hosts[address]+"\n")
            text_file.write(md_host)
            new_content=""
            new_scripts=scripts[address]
            for script, content in new_scripts.items():
                    new_content+=script+content
            text_file.write(new_content)       
            text_file.close()
    except IOError as e:
        print(e)
    md += "\n\n"
    overview[title]=md

#print(md)
if not os.path.isfile("/home/kali/Documents/notes/subnet_%s/overview.md" % net_id):
    text_file = open("/home/kali/Documents/notes/subnet_%s/overview.md" % net_id, "w")
    new_content=""
    for ip, content in overview.items():
            new_content+=ip+content
    text_file.write(new_content)
    text_file.close()
else:
    text_file = open("/home/kali/Documents/notes/subnet_%s/overview.md" % net_id, "a+")
    text_file.seek(0)
    old_content = text_file.read()
    old_overview_headers = identify_top_headers(remove_code_blocks(old_content.split("\n")))
    new_content=""
    for ip, content in overview.items():
        if ip.strip() not in old_overview_headers:
            new_content+=ip+content
    text_file.write(new_content)
    text_file.close()

if not os.path.isfile("/home/kali/Documents/notes/subnet_%s/cpe_list.md" % net_id):
    text_file = open("/home/kali/Documents/notes/subnet_%s/cpe_list.md" % net_id, "w")
    for cpe in cpe_list:
        n = text_file.write(cpe+"\n")
    text_file.close()
else:
    text_file = open("/home/kali/Documents/notes/subnet_%s/cpe_list.md" % net_id, "a+")
    text_file.seek(0)
    old_content = text_file.read()
    old_cpe = old_content.split("\n")
    new_content=""
    for cpe in cpe_list:
        if cpe not in old_cpe:
            new_content+=cpe+"\n"
    text_file.write(new_content)
    text_file.close()
