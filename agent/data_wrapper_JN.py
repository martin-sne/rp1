#!/usr/bin/env python
import dns.resolver
import dns.zone
from xml.etree import ElementTree
from xml.etree.ElementTree import Element, SubElement, tostring, XML
from xml.dom import minidom
import xml.etree.cElementTree as ET
import re
import socket
import os


#ML added
global zone_hint_file
zone_hint_file="/opt/agent/zone_hint"
global domains
domains = {}
global xml_filename
global xml_updated_filename
xml_filename="/opt/agent/data.xml"
xml_updated_filename="/opt/agent/updated.xml"

# Creation of XML file
xml_file = open(xml_filename, "w")

#ML deleted
# Zones declaration
#zone = ["warsaw.practicum.os3.nl", "derby.practicum.os3.nl", "berlin.warsaw.practicum.os3.nl", "paris.derby.practicum.os3.nl"]


# ML deleted
# Hardcoded zones and IPs in case of SERVFAIL
#domains = { 'warsaw.practicum.os3.nl' : '145.100.104.62',
#            'paris.derby.practicum.os3.nl' : '145.100.104.62',
#            'derby.practicum.os3.nl' : '145.100.104.165',
#            'berlin.warsaw.practicum.os3.nl':'145.100.104.165'}


#ML created
def get_zone_hint(zone_hint_file):
   with open(zone_hint_file) as f:
        for line in f:
                (zone_name, ns_ip) = line.split()
                domains[str(zone_name)] = ns_ip
   return domains

domains = get_zone_hint(zone_hint_file) 

# Create top of document
top = Element('ZoneList')


# Format the XML document into a readable one
def format_xml(doc):
	# convert the document to a string
	doc_to_string = ElementTree.tostring(doc, 'utf-8')
	# format this string into a readable document
	reformatted = minidom.parseString(doc_to_string)
	return reformatted.toprettyxml(indent="  ")



# Create zones
created_zones = []
i=0

def create_zone(zone_name):
        global i
        i = i + 1
        new_zone = SubElement(top, 'Zone', name=zone_name, id=str(i))
        created_zones.append(new_zone)

#ML added
for zones in sorted(domains.iterkeys()):
        create_zone(zones)


# Create tables
for zones in created_zones:
        table1 = SubElement(zones, 'table', name='dnssecZoneGlobalTable')
        table2 = SubElement(zones, 'table', name='dnssecZoneAuthNSTable')
        table3 = SubElement(zones, 'table', name='dnssecZoneSigTable')
        table4 = SubElement(zones, 'table', name='dnssecZoneDiffTable')

        # Create items for table1
        table1_item1 = SubElement(table1, 'item')
        table1_item1a = SubElement(table1_item1, 'data',  id='2', name='dnssecZoneGlobalServFail', type='Integer32')
        table1_item2 = SubElement(table1, 'item')
        table1_item2a = SubElement(table1_item2, 'data',  id='3', name='dnssecZoneGlobalOrigin', type='OctetString')
        table1_item3 = SubElement(table1, 'item')
        table1_item3a = SubElement(table1_item3, 'data',  id='4', name='dnssecZoneGlobalRecordCount', type='Unsigned32')
        table1_item4 = SubElement(table1, 'item')
        table1_item4a = SubElement(table1_item4, 'data',  id='5', name='dnssecZoneGlobalUniqueNameCount', type='Unsigned32')
        table1_item5 = SubElement(table1, 'item')
        table1_item5a = SubElement(table1_item5, 'data',  id='6', name='dnssecZoneGlobalDelegationCount', type='Unsigned32')
        table1_item6 = SubElement(table1, 'item')
        table1_item6a = SubElement(table1_item6, 'data',  id='7', name='dnssecZoneGlobalDSpresent', type='Integer32')
        table1_item7 = SubElement(table1, 'item')
	table1_item7a = SubElement(table1_item7, 'data',  id='8', name='dnssecZoneGlobalDNSKEYSignatureVerification', type='Integer32')
	table1_item8 = SubElement(table1, 'item')
	table1_item8a = SubElement(table1_item8, 'data',  id='9', name='dnssecZoneGlobalAuthNSCount', type='Unsigned32')
	table1_item9 = SubElement(table1, 'item')
        table1_item9a = SubElement(table1_item9, 'data',  id='10', name='dnssecZoneGlobalAuthNSAddress', type='DisplayString')
        table1_item10 = SubElement(table1, 'item')
        table1_item10a = SubElement(table1_item10, 'data',  id='11', name='dnssecZoneGlobalAuthNSName', type='OctetString')
	table1_item11 = SubElement(table1, 'item')
        table1_item11a = SubElement(table1_item11, 'data',  id='12', name='dnssecZoneGlobalMinimumTTL', type='Integer32')
	table1_item12 = SubElement(table1, 'item')
        table1_item12a = SubElement(table1_item12, 'data',  id='13', name='dnssecZoneGlobalMaximumTTL', type='Integer32')
	table1_item13 = SubElement(table1, 'item')
        table1_item13a = SubElement(table1_item13, 'data',  id='14', name='dnssecZoneGlobalSOATTL', type='Integer32')
	table1_item14 = SubElement(table1, 'item')
        table1_item14a = SubElement(table1_item14, 'data',  id='15', name='dnssecZoneGlobalSOA', type='DisplayString')



        # Create items for table2
        table2_item1 = SubElement(table2, 'item')
        table2_item1a = SubElement(table2_item1, 'data',  id='2', name='dnssecZoneAuthNSName', type='OctetString')

        # Create items for table3
        table3_item1 = SubElement(table3, 'item')
        table3_item1a= SubElement(table3_item1, 'data',  id='2', name='dnssecZoneSigOldestSignatureTime', type='DisplayString')
        table3_item2 = SubElement(table3, 'item')
        table3_item2a= SubElement(table3_item2, 'data',  id='3', name='dnssecZoneSigSOASignatureExpirationTime', type='DisplayString')
        table3_item3 = SubElement(table3, 'item')
        table3_item3a= SubElement(table3_item3, 'data',  id='4', name='dnssecZoneSigNSSignatureExpirationTime', type='DisplayString')
        table3_item4 = SubElement(table3, 'item')
        table3_item4a= SubElement(table3_item4, 'data',  id='5', name='dnssecZoneSigDNSKEYSignatureExpirationTime', type='DisplayString')

        # Create items for table4
        table4_item1 = SubElement(table4, 'item')
        table4_item1a = SubElement(table4_item1, 'data',  id='2', name='dnssecZoneDiffSerial', type='Integer32')

	# Closing tags by adding empty values
	table1_item1a.text = ' '
	table1_item2a.text = ' '
	table1_item3a.text = ' '
	table1_item4a.text = ' '
	table1_item5a.text = ' '
	table1_item6a.text = ' '
	table1_item7a.text = ' '
	table1_item8a.text = ' '
	table1_item9a.text = ' '
	table1_item10a.text = ' '
	table1_item11a.text = ' '
	table1_item12a.text = ' '
	table1_item13a.text = ' '
	table1_item14a.text = ' '	
	table2_item1a.text = ' '
	table3_item1a.text = ' '
	table3_item2a.text = ' '
	table3_item3a.text = ' '
	table3_item4a.text = ' '
	table4_item1a.text = ' '


# Write the XML template to file data.xml	
xml_file.write(format_xml(top))
xml_file.close()


# Finding the name server IP of the zone (copyright)
def get_authoritative_nameserver_data(zone): 
	n = dns.name.from_text(zone)
	default = dns.resolver.get_default_resolver()
   	nameserver = default.nameservers[0]

   #log('Looking up %s on %s' % (domain, nameserver))
   	query = dns.message.make_query(zone, dns.rdatatype.NS)
   	response = dns.query.udp(query, nameserver)
   	rcode = response.rcode()
   	error_code = "None"
   	if rcode != dns.rcode.NOERROR:
        	if rcode == dns.rcode.NXDOMAIN:
                	#raise Exception('%s does not exist.' % sub)
                	error_code = dns.rcode.to_text(rcode)
        	else:
                	#raise Exception('Error %s' % dns.rcode.to_text(rcode))
                	error_code = dns.rcode.to_text(rcode)

	if error_code == "None":
        	rrset = None
        	if len(response.authority) > 0:
                	rrset = response.authority[0]
        	else:
                	rrset = response.answer[0]

        	rr = rrset[0]
		authority = rr.target
        #log('%s is authoritative for %s' % (authority, domain))
        	nameserver = default.query(authority).rrset[0].to_text()
        	return nameserver
   	else:
        	return error_code




# Retrieve fresh data from XFR
def get_data(zone):
	get_auth_data = get_authoritative_nameserver_data(zone)
        if get_auth_data == "SERVFAIL":
                nameserver = domains[zones]
        else:
                nameserver = get_auth_data

	z = dns.zone.from_xfr(dns.query.xfr(nameserver, zone))
        names = z.nodes.keys()
        names.sort()
        for n in names:
                return z[n].to_text(n)


# Retrieve the oldest signature of a zone
def oldest_sig(zones):
        data = get_data(zones)
        oldest_rrsig = re.findall(r'RRSIG \w* [0-9] [0-9] [0-9]+ [0-9]+ [0-9]+',data)
        dates_rrsig = []
        for values in oldest_rrsig:
                values_list = values.split()
                dates_rrsig.append(values_list[6])
		return str(min(dates_rrsig))

# Retrieve the expiration date of the SOA record signature of a zone
def soa_sig_exp(zones):
        data=get_data(zones)
        soa_sig=re.findall(r'RRSIG SOA [0-9] [0-9] [0-9]+ [0-9]+',data)
        for values in soa_sig:
                values_list=values.split()
                return(values_list[5])

# Retrieve the expiration date of NS record signature of a zone
def ns_sig_exp(zones):
        data=get_data(zones)
        ns_sig=re.findall(r'RRSIG NS [0-9] [0-9] [0-9]+ [0-9]+',data)
        dates_ns = []
	for values in ns_sig:
                values_list=values.split()
                dates_ns.append(values_list[5])
	ns = ' '.join(dates_ns)
	return ns

# Retrieve the expiration date of DNSKEY signature of a zone
def dnskey_sig_exp(zones):
        data=get_data(zones)
        dnskey_sig=re.findall(r'RRSIG DNSKEY [0-9] [0-9] [0-9]+ [0-9]+',data)
        dates_dnskey = []
        for values in dnskey_sig:
                values_list=values.split()
                dates_dnskey.append(values_list[5])
	rrsig = ' '.join(dates_dnskey)
	return rrsig


# Check if serials are the same between slave and master
def diff_serial(zones):
        data=get_data(zones)
        serial_master=re.findall(r'SOA @ .+ [0-9]+',data)
        for values in serial_master:
                values_list=values.split()
                serial_master=values_list[3]	
        # Looking for the slave
        slave=re.findall(r'NS .+\.',data)
        for values in slave:
                values_list=values.split()
                slave=values_list

        # Getting the IP from the slave
        ipslave=socket.gethostbyname(slave[1])

        # Querying the zone from the slave IP
        z = dns.zone.from_xfr(dns.query.xfr(ipslave, zones))
        names = z.nodes.keys()
        names.sort()
        for n in names:
                slave_zone=z[n].to_text(n)
	        serial_slave = re.findall(r'SOA @ .+ [0-9]+', slave_zone)
                # Retrieving the serial from the slave
                for values in serial_slave:
                        values_list=values.split()
                        serial_slave=values_list[3]
                # Comparing slave and master serial
                        if serial_slave !=  serial_master:
                                return str(2)
                        elif serial_slave == serial_master:
                                return str(1)
                        else:
                                return str(3)



# Initialize the dictionary
values = {}

# Construct dictionary
# ML added
for zones in sorted(domains.iterkeys()):
        values[str(zones + "_dnssecZoneSigTable_2")] = str('"' + oldest_sig(zones) + '"')
        values[str(zones + "_dnssecZoneSigTable_3")] = str('"' + soa_sig_exp(zones) + '"')
        values[str(zones + "_dnssecZoneSigTable_4")] = str('"' + ns_sig_exp(zones) + '"')
        values[str(zones + "_dnssecZoneSigTable_5")] = str('"' + dnskey_sig_exp(zones) + '"')
        values[str(zones + "_dnssecZoneDiffTable_2")] = diff_serial(zones)



# Defining the filename variable


# Update XML template with retrived values
def editXML(xml_filename):
	
	global values
	tree = ET.ElementTree(file=xml_filename)
	root = tree.getroot()

	# get all zones
	for child_of_root in root:
        	zones = child_of_root.attrib

        	# build path for xpath query
        	# Example: 'Zone[@name="os3.nl"]/table'
        	path = "Zone[@name=\"" + zones['name'] + "\"]/table" 
        	# get all tables 
        	for table in tree.iterfind(path):
                	tables=table.attrib

                	# build path for xpath query 
                	# Example: 'Zone[@name="os3.nl"]/table[@name="dnssecGlobalZoneTable"]/item/data' 
                	path2= "Zone[@name=\"" + zones['name'] + "\"]/table[@name=\"" + tables['name'] + "\"]/item/data"

                	# finally get the data for each table 
                	# and corresponding table entries 
                	for data in tree.iterfind(path2):
                        	#print data.tag, data.attrib, data.text, zones['id'], zones['name'], tables['name']
                        	##dnssecGlobalTableRow1.setRowCell(8, agent.Unsigned32(datadnssecglobaltable["dnssecGlobalZoneAuthNsCount"]))
                        	# dnssecZoneAuthNsTableRow2.setRowCell(2, agent.DisplayString("ns1.distributed-systems.net"))
				for k in values:
					#print k	
					tmp = k.split('_')
					#print "######TESTID", data.attrib['id']
					if str(tmp[0]) == str(zones['name']) and str(tmp[1]) == str(tables['name']) and int(tmp[2]) == int(data.attrib['id']): 
					#and str(tmp[1]) == str(tables['name']) and  int(tmp[2]) == int(data['id']):
						data.text = values[k]
						tree = ET.ElementTree(root)
    	 					with open(xml_updated_filename, "w") as f:
        						tree.write(f)

editXML(xml_filename)
