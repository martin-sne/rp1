#!/usr/bin/env python
# Inspiration http://eli.thegreenplace.net/2012/03/15/processing-xml-in-python-with-elementtree

import xml.etree.cElementTree as ET
tree = ET.ElementTree(file='data.xml')
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
			print tables['name'] + "Row" + zones['id'] + '.setRowCell(' + data.attrib['id'] + ', agent.' + data.attrib['type'] + '(' + data.text + '))'
			print "New"
