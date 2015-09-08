#!/usr/bin/env python

import xml.etree.cElementTree as ET
tree = ET.ElementTree(file='data5.txt')
root = tree.getroot()
zones = {}

# get all zones
for child_of_root in root:
	#print child_of_root.tag, child_of_root.attrib
	zones = child_of_root.attrib
	print zones['name']
	print zones['id']	
# get all tables

for elem in tree.iterfind('Zone[@name="os3.nl"]/table'):
		print elem.tag, elem.attrib

# get all data with Zone name="os3.nl" and inside table dnssecGlobalZoneTable
for elem in tree.iterfind('Zone[@name="os3.nl"]/table[@name="dnssecGlobalZoneTable"]/item/data'):
	print elem.tag, elem.attrib, elem.text


