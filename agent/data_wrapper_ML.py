#!/usr/bin/env python
#TODO execute functions depending on dns.rcode.to_text(rcode) SERVFAIL --> requires to set NS fix for domain
#  dnssecZoneGlobalServFail Indicates if a recurser/resolver can get NS record data of zone
import sys
import dns.query
import dns.zone
import dns.rdatatype
import dns.resolver
import dns.name
import dns.message
import Crypto
import re
import xml.etree.cElementTree as ET

global domains
global nameserver
global xmlfeed
global zone_hint_file
global xml_file

xmlfeed={}
domains = {}
zone_hint_file="/opt/agent/zone_hint"
xml_file = "/opt/agent/updated.xml"

def get_zone_hint(zone_hint_file):
   with open(zone_hint_file) as f:
    	for line in f:
       		(zone_name, ns_ip) = line.split()
       		domains[str(zone_name)] = ns_ip
   return domains



def get_authoritative_nameserver_data():
   global nameserver
   n = dns.name.from_text(domain)

   default = dns.resolver.get_default_resolver()
   nameserver = default.nameservers[0]

   #log('Looking up %s on %s' % (domain, nameserver))
   query = dns.message.make_query(domain, dns.rdatatype.NS)
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
	return nameserver,authority,domain
   else:
	return error_code

def log(msg):
    print msg

def get_ns_name():
    nameserver = domains[domain]
    request_ns = dns.message.make_query(domain,
                                 dns.rdatatype.NS)

    response_ns = dns.query.udp(request_ns,nameserver)
    raw = str(response_ns.answer[0])
    ns_name = re.split('\s+', raw)


    return ns_name[4]


#def get_all_authoritative_nameservers():
#    answers = dns.resolver.query(domain, 'NS')
#    ns = []
#    for rdata in answers:
#    	n = str(rdata)
#    	ns.append(n)
#    return ns,len(ns)

def get_all_authoritative_nameservers():
    request_ns = dns.message.make_query(domain,
                                 dns.rdatatype.NS)

    response_ns = dns.query.udp(request_ns,nameserver)
    ns = []

    for rdata in response_ns.answer:
        ns_name = re.split('\s+',str(rdata))
        ns_data = ' '.join(ns_name)
        ns = re.findall(r"(?<=NS\s)(\b[A-Za-z0-9.-_]*\b)", ns_data)

    return ns, len(ns)




def get_zone_xfr(domain,nameserver):
    global zone
    zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
    names = zone.nodes.keys()
    names.sort()

    for rr in names:
        raw = zone[rr].to_text(rr)
        lines = raw.split('\n')
    	return raw

def get_origin_recordcount():
        # TODO: Implement in a way, that only one XFR is required
        zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
        names = zone.nodes.keys()
        names.sort()

        totalrecordsets = 0
        totalrecords = 0
        for rr in names:
                totalrecordsets += len(rr)
                raw = zone[rr].to_text(rr)
                lines = raw.split('\n')
                totalrecords += len(lines)

	global totaldelegations
        totaldelegations = 0
        for (name, rdataset) in zone.iterate_rdatasets(dns.rdatatype.NS):
                if name != dns.name.empty:
                        totaldelegations += len(rdataset)
	return zone.origin, totalrecords, totalrecordsets, totaldelegations


def get_origin_dsmatch():
        # TODO: Implement in a way, that only one XFR is required
        zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
        names = zone.nodes.keys()
        names.sort()

        totalds = 0
        for (dsname, rdataset) in zone.iterate_rdatasets(dns.rdatatype.DS):
                if dsname != dns.name.empty:
                        totalds += len(rdataset)

        if int(totalds) == int(totaldelegations):
                ds_present_match = 1
        else:
                ds_present_match = 2

        return ds_present_match



def validate_dnskey():
    ret_val = 3
    request = dns.message.make_query(domain,
                                 dns.rdatatype.DNSKEY,
                                 want_dnssec=True)

    response = dns.query.udp(request,nameserver)

    if response.rcode() != 0:
	ret_val = 3
	return ret_val

    answer = response.answer
    name = dns.name.from_text(domain)

    try:
    	dns.dnssec.validate(answer[0],answer[1],{name:answer[0]})
	#print dns.dnssec.validate(answer[0],answer[1],{name:answer[0]})
    except dns.dnssec.ValidationFailure:
    	pass
    else:
    # valid DNSSEC selfsigned DNSKEY for domain
	ret_val = 1
	return ret_val

def get_soa():
    request = dns.message.make_query(domain,
                                 dns.rdatatype.SOA)

    response = dns.query.udp(request,nameserver)
    soa = str(response.answer[0])
    soa_parts = soa.split()
    return response.answer[0],soa_parts[1]

def minimum_ttl():
	data=get_zone_xfr(domain,nameserver)
	#print data
	minimum_ttl=re.findall(r'.*IN.*',data)
	#print minimum_ttl
	minimum_ttl_list = []
	for values in minimum_ttl:
		
		values_list=values.split()
		
		if int(values_list[1]) == 0:
			continue
		else:
                	minimum_ttl_list.append(int(values_list[1]))
	#print minimum_ttl_list
	#print min(minimum_ttl_list)
	#print max(minimum_ttl_list)	

	return min(minimum_ttl_list), max(minimum_ttl_list)


# Update XML template with retrived values
def editXML(xml_file):  
        global xmlfeed
        tree = ET.ElementTree(file=xml_file)
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
                                for k in xmlfeed:
                                        tmp = k.split('_')
                                        if str(tmp[0]) == str(zones['name']) and str(tmp[1]) == str(tables['name']) and int(tmp[2]) == int(data.attrib['id']): 
                                                data.text = xmlfeed[k]
                                                tree = ET.ElementTree(root)
                                                with open(xml_file, "w") as f:
                                                        tree.write(f)


def main(domains):
	global domain
	domains = get_zone_hint(zone_hint_file)
	for domain in sorted(domains.iterkeys()):
		
		print "\n##############" ,domain   

		get_auth_data = get_authoritative_nameserver_data()

		if get_auth_data == "SERVFAIL":
			servfail=2
			global nameserver			
			nameserver = domains[domain]					
			#global nameserver
			#get_auth_data = get_authoritative_nameserver_data()
			#log('%s is authoritative for %s' % (authority, domain))
			# TODO dnssecZoneGlobalAuthNSAddress -->  _dnssecZoneGlobalTable_10 (IpAddress)
			#IMPLEMENT!
			log('dnssecZoneGlobalAuthNSAddress in _dnssecZoneGlobalTable_10 is %s' % (nameserver))
			xmlfeed[str(domain + "_dnssecZoneGlobalTable_10")] = '"' + str(nameserver) + '"'

			# TODO dnssecZoneGlobalAuthNSName --> _dnssecZoneGlobalTable_11	(OctetString)
			#IMPLEMENT!
			nameserver_name = get_ns_name()
			log('dnssecZoneGlobalAuthNSName in _dnssecZoneGlobalTable_11 is %s' % (nameserver_name))
                	xmlfeed[str(domain + "_dnssecZoneGlobalTable_11")] = '"' + str(nameserver_name) + '"'

		else:
			servfail=1
			
                	#log('%s is authoritative for %s' % (authority, domain))
                	# TODO dnssecZoneGlobalAuthNSAddress -->  _dnssecZoneGlobalTable_10 (IpAddress)
                	#IMPLEMENT!
                	log('dnssecZoneGlobalAuthNSAddress in _dnssecZoneGlobalTable_10 is %s' % (get_auth_data[0]))
                	xmlfeed[str(domain + "_dnssecZoneGlobalTable_10")] = '"' + str(get_auth_data[0]) + '"'

                	# TODO dnssecZoneGlobalAuthNSName --> _dnssecZoneGlobalTable_10 (OctetString)
                	#IMPLEMENT!
                	log('dnssecZoneGlobalAuthNSName in _dnssecZoneGlobalTable_11 is %s' % (get_auth_data[1]))
                	xmlfeed[str(domain + "_dnssecZoneGlobalTable_11")] = '"' + str(get_auth_data[1]) + '"'

		#  dnssecZoneGlobalServFail --> _dnssecZoneGlobalTable_2 (Integer32)
		log('dnssecZoneGlobalServFail in _dnssecZoneGlobalTable_2 is %s' % (servfail))
                xmlfeed[str(domain + "_dnssecZoneGlobalTable_2")] = str(servfail)

		get_all_authserver = get_all_authoritative_nameservers()
		nameserverlist = ' '.join(get_all_authserver[0])
		#  dnssecZoneAuthNSName -->  _ dnssecZoneAuthNSTable_2 (OctetString)
                log('dnssecZoneAuthNSName in _dnssecZoneAuthNSTable_2 is %s' % (nameserverlist))
                xmlfeed[str(domain + "_dnssecZoneAuthNSTable_2")] = '"' + str(nameserverlist) + '"'
		#  dnssecZoneGlobalAuthNSCount -->  _dnssecZoneGlobalTable_9 (Integer32)
                log('dnssecZoneGlobalAuthNSCount in _dnssecZoneGlobalTable_9 is %s' % (get_all_authserver[1]))
                xmlfeed[str(domain + "_dnssecZoneGlobalTable_9")] = str(get_all_authserver[1]) 


		get_soa_data = get_soa()
                # dnssecZoneGlobalSOA -->  _dnssecZoneGlobalTable_15 (DisplayString)
                log('dnssecZoneGlobalSOA in _dnssecZoneGlobalTable_15 is %s' % (get_soa_data[0]))
		xmlfeed[str(domain + "_dnssecZoneGlobalTable_15")] = '"' + str(get_soa_data[0]) + '"'
		# dnssecZoneGlobalSOATTL -->  _dnssecZoneGlobalTable_14 (Integer32)
                log('dnssecZoneGlobalSOATTL in _dnssecZoneGlobalTable_14 is %s' % (get_soa_data[1]))
                xmlfeed[str(domain + "_dnssecZoneGlobalTable_14")] = str(get_soa_data[1])
		
		validate_dnskey_data = validate_dnskey()
		
		if validate_dnskey_data == None:
			result = 2

			# dnssecZoneGlobalDNSKEYSignatureVerification -->  _dnssecZoneGlobalTable_8 (Integer32)
                	log('dnssecZoneGlobalDNSKEYSignatureVerification in _dnssecZoneGlobalTable_8 is %s' % (result))
                	xmlfeed[str(domain + "_dnssecZoneGlobalTable_8")] = str(result)
		else: 
			# dnssecZoneGlobalDNSKEYSignatureVerification -->  _dnssecZoneGlobalTable_8 (Integer32)
                        log('dnssecZoneGlobalDNSKEYSignatureVerification in _dnssecZoneGlobalTable_8 is %s' % (validate_dnskey_data))
                        xmlfeed[str(domain + "_dnssecZoneGlobalTable_8")] = str(validate_dnskey_data)

		

		minimum_ttl_data = minimum_ttl()
		# TODO dnssecZoneGlobalMinimumTTL -->  _dnssecZoneGlobalTable_12 (Integer32)
                log('dnssecZoneGlobalMinimumTTL in _dnssecZoneGlobalTable_12 is %s' % (minimum_ttl_data[0]))
                xmlfeed[str(domain + "_dnssecZoneGlobalTable_12")] = str(minimum_ttl_data[0])
		# TODO dnssecZoneGlobalMaximumTTL -->  _dnssecZoneGlobalTable_13 (Integer32)
                log('dnssecZoneGlobalMaximumTTL in _dnssecZoneGlobalTable_13 is %s' % (minimum_ttl_data[1]))
                xmlfeed[str(domain + "_dnssecZoneGlobalTable_13")] = str(minimum_ttl_data[1])

		get_origin_recordcount_data = get_origin_recordcount()
		#return zone.origin, totalrecords, totalrecordsets, totaldelegations
		#  dnssecZoneGlobalOrigin -->  _dnssecZoneGlobalTable_3 (OctetString)
                log('dnssecZoneGlobalOrigin in _dnssecZoneGlobalTable_3 is %s' % (get_origin_recordcount_data[0]))
                xmlfeed[str(domain + "_dnssecZoneGlobalTable_3")] = '"' + str(get_origin_recordcount_data[0]) + '"'
		#   dnssecZoneGlobalRecordCount -->  _dnssecZoneGlobalTable_4 (Integer32)
                log('dnssecZoneGlobalRecordCount in _dnssecZoneGlobalTable_4 is %s' % (get_origin_recordcount_data[1]))
                xmlfeed[str(domain + "_dnssecZoneGlobalTable_4")] = str(get_origin_recordcount_data[1]) 
		#   dnssecZoneGlobalRecordSetCount -->  _dnssecZoneGlobalTable_5 (Integer32)
                log('dnssecZoneGlobalUniqueNameCount in _dnssecZoneGlobalTable_5 is %s' % (get_origin_recordcount_data[2]))
                xmlfeed[str(domain + "_dnssecZoneGlobalTable_5")] = str(get_origin_recordcount_data[2])
		#   dnssecZoneGlobalDelegationCount -->  _dnssecZoneGlobalTable_6 (Integer32)
                log('dnssecZoneGlobalDelegationCount in _dnssecZoneGlobalTable_6 is %s' % (get_origin_recordcount_data[3]))
                xmlfeed[str(domain + "_dnssecZoneGlobalTable_6")] = str(get_origin_recordcount_data[3])

		get_data_origin_dsmatch = get_origin_dsmatch()
		#    dnssecZoneGlobalDSpresent -->  _dnssecZoneGlobalTable_7 (Integer32)
                log('dnssecZoneGlobalDSpresent in _dnssecZoneGlobalTable_7 is %s' % (get_data_origin_dsmatch))
                xmlfeed[str(domain + "_dnssecZoneGlobalTable_7")] = str(get_data_origin_dsmatch)


		editXML(xml_file)

#stub to launch main
if __name__ == '__main__':
    main(domains)
