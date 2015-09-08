#!/usr/bin/python -u
import snmp_passpersist as snmp

def update():
	pp.add_int('3.0',123)

pp=snmp.PassPersist(".1.3.6.1.2.1.74.1.30187.1.1")
pp.start(update,10) # Every 30s

