import ipaddress
addr4 = ipaddress.ip_address('192.0.2.1')
t=addr4 in ipaddress.ip_interface('192.0.2.0')

print(t)