import ipaddress
from ciscoconfparse import CiscoConfParse
import sys,os
from dominate.tags import *


#list that contain the IDs of the global audit
glob_list=list()

#list that contain the IDs of the global audit
intf_audit=list()

#dict that contain key the ID of the weakness and the value is a raw table (glob audit)
glob_table_dict={}

#dict that contain key the ID of the weakness and the value is a raw table (interface audit)
intf_table_dict={}

#number of CRITICAL rating
CRITICAL_RATING=0

#number of HIGH rating
HIGH_RATING=0

#number of MEDUIM rating
MEDUIM_RATING=0

#number of LOW rating
LOW_RATING=0

#number of INFORMATIONAL rating
INFORMATIONAL_RATING=0

#div for interface audit to put data in (report section)
d_intfaudit=div(_class="interfaceaudit")

#div for global audit to put data in (report section)
d_globaudit=div(_class="globaudit")

#div for device configuration to put data in (report section)
d_vulnerability=div(_class="vulnerability")

#div for device configuration to put data in (report section)
d_device_conf=div(_class="device_conf")

#list that contain all audits found in the global security audit
global_list_sec_audit=list()

#list that contain all audits found in the interface audit
intf_list_sec_audit = list()

#IP classes
classA = ipaddress.IPv4Network(("10.0.0.0", "255.0.0.0"))  
classB = ipaddress.IPv4Network(("172.16.0.0", "255.240.0.0")) 
classC = ipaddress.IPv4Network(("192.168.0.0", "255.255.0.0")) 

import argparse

parser=argparse.ArgumentParser()
parser.add_argument('--device',type=str,required=True,)
parser.add_argument('--file',type=str,required=True)

args=parser.parse_args()

try:
        device_type=args.device
        file_name=args.file

except :
        print("please check your arguments")
        sys.exit(0)
try:
    file_size = os.stat(file_name).st_size
    if(file_size==0):
            print("the file is empty !!")
            sys.exit()
except:
    print("the file name <<"+file_name +">> don't exists here")
    sys.exit(0)
        
parse = CiscoConfParse(file_name)
