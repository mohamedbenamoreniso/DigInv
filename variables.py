import ipaddress
from ciscoconfparse import CiscoConfParse
import sys,os


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
#list that contain all audits found in the global security audit
global_list_sec_audit=list()
#list that contain all audits found in the interface audit
intf_list_sec_audit = list()
#IP classes
classA = ipaddress.IPv4Network(("10.0.0.0", "255.0.0.0"))  
classB = ipaddress.IPv4Network(("172.16.0.0", "255.240.0.0")) 
classC = ipaddress.IPv4Network(("192.168.0.0", "255.255.0.0")) 

try:
    file = str(sys.argv[1])
    
except:
    
    print("please enter a name file as an argument")

file_size = os.stat(file).st_size
if(file_size==0):
        print("the file is empty !!")
        sys.exit()
        
parse = CiscoConfParse(file)
