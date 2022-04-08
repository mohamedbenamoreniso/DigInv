##############interface auditing##################
from variables import *
from func import *
from settings import *


#audit port-security 
for obj in parse.find_objects(r"interface"):
    intf_no_filter=obj.has_child_with(r"ip\saccess-group")
    
    
    obj_list=list()
    for child in obj.children:
        obj_list.append(str(child.text))
    #make the children of interface as string   
    obj_list= ''.join(map(str,obj_list))
    if("no shutdown" in obj_list):
        #port security
        if ("switchport port-security" not in obj_list):
            intf_audit.append(4)
#audit STP
glob_bpduguard= parse.has_line_with(r"spanning-tree portfast bpduguard default")
glob_bpdufilter=parse.has_line_with(r"spanning-tree portfast bpdufilter default")


    