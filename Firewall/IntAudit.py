##############interface auditing##################

from variables import *
from func import *
from settings import *
from collections import defaultdict
from dominate.util import raw
#this list will contain the data to make a table every time we call the method build_table
data=defaultdict(list)



#convert string data to table data
def convert_str_table(id,column):
    
    
    intf_table_dict[id]=raw(build_table(data[id],column))
#Routing Protocols audit
networks_rp=list()
interfaces_networks_rp=list()
auth_keys=list()
    
#ospf Audit
#find interfaces that have ospf configured

HELPER_REGEX=r'network\s(\d+\.\d+\.\d+\.\d+\s\d+\.\d+\.\d+\.\d+)'

for ospf_obj in parse.find_objects(r'^router\sospf'):
    
    lsa=ospf_obj.has_child_with(r'max-lsa')
    if(lsa==False):
        intf_audit.append(31)
        


    for child_obj in ospf_obj.children:  # Iterate over OSPF children

        network_ospf = child_obj.re_match_typed(HELPER_REGEX, default=NO_MATCH)

        if network_ospf!=NO_MATCH:
            
            
            try:
                net=network_ospf.split()
                network=net[0]+"/"+net[1]
            except:
                pass

try:
    interfaces_networks_rp=list(set(get_interfaces_firewall(parse,network)))

    data=defaultdict(list)
    #Iterate over ospf interfaces
    for intf in interfaces_networks_rp:

        
        md5_auth=intf.has_child_with(r'ospf\sauthentication\smessage-digest')
        no_auth=intf.has_child_with(r'ospf\sauthentication\snull')
        for intf_child in intf.children:
            priority=intf_child.re_match_typed(r'ospf\spriority\s(\d+)',default=NO_MATCH)
            if(priority!=NO_MATCH):
                if(int(priority)<255):
                    intf_audit.append(28)
                    obj_data=[]
                    obj_data.extend((re.findall(r"interface\s(\S+)",str(intf.text))[0],priority))
                    data[28].append(obj_data)
        
        

        if(md5_auth==False or no_auth==True):
            intf_audit.append(5)

            
    data=dict(data)
    try:
        convert_str_table(28,["Interface","OSPF Priority"])     
    except:
        pass

    networks_rp.clear()
    interfaces_networks_rp.clear()
except:
    pass
#EIGRP Audit
for eigrp_obj in parse.find_objects(r'^router\seigrp'):
    
    for child_obj in eigrp_obj.children:  # Iterate over EIGRP children

        network_eigrp = child_obj.re_match_typed(HELPER_REGEX, default=NO_MATCH)

        if network_eigrp!=NO_MATCH:
            
            net=network_eigrp.split()

            try:
                net=network_ospf.split()
                network=net[0]+"/"+net[1]
            except:
                pass

try:
    interfaces_networks_rp=list(set(get_interfaces_firewall(parse,network)))

    for intf in interfaces_networks_rp:
    
            
        md5_auth=intf.has_child_with(r"authentication\smode\seigrp\s\d+\smd5")
        if(md5_auth==False):
            intf_audit.append(12)   

except:
    pass
        

#BGP Audit
i=j=0
for obj in  parse.find_objects(r'^router bgp'):
    bgp_damp=obj.has_child_with(r"bgp dampening")
    if(bgp_damp==False):
        intf_audit.append(29)
        

    for bgp in obj.children:
        neighbor=bgp.re_match_typed(r'neighbor\s(\d+\.\d+\.\d+\.\d+)\sremote-as',default=NO_MATCH)
        neighbor_AUTH=bgp.re_match_typed(r'neighbor\s\d+\.\d+\.\d+\.\d+\spassword\s(\w+)',default=NO_MATCH)
        
        if(neighbor!=NO_MATCH): i=i+1
        if (neighbor_AUTH!=NO_MATCH):  j=j+1
           
if(i+j!=0 and i%j!=0): intf_audit.append(1)
#RIP Audit
#under router

rip_int=True
for obj in parse.find_objects(r'^router\srip'):

    if not (obj.has_child_with(r'neighbor')):
        intf_audit.append(30)

    if(obj.has_child_with(r"version\s1") or not obj.has_child_with(r"version\s2")):

        intf_audit.append(6)
        rip_int=False
    networks_rip=list()
    for obj_child in obj.children:
        network=obj_child.re_match_typed(r'network\s(\d+\.\d+\.\d+\.\d+)',default=NO_MATCH)
       
        
        if(network!=NO_MATCH):
            network=ipaddress.ip_address(network)
            if network in classA:
                netmask="/8"
            elif network in classB:
                netmask="/16"
            elif network in classC:
                netmask="/24"
            networks_rip.append(network)



#under interface
for obj in parse.find_objects_w_child(r'^interface',r'rip'):

        rip_md5=obj.has_child_with(r'rip\sauthentication\smode\smd5')
        #version 1 under interface
        rip_v1=obj.has_child_with(r'rip\s\w+\sversion\s1')

        if (rip_v1==True  and rip_int==True):
            intf_audit.append(6)
            

        #clear text auth
        if obj.has_child_with(r'rip\sauthentication\skey-\w+\s\w+') and rip_md5==False:
            intf_audit.append(7)
            

        #No Auth
        elif (rip_md5==False):
             intf_audit.append(10)
data=defaultdict(list)          
#weak routing  auth keys
for key_chain in auth_keys:
    
    for i in range(2,len(key_chain),3):
        if not (check_strength_password(key_chain[i])):
            intf_audit.append(27)
            obj_data=[]
            obj_data.extend((key_chain[i-2],key_chain[i-1],key_chain[i]))
            
            data[27].append(obj_data)

data=dict(data)   
if(27 in data):

    convert_str_table(27,["key-chain","key-ID","Key-string"])


intf_audit=list(set(intf_audit))

print(intf_audit)
#sort security audits from CRITICAL to INFORMATIONAL
cl = list()
hl = list()
ml = list()
ll = list()
il = list()
for i in intf_audit:
    
    if(audits_intf[str(i)]['tab'][0] == "CRITICAL"):
        cl.append(i)
        CRITICAL_RATING+=1
    elif(audits_intf[str(i)]['tab'][0] == "HIGH"):
        hl.append(i)
        HIGH_RATING+=1
    elif(audits_intf[str(i)]['tab'][0] == "MEDIUM"):
        ml.append(i)
        MEDUIM_RATING+=1
    elif(audits_intf[str(i)]['tab'][0] == "LOW"):
        ll.append(i)
        LOW_RATING+=1
    else:
        il.append(i)
        INFORMATIONAL_RATING+=1

intf_audit.clear()
intf_audit = cl+hl+ml+ll+il

settings.init_securityaudits_intf()
for i in intf_audit:
    retrieve_data_from_json_intf(i)
    if i in intf_table_dict:
        d_intfaudit+=p('This table below illustrates the weakness of : %s' %settings.audits_intf[str(i)]['name'])
        d_intfaudit+=intf_table_dict.get(i)