##############interface auditing##################
from variables import *
from func import *
from settings import *
from dominate.util import raw
from collections import defaultdict


NO_MATCH="__no_match__"
#this list will contain the data to make a table every time we call the method build_table
data=defaultdict(list)

#convert string data to table data
def convert_str_table(id,column):
    
    
    intf_table_dict[id]=raw(build_table(data[id],column))
        
    
   

#function to audit hsrp vrrp glbp
def audit_hsrp_glbp_vrrp(proto,data,table_data):
    
    #low priority
    priority=re.findall(proto+r"\s(\d+)\spriority\s(\d+)",data)
    if(len(priority)!=0 and int(priority[0][1])<254):
        try:
            
            obj_data=[]
            _ipaddress=re.findall(proto+r"\s\d+\sip\s(\d+\.\d+\.\d+\.\d+)",data)
            obj_data.append(_interface)
            obj_data.extend((_ipaddress[0],priority[0][0],priority[0][1]))
            table_data["low_prio"]+=(obj_data)
        except:
            print("ERROR")
    #No Authentication configured
    if("md5" not in data and "authentication text" not in data):
        try:
            obj_data=[]
            priority=re.findall(proto+r"\s(\d+)\spriority\s(\d+)",data)
            _ipaddress=re.findall(proto+r"\s\d+\sip\s(\d+\.\d+\.\d+\.\d+)",data)
            group=re.findall(proto+r"\s(\d+)\sip",data)
            obj_data.extend((_interface,_ipaddress[0],group[0],priority[0][1]))
            table_data["not_all_auth"]+=(obj_data)
        except:
            print("error")
    #Clear text authentication
    if("authentication text" in data):
        try:
            obj_data=[]
            priority=re.findall(proto+r"\s(\d+)\spriority\s(\d+)",data)
            
            _ipaddress=re.findall(proto+r"\s\d+\sip\s(\d+\.\d+\.\d+\.\d+)",data)
            group=re.findall(proto+r"\s(\d+)\sip",data)
            obj_data.extend((_interface,_ipaddress[0],group[0],priority[0][1]))
            table_data["clear_text"]+=(obj_data)
        except:
            print("error")
        key=re.findall(proto+r"\s\d+\sauthentication\stext\s(\S+)",data)
        
        
        #Weak authentication keys
        if not (check_strength_password(key[0])):
            obj_data=[]
            
            obj_data.extend((_interface,_ipaddress[0],group[0],key[0]))
            table_data["weak_auth_keys"]+=(obj_data)
        #Dictionary based authentication keys
        if(check_dict_password(key[0])):
            obj_data=[]
            obj_data.extend((_interface,_ipaddress[0],group[0],key[0]))
            table_data["dict_keys"]+=(obj_data)
       

    return table_data
for obj in parse.find_objects_w_child(r"^interface",r"(glbp|standby|vrrp)"):
    
    _interface=re.findall(r"interface\s(\S+)",str(obj.text))[0]
    obj_list=list()
    vrrp=defaultdict(str)
    glbp=defaultdict(str)
    hsrp=defaultdict(str)

    for obj_child in obj.children:
        obj_list.append(str(obj_child.text))
    for proto in obj_list:
        
        if(bool(re.search("vrrp",proto))):
            x=re.findall(r'vrrp\s(\d+)',proto)
            vrrp[x[0]]+=(proto)
            
            
        elif(bool(re.search("glbp",proto))):
            x=re.findall(r'glbp\s(\d+)',proto)
            glbp[x[0]]+=proto 
            
        elif(bool(re.search("standby",proto))):
            x=re.findall(r'standby\s(\d+)',proto)
            hsrp[x[0]]+=proto 
            
    vrrp=dict(vrrp)
    hsrp=dict(hsrp)
    glbp=dict(glbp)
    
    #audit VRRP
    if(len(vrrp)!=0):
       
       
       for group in vrrp:
          table_data={"not_all_auth":[],"clear_text":[],"low_prio":[],"weak_auth_keys":[],"dict_keys":[]}
          result= audit_hsrp_glbp_vrrp("vrrp",vrrp[group],table_data)
          
          for weakness in table_data:
              if(weakness):
                if(weakness=="not_all_auth" and table_data[weakness]):
                    data[9].append(table_data[weakness])
                    intf_audit.append(9)
                elif(weakness=="clear_text" and table_data[weakness]):
                    data[8].append(table_data[weakness])
                    intf_audit.append(8)
                elif(weakness=="low_prio" and table_data[weakness]):
                    data[14].append(table_data[weakness] and table_data[weakness])
                    intf_audit.append(14)
                elif(weakness=="weak_auth_keys" and table_data[weakness]):
                    data[20].append(table_data[weakness] and table_data[weakness])
                    intf_audit.append(20)
                elif(weakness=="dict_keys" and table_data[weakness]):
                     data[19].append(table_data[weakness])
                     intf_audit.append(19)


       

       
        
    #audit GLBP
    if(len(glbp)!=0):
        for group in glbp:
          table_data={"not_all_auth":[],"clear_text":[],"low_prio":[],"weak_auth_keys":[],"dict_keys":[]}
          result= audit_hsrp_glbp_vrrp("glbp",glbp[group],table_data)
          
          for weakness in table_data:
              if(weakness):
                if(weakness=="not_all_auth" and table_data[weakness]):
                    data[2].append(table_data[weakness])
                    intf_audit.append(2)
                elif(weakness=="clear_text" and table_data[weakness]):
                    data[11].append(table_data[weakness])
                    intf_audit.append(11)
                elif(weakness=="low_prio" and table_data[weakness]):
                    data[15].append(table_data[weakness] and table_data[weakness])
                    intf_audit.append(15)
                elif(weakness=="weak_auth_keys" and table_data[weakness]):
                    data[23].append(table_data[weakness] and table_data[weakness])
                    intf_audit.append(23)
                elif(weakness=="dict_keys" and table_data[weakness]):
                     data[24].append(table_data[weakness])
                     intf_audit.append(24)
       
    #audit HSRP
    if(len(hsrp)!=0):
        for group in hsrp:
          table_data={"not_all_auth":[],"clear_text":[],"low_prio":[],"weak_auth_keys":[],"dict_keys":[]}
          result= audit_hsrp_glbp_vrrp("standby",hsrp[group],table_data)
          
          for weakness in table_data:
              if(weakness):
                if(weakness=="not_all_auth" and table_data[weakness]):
                    data[3].append(table_data[weakness])
                    intf_audit.append(3)
                elif(weakness=="clear_text" and table_data[weakness]):
                    data[4].append(table_data[weakness])
                    intf_audit.append(4)
                elif(weakness=="low_prio" and table_data[weakness]):
                    data[16].append(table_data[weakness] and table_data[weakness])
                    intf_audit.append(16)
                elif(weakness=="weak_auth_keys" and table_data[weakness]):
                    data[25].append(table_data[weakness] and table_data[weakness])
                    intf_audit.append(25)
                elif(weakness=="dict_keys" and table_data[weakness]):
                     data[26].append(table_data[weakness])
                     intf_audit.append(26)
        

data=dict(data)

for i in [3,4,16,25,26,24,23,15,11,19,20,14,8,9]:
      
    if(i in data):
        convert_str_table(i,["interface","Virtual Address","group","priority"])    


#lines audit
for obj in parse.find_objects(r"line"):
    obj_list=list()
    for child in obj.children:
        obj_list.append(str(child.text))
    #make the children of interface as string   
    obj_list= ''.join(map(str,obj_list))

    #telnet enabled
    if ("vty" in str(obj.text)):
        if ("telnet" in obj_list):
            intf_audit.append(39)
    #connection timeout
    if not ("exec-timeout"  in obj_list):
        intf_audit.append(40)

        
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
            
            net=network_ospf.split()

            #Translates an OSPF (address, wildcard) to a list of ip_network objects (address, netmask)
            networks_rp.append(wildcard_to_netmasks(net[0],net[1]))

try:
    interfaces_networks_rp=list(set(get_interfaces(networks_rp,parse,interfaces_networks_rp)))

    data=defaultdict(list)
    #Iterate over ospf interfaces
    for intf in interfaces_networks_rp:

        text_auth=intf.has_child_with(r'ip\sospf\sauthentication-key')
        md5_auth=intf.has_child_with(r'ip\sospf\smessage-digest-key')
        for intf_child in intf.children:
            priority=intf_child.re_match_typed(r'ip\sospf\spriority\s(\d+)',default=NO_MATCH)
            if(priority!=NO_MATCH):
                if(int(priority)<255):
                    intf_audit.append(28)
                    obj_data=[]
                    obj_data.extend((re.findall(r"interface\s(\S+)",str(intf.text))[0],priority))
                    data[28].append(obj_data)
        
        if (text_auth==True):
            intf_audit.append(13)

        elif(md5_auth==False):
            intf_audit.append(5)
            
    data=dict(data)
    try:
        convert_str_table(28,["Interface","OSPF Priority"])     
    except:
        pass
except:
    pass

networks_rp.clear()
interfaces_networks_rp.clear()
#EIGRP Audit
for ospf_obj in parse.find_objects(r'^router\seigrp'):
    
    for child_obj in ospf_obj.children:  # Iterate over EIGRP children

        network_eigrp = child_obj.re_match_typed(HELPER_REGEX, default=NO_MATCH)

        if network_eigrp!=NO_MATCH:
            
            net=network_eigrp.split()

            #Translates an EIGRP (address, wildcard) to a list of ip_network objects (address, netmask)
            networks_rp.append(wildcard_to_netmasks(net[0],net[1]))

interfaces_networks_rp=list(set(get_interfaces(networks_rp,parse,interfaces_networks_rp)))

for intf in interfaces_networks_rp:
    
            
        md5_auth=intf.has_child_with(r"ip\sauthentication\skey-chain\seigrp")
        if(md5_auth==False):
            intf_audit.append(12)   
        elif(md5_auth==True):
            for intf_child in intf.children:
               
                #key_chain=intf_child.re_match_typed(r"ip\sauthentication\skey-chain\seigrp\s(S+)$",default=NO_MATCH)
                key_chain=re.findall(r"ip authentication\skey-chain\seigrp\s\d+\s(\w+)",str(intf_child.text))
                if(key_chain):
                    
                    auth_keys+=(get_key_strings(key_chain[0]))
        

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
for obj in parse.find_objects_w_child(r'^interface',r'ip\srip'):

        rip_md5=obj.has_child_with(r'ip\srip\sauthentication\smode\smd5')
        #version 1 under interface
        rip_v1=obj.has_child_with(r'ip\srip\s\w+\sversion\s1')

        if (rip_v1==True  and rip_int==True):
            intf_audit.append(6)
            

        #clear text auth
        if obj.has_child_with(r'ip\srip\sauthentication\skey-\w+\s\w+') and rip_md5==False:
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
data=defaultdict(list)
#interfaces audit
for obj in parse.find_objects(r"interface"):
    intf_no_filter=obj.has_child_with(r"ip\saccess-group")
    _interface=re.findall(r"interface\s(\S+)",str(obj.text))[0]
    _shutdown="Active"
    obj_list=list()
    for child in obj.children:
        obj_list.append(str(child.text))
    #make the children of interface as string   
    obj_list= ''.join(map(str,obj_list))
  
    if ("no shutdown" in obj_list):
        try:
            
            _ipaddress=re.findall(r"ip\saddress\s(\d+\.\d+\.\d+\.\d+)",obj_list)[0]
            
            
        except:
            _ipaddress="Not Configured"
            
        try:
            _description=re.findall(r"description\s(\S+)",obj_list)[0]
        except:
            _description="No Description Found"

        obj_data=[]
        obj_data.extend((_interface,_ipaddress,_shutdown,_description))
        if not (intf_no_filter):
            intf_audit.append(17)
            data[17].append(obj_data)
            #build the table 
            
        if  ("no ip directed broadcast" not  in obj_list):
            intf_audit.append(32)
            #build the table
            data[32].append(obj_data)
        if  ("no ip mask-reply" not in obj_list):
            intf_audit.append(34)
            data[34].append(obj_data)
            #build the table 
        if  ("no ip proxy-arp" not in obj_list):
            intf_audit.append(35)
            data[35].append(obj_data)
            #build the table 
        if  ("no ip unreachables" not in obj_list):
            intf_audit.append(36)
            data[36].append(obj_data)
            #build the table 
        if  ("no ip redirects" not in obj_list):
            intf_audit.append(37)
            data[37].append(obj_data)
            #build the table 
data=dict(data)
for i in [17,32,34,35,36,37]:
   
    if(i in data):
        convert_str_table(i,["Interface","Address","State","Description"])





intf_audit=list(set(intf_audit))

print(intf_audit)
#sort security audits from CRITICAL to INFORMATIONAL
cl = list()
hl = list()
ml = list()
ll = list()
il = list()
for i in intf_audit:
    print(audits_intf[str(i)]['tab'][0])
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
        

    


