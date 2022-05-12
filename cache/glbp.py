



from dominate.util import raw
from matplotlib.pyplot import text
from variables import *
import re
from func import build_table
from collections import defaultdict
data=defaultdict(list)


#function to audit
def audit_hsrp_glbp_vrrp(proto,data,table_data):
    
    #low priority
    priority=re.findall(proto+r"\s(\d+)\spriority\s(\d+)",data)
    if(len(priority)!=0 and int(priority[0][1])<254):
        try:
            
            obj_data=[]
            _ipaddress=re.findall(proto+r"\s\d+\sip\s(\d+\.\d+\.\d+\.\d+)",data)
            obj_data.append(str(obj.text))
            obj_data.extend((_ipaddress[0],priority[0][0],priority[0][1]))
            table_data["low_prio"]+=(obj_data)
        except:
            print("ERROR")
    #No Authentication configured
    if("md5" not in data and "authentication text" not in data):
        try:
            obj_data=[]
            _ipaddress=re.findall(proto+r"\s\d+\sip\s(\d+\.\d+\.\d+\.\d+)",data)
            group=re.findall(proto+r"\s(\d+)\sip",data)
            obj_data.extend((str(obj.text),_ipaddress[0],group[0]))
            table_data["not_all_auth"]+=(obj_data)
        except:
            print("error")
    #Clear text authentication
    if("authentication text" in data):
        try:
            obj_data=[]
            obj_data.append(str(obj.text))
            _ipaddress=re.findall(proto+r"\s\d+\sip\s(\d+\.\d+\.\d+\.\d+)",data)
            group=re.findall(proto+r"\s(\d+)\sip",data)
            obj_data.extend((_ipaddress[0],priority[0][0],group[0]))
            table_data["clear_text"]+=(obj_data)
        except:
            print("error")

    #Weak authentication keys

    #Dictionary based authentication keys

       

    return table_data
for obj in parse.find_objects_w_child(r"^interface",r"(glbp|standby|vrrp)"):
    print(str(obj.text))
    
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
          print(result)
          for weakness in table_data:
              if(weakness):
                if(weakness=="not_all_auth" and table_data[weakness]):
                    data[9].append(table_data[weakness])
                elif(weakness=="clear_text" and table_data[weakness]):
                    data[8].append(table_data[weakness])
                elif(weakness=="low_prio" and table_data[weakness]):
                    data[14].append(table_data[weakness] and table_data[weakness])
                elif(weakness=="weak_auth_keys" and table_data[weakness]):
                    data[20].append(table_data[weakness] and table_data[weakness])
                elif(weakness=="dict_keys" and table_data[weakness]):
                     data[19].append(table_data[weakness])


       

       
        
    #audit GLBP
    if(len(glbp)!=0):
       table_data={"not_all_auth":[],"clear_text":[],"low_prio":[],"weak_auth_keys":[],"dict_keys":[]}
       
    #audit HSRP
    if(len(hsrp)!=0):
        table_data={"not_all_auth":[],"clear_text":[],"low_prio":[],"weak_auth_keys":[],"dict_keys":[]}
        
        
data=dict(data)
print(data[14])
print("\n")
print(data[9])
print("\n")
print(data[8])
intf_table={}
intf_table[8]=raw(build_table(data[8],["interface","Virtual Address","group","priority"]))
intf_table[14]=raw(build_table(data[14],["interface","Virtual Address","group","priority"]))
print(intf_table[8],intf_table[14])


"""
#the configuration report
report+=h3("3 Configuration Report")
report+=h4("3.1 Introduction")
report+=p("This section details the configuration settings of your device in an easy to read and understand format. \
        The various device configuration settings are grouped into sections of related options.")
report+=h4("3.2 Basic Information")
report+=raw(build_table([[hostname,device_type,versio_os]],["Name","Device","OS"]))
report+=d_device_conf
"""