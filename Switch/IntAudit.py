##############interface auditing##################
from variables import *
from func import *
from settings import *


#audit STP
glob_bpduguard= parse.has_line_with(r"spanning-tree portfast bpduguard default")
glob_bpdufilter=parse.has_line_with(r"spanning-tree portfast bpdufilter default")
glob_guardloop=parse.has_line_with(r"spanning-tree loopguard default")

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
        #bdduguard
        if  not (glob_bpduguard):
            if("switchport host" not in obj_list):

                if ("spanning-tree bpduguard enable" not in obj_list):
                    intf_audit.append(1)
        #bdufilter
        if not (glob_bpdufilter):
            if("switchport host" not in obj_list):      
                if ("spanning-tree bpdufilter enable" not in obj_list):
                    intf_audit.append(2)
        if not (glob_guardloop):
            if ("spanning-tree guard loop" not in obj_list):
                intf_audit.append(10)
        if ("spanning-tree guard root" not in obj_list):
            intf_audit.append(11)
        #check dtp enabled
        if ("switchport nonegotiate" not in obj_list):
            intf_audit.append(12)
        #trunk allowed vlans 
        if ("switchport mode trunk" in obj_list):
            if ("switchport trunk allowed vlan" not in obj_list):
                intf_audit.append(13)
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




intf_audit=list(set(intf_audit))
print("int")
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


print(CRITICAL_RATING,HIGH_RATING,MEDUIM_RATING,LOW_RATING,INFORMATIONAL_RATING)


settings.init_securityaudits_intf()
for i in intf_audit:
    retrieve_data_from_json_intf(i)
    if i in intf_table_dict:
        d_intfaudit+=p('This table below illustrates the weakness of : %s' %settings.audits_intf[str(i)]['name'])
        d_intfaudit+=intf_table_dict.get(i)

    