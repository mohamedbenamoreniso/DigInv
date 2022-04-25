##############interface auditing##################

from variables import *
from func import *
from settings import *




#function to query informations from objects network
def Query_object(object):

    try:

        for obj in parse.find_objects(r"object\s\w+\s"+object.split()[1]):
           
            for obj_child in obj.children:
                if ("subnet" in str(obj_child.text)):
                    print("test")
                    
                    intf_audit.append(41)   
            return 1
            
  
    except:
        return 0
#function to query informations from object group network
def Query_object_group(object_group):
    try:

        for obj in parse.find_objects(r"object-group\s\w+\s"+object_group.split()[1]):
           
            for obj_child in obj.children:
                line=str(obj_child.text)
                if ("subnet" in line):
                    intf_audit.append(41)
                elif("object" in line):
                    Query_object(line)  
            return 1
            
  
    except:
        return 0



#Network filtering(ACL Audit)
print("----------start auditing access control lists--------------------")
# 1 - extended access control list
for acl in parse.find_objects(r"^access-list\s\w+\sextended"):
    #check if there are any source/destination allowed
    SOURCE=r"(\d+\.\d+\.\d+\.\d+\s\d+\.\d+\.\d+\.\d+|host\s\d+\.\d+\.\d+\.\d+|any4|any6|any|interface\s\w+|object\s\w+|object-group\s\w+)\s"
    DESTINATION=r"(\d+\.\d+\.\d+\.\d+\s\d+\.\d+\.\d+\.\d+|host\s\d+\.\d+\.\d+\.\d+|any4|any6|any|interface\s\w+|object\s\w+|object-group\s\w+)"
    
    
    HELPER_REGEX=r"access-list\s(\S+)\sextended\s(\w+)\s(\d+|\w+)\s"+SOURCE+DESTINATION
    
    acl_line=re.findall(HELPER_REGEX,str(acl.text))[0]
    print(acl_line)
   
    #get the source from ACE
    acl_source=acl_line[-2]

    #get the destination from ACE
    acl_destination=acl_line[-1]
    print(acl_source,acl_destination)

    #check source
    _pass=False
    #any source
    if("any" in acl_source and _pass==False):
        intf_audit.append(43)
        _pass==True

    #source with object configured
    elif(_pass==False and "object" in acl_source):
        print(Query_object(acl_source))
        _pass==True
    #source with object group configured
    elif(_pass==False and "object-group" in acl_source):
        print(Query_object_group(acl_source))
        _pass==True
    #entire network
    elif( _pass==False and ("host" not in acl_source)):
        
        intf_audit.append(41)
        _pass==True



    #check destination

    #check destination port




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