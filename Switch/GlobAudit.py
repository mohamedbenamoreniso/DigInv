from variables import *
from settings import *
from func import *



#software version
if parse.find_objects(r"version 12"):
    glob_list.append(55)
# service PAD
if not (parse.find_objects(r"no service pad")):
    glob_list.append(44)
# service tcp-keep-alives-in
if not parse.find_objects(r'service tcp-keepalives-in'):
    glob_list.append(9)


# checking BOOTP
if not parse.find_objects(r'no ip bootp server'):

   glob_list.append(26)


# checking Service Password Encryption
if parse.find_objects(r'no service password-encryption'):
   glob_list.append(21)


# checking enable secret
if not parse.find_objects(r'enable secret'):

     glob_list.append(4)
# checking domain lookup
if not (parse.find_objects(r'no ip domain(\s|-)lookup')):

     glob_list.append(40)

# Post Logon Banner
if not (parse.find_objects(r"banner exec")):
    glob_list.append(43)
# checking CDP
if not parse.find_objects(r'no cdp run'):

    glob_list.append(22)
elif not parse.find_objects_w_child(r'^interface\s\w+thernet', r'no cdp enable'):

     glob_list.append(22)
# checking mode VTP mode
if parse.find_objects(r'vtp mode server'):

     glob_list.append(23)
#username contain admin
if parse.find_objects(r'username (admin|ADMIN|Admin)'):
    glob_list.append(13)
#checking enable password
if parse.find_objects(r'^enable password'):
    glob_list.append(11)
#Check access rules
if not (parse.find_objects(r"(^|ip)\saccess-list")):
   glob_list.append(42)
    
# checking domain lookup
if not (parse.find_objects(r'no ip domain(\s|-)lookup')):
    
     glob_list.append(40)
#SNMP Audit
tests ={
  'VERSION':False,
  'DEFAULT_COM':False,
  'WRITE_ACCESS':False,
  'ACCESS_LIST':False,
  'CLEAR_TEXT':False,
  'SYSTEM_SHUTDOWN_EN':False,
  'SNMP_TFTP':True,
  'WRITE_VIEW':False
  }

HELPPER_REG_1=r"snmp-server\scommunity\s(\w+)\s(\w+)($|\s(\w+))"

HELPPER_REG_2=r"snmp-server\sgroup\s\w+\s(\w+)\s(\w+)"

HELPPER_REG_3=r"snmp-server\ssystem-shutdown"
glob_list.append(23)
for obj in parse.find_objects(r'^snmp-server'):

      if("snmp-server enable traps" not in str(obj.text)):
        
        
        community=re.findall(HELPPER_REG_1,str(obj.text))
        group=re.findall(HELPPER_REG_2,str(obj.text))
        
        if(str(obj.text)=="snmp-server system-shutdown"):
            tests['SYSTEM_SHUTDOWN_EN']=True
            glob_list.append(8)
            
        
        if("snmp-server file-transfer"  in str(obj.text)):
            tests['SNMP_TFTP']=False
            glob_list.pop(23)

        
        if(community):
            if(check_strings(community[0][0])):
               glob_list.append(28) 

            if(community[0][0] in ("private","public")):
                tests["DEFAULT_COM"]=True
                tests["VERSION"]=True
                glob_list.append(26)
                glob_list.append(2)

            if(community[0][1] in("RW")):
                tests["WRITE_ACCESS"]=True
                glob_list.append(6)

            if(not community[0][3]):
                tests["ACCESS_LIST"]=True
                glob_list.append(27)

            if("view" not in str(obj.text)):
                tests["WRITE_VIEW"]=True
                glob_list.append(28)

        if(group):
            
            if(group[0][0] in("v1")):

                tests["VERSION"]=True
                glob_list.append(26)
            if(group[0][0] in ("v3") and group[0][1] !="priv"):

                tests["CLEAR_TEXT"]=True
                glob_list.append(5)
            if("access" not in str(obj.text)):

                tests["ACCESS_LIST"]=True
                glob_list.append(27)


glob_list=list(set(glob_list))

#sort security audits from CRITICAL to INFORMATIONAL
cl = list()
hl = list()
ml = list()
ll = list()
il = list()
for i in glob_list:
   
    if(audits[str(i)]['tab'][0] == "CRITICAL"):
        cl.append(i)
        CRITICAL_RATING += 1
    elif(audits[str(i)]['tab'][0] == "HIGH"):
        hl.append(i)
        HIGH_RATING+=1
    elif(audits[str(i)]['tab'][0] == "MEDIUM"):
        ml.append(i)
        MEDUIM_RATING+=1
    elif(audits[str(i)]['tab'][0] == "LOW"):
        ll.append(i)
        LOW_RATING+=1
    else:
        il.append(i)
        INFORMATIONAL_RATING+=1



glob_list.clear()
glob_list = cl+hl+ml+ll+il

for i in glob_list:
    retrieve_data_from_json(i)
    if i in glob_table_dict:
        d_globaudit += p('This table below illustrates the weakness of : %s' %settings.audits[str(i)]['name'])
        d_globaudit += glob_table_dict.get(i)

