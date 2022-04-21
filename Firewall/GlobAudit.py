from ast import Try
from Router.IntfAudit import HELPER_REGEX
from variables import *
import re
from settings import *
from func import *
from dominate.util import raw

#this list will contain the data to make a table every time we call the method build_table
table_data=[]

#SNMP Audit
tests ={
  'VERSION':False,
  'DEFAULT_COM':False,
  'ACCESS_LIST':False,
  'CLEAR_TEXT':False,
  'WRITE_VIEW':False
  }

HELPPER_REG_1=r"snmp-server\scommunity\s\.d\s(\w+)\s(\w+)($|\s(\w+))"

HELPPER_REG_2=r"snmp-server\sgroup\s\w+\s(\w+)\s(\w+)"


for obj in parse.find_objects(r'^snmp-server'):

    if("snmp-server enable traps" not in str(obj.text)):
        
        
        community=re.findall(HELPPER_REG_1,str(obj.text))
        group=re.findall(HELPPER_REG_2,str(obj.text))
        
        if(community):
            if(check_strings(community[0][0])):
               glob_list.append(28) 

            if(community[0][0] in ("private","public")):
                tests["DEFAULT_COM"]=True
                tests["VERSION"]=True
                glob_list.append(26)
                glob_list.append(2)



            if(not community[0][3]):
                tests["ACCESS_LIST"]=True
                glob_list.append(27)

            if("view" not in str(obj.text)):
                tests["WRITE_VIEW"]=True
                glob_list.append(28)

        if(group):
            
            if(group[0][0] in ("v3") and group[0][1] !="priv"):

                tests["CLEAR_TEXT"]=True
                glob_list.append(5)
        if ("md5" in str(obj.text)):
            #use SHA instead
            glob_list.append(55)
        if (r"version 1" in str(obj.text)):
            glob_list.append(31)


# checking enable password
if not parse.find_objects(r'enable password'):
   
     glob_list.append(4)

#ip http server enabled
HTTP_ENABLED=False
if parse.find_objects(r'http server enable'):
    
     glob_list.append(15)
     HTTP_ENABLED=True

#check timeout http server
if (HTTP_ENABLED==True and not parse.find_objects(r'^http server (session-timeout|idle-timeout)')):
    glob_list.append(8)

#username contain admin
if parse.find_objects(r'username (admin|ADMIN|Admin)'):
    glob_list.append(13)

#Post Logon Banner
if not (parse.find_objects(r"banner exec")):
    glob_list.append(43)

#Check access rules
if not (parse.find_objects(r"saccess-list")):
   glob_list.append(42)

#banner-logon
if not parse.find_objects(r'banner login'):
     
      glob_list.append(25)


#check NTP Queries
if (parse.find_objects(r"^ntp")):
    
    if not (parse.find_objects(r"ntp authentication-key")):
        glob_list.append(41)

glob_list=list(set(glob_list))

#Network filtering(ACL Audit)
print("----------start auditing access control lists--------------------")
# 1 - extended access control list
for acl in parse.find_objects(r"^access-list\s\w+\sextended"):
    #check if there are any source/destination allowed
    SOURCE=r"(\d+\.\d+\.\d+\.\d+\s\d+\.\d+\.\d+\.\d+|host\s\d+\.\d+\.\d+\.\d+|any|any4|any6|interface\s\w+|object\s\w+|object-group\s\w+)\s"
    DESTINATION=r"(\d+\.\d+\.\d+\.\d+\s\d+\.\d+\.\d+\.\d+|host\s\d+\.\d+\.\d+\.\d+|any|any4|any6|interface\s\w+|object\s\w+|object-group\w+)\s"
    #HELPER_REGEX=r"access-list\s(\S+)\sextended\s(\w+)\s(\d+|\w+)\s"+SOURCE+DESTINATION+r"(\S+)\s(\d+|\w+)($|\w+)"
    
    HELPER_REGEX=r"access-list\s(\S+)\sextended\s(\w+)\s(\d+|\w+)\s"+SOURCE+DESTINATION+r"($|(\S+))"
    
    acl_audits=re.findall(HELPER_REGEX,str(acl.text))
    print(acl_audits)

    



    









glob_list=list(set(glob_list))
print(glob_list)
#sort security audits from CRITICAL to INFORMATIONAL
cl = list()
hl = list()
ml = list()
ll = list()
il = list()
for i in glob_list:
    
    if(audits[str(i)]['tab'][0] == "CRITICAL"):
        cl.append(i)
        CRITICAL_RATING+=1
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
        d_globaudit+=p('This table below illustrates the weakness of : %s' %settings.audits[str(i)]['name'])
        d_globaudit+=glob_table_dict.get(i)