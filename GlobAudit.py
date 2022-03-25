from numpy import append
from variables import *
from settings import *
import re
from func import *
from dominate.util import raw

#this list will contain the data to make a table every time we call the method build_table
table_data=[]

#service PAD
if not (parse.find_objects(r"no service pad")):
    glob_list.append(44)
#service tcp-keep-alives-in
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

#weak minimum password length
if(parse.find_objects(r'security passwords min-length')):

    pass_policy=parse.find_objects(r'security passwords min-length')[0]
    pass_len=re.findall(r'security\spasswords\smin-length\s(\d+)',str(pass_policy.text))
    if(int(pass_len[0])<8):
        glob_list.append(35)
     

#Aux port
if(parse.find_objects(r'line aux')):
    aux=parse.find_objects(r'line aux')
    if not (aux[0].has_child_with(r'no\sexec')):
        glob_list.append(16)
#ip http server enabled
HTTP_ENABLED=False
if parse.find_objects(r'ip http server'):
    
     glob_list.append(15)
     HTTP_ENABLED=True

#check timeout http server
if (HTTP_ENABLED==True and not parse.find_objects(r'^ip http timeout-policy')):
    glob_list.append(8)
# HTTP Restriction
if(HTTP_ENABLED==True and not parse.find_objects(r'ip http access-class')):
    glob_list.append(17)

#username contain admin
if parse.find_objects(r'username (admin|ADMIN|Admin)'):
    glob_list.append(13)
#checking enable password
if parse.find_objects(r'^enable password'):
    glob_list.append(11)
    
    
# checking domain lookup
if not (parse.find_objects(r'no ip domain(\s|-)lookup')):
    
     glob_list.append(40)
      
# checking classless
if parse.find_objects(r'no ip classless'):
    
      pass
else:
    glob_list.append(10)

#Check access rules
if not (parse.find_objects(r"(^|ip)\saccess-list")):
   glob_list.append(42)
#Post Logon Banner
if not (parse.find_objects(r"banner exec")):
    glob_list.append(43)
# checking CDP
if not parse.find_objects(r'no cdp run'):
   
    glob_list.append(22)
elif not parse.find_objects_w_child(r'^interface\s\w+thernet',r'no cdp enable'):
   
     glob_list.append(22)

     
#checking mode VTP mode
if parse.find_objects(r'vtp mode server'):
    
     glob_list.append(23)

    
#ip source-route
if not parse.find_objects(r'no ip source-route'):
    
     glob_list.append(24)

    
#banner-logon
if not parse.find_objects(r'banner login'):
     
      glob_list.append(25)

   
#udp small-servers enabled
if parse.find_objects(r'service udp-small-servers'):
   
     glob_list.append(4)
    

    
#tcp small-servers enabled
if not (parse.find_objects(r'service tcp-small-servers')):
   
     glob_list.append(39)

    
#ip finger
if parse.find_objects(r'ip finger'):
    
     glob_list.append(27)

#IP Identification service
if parse.find_objects(r'ip identd'):
    glob_list.append(46)
#tcp-keep-alives out
if not parse.find_objects(r'service tcp-keepalives-out'):
    glob_list.append(47)

#Sequence Numbers and Time Stamps
if parse.find_objects(r'no\sservice\stimestamps\s(debug|log)'):
    glob_list.append(48)
#cef 
if parse.find_objects(r'no ip cef'):
    glob_list.append(49)
#gratuitous arp
if parse.find_objects(r'ip gratuitous-arps'):
    glob_list.append(50)
#auth failure rate
fail_rate=parse.find_objects(r'security authentication failure rate')
if(fail_rate):
    fail_rate=fail_rate[0]
    fail_time=fail_rate.re_match_typed(r'security authentication failure rate (\d+)',default=NO_MATCH)
    if(fail_time!=NO_MATCH and int(fail_time)>3):
        glob_list.append(51)
else:
    glob_list.append(52)
#tcpsynwait 
fail_rate=parse.find_objects(r'ip tcp synwait-time')
if(fail_rate):
    fail_rate=fail_rate[0]
    fail_time=fail_rate.re_match_typed(r'ip tcp synwait-time (\d+)',default=NO_MATCH)
    if(fail_time!=NO_MATCH and int(fail_time)>10):
        glob_list.append(53)
else:
    glob_list.append(54)
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

#Users stregth password checker
#users with dictionnary based attack

for user in parse.find_objects(r"^username"):

    #initialize the list of the object data
    obj_data=[]
    
    password=re.findall(r"password\s\d\s(\S+)",str(user.text))
    username=re.findall(r"username\s(\w+)",str(user.text))
    privilege=re.findall(r"privilege\s(\d+)",str(user.text))
   
    
    if not (check_strength_password(password[0])):
        glob_list.append(14)

        
    if(check_dict_password(password[0])):
        
        glob_list.append(1)
        obj_data.extend((username[0],password[0],privilege[0]))
        table_data.append(obj_data)

column=["User","Password","Privilege"]
glob_table_dict[1]=raw(build_table(table_data,column))
        
        

#check NTP Queries
if (parse.find_objects(r"^ntp")):
    if(parse.find_objects(r"ntp\saccess-group\squery-only")):
        pass
    else:
        glob_list.append(19)
    if not (parse.find_objects(r"ntp authentication-key")):
        glob_list.append(41)

glob_list=list(set(glob_list))
glob_list.sort()
print(glob_list)
settings.init()
for i in glob_list:
    retrieve_data_from_json(i)
    if i in glob_table_dict:
        d_globaudit+=p('This table below illustrates the weakness of : %s' %settings.audits[str(i)]['name'])
        d_globaudit+=glob_table_dict.get(i)
        
    if(i==1):
        CRITICAL_RATING+=1
    elif(2<= i <=11):
        HIGH_RATING+=1
    elif(12<= i <=20):
        MEDUIM_RATING+=1
    elif(21<=i<=38):
        LOW_RATING+=1
    else:
        INFORMATIONAL_RATING+=1



        

