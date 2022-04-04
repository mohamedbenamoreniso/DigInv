from variables import *
from settings import *
from func import *


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
# checking domain lookup
if not (parse.find_objects(r'no ip domain(\s|-)lookup')):
    
     glob_list.append(40)

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