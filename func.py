from dominate.tags import *
from dominate import *
import re
import pandas as pd
import settings
import variables
from variables import *
import ipaddr
import itertools
from ipaddress import NetmaskValueError
import ipaddress


MAX_DONT_CARE_BITS = 8
NO_MATCH="__no_match__"



#function to check if password include in a dictionnary attack
def check_dict_password(password):
    inFile = open('passwords.txt', 'r')
    passwords_list=inFile.read().split("\n")
    
    if (password in passwords_list):
            
            return True
    else:
            
            return False
           
            
    
#function to check the strength of a password
def check_strength_password(password):
    flag = 0
    while True:
        if (len(password)<8):
            flag = -1
            break
        elif not re.search("[a-z]", password):
            flag = -1
            break
        elif not re.search("[A-Z]", password):
            flag = -1
            break
        elif not re.search("[0-9]", password):
            flag = -1
            break
        elif not re.search("[&'(-_)=$*%!:;,<>§µ^]", password):
            flag = -1
            break
        elif re.search("\s", password):
            flag = -1
            break
        else:
            flag = 0
            return True
            
    if flag ==-1:
        return False

#function to check if snmp strings are wreak or belong to dictionary-based attack
def check_strings(_str):
    if len(_str) < 8 or _str.lower() == _str or _str.upper() == _str :
        return True

    else:
        return False
        
# function to retrieve data from the json file (global audit)

settings.init()
i=1
def retrieve_data_from_json(id):
    global i
    global d_globaudit
    str_id = str(id)
    variables.global_list_sec_audit.append(settings.audits[str_id]['name'])
    # start global report generating
    inf_div=div(_class="information")
    threat_div=div(_class="container")
    with inf_div:
        inf_div += h3('%d. %s' % (i,settings.audits[str_id]['name']))
        inf_div+=h5("observation")
        inf_div += p('%s' % settings.audits[str_id]['observation'])
        inf_div+=h5("impact")
        #inf_div += p('%s' % settings.audits[str_id]['impact'])
        impact=settings.audits[str_id]['impact'].split(";")
        rec_s=ul()
        for rec in impact:
            rec_s+=li(rec)
        inf_div+=rec_s
        inf_div+=h5("ease")
        inf_div += p('%s' % settings.audits[str_id]['ease'])
        inf_div+=h5("recommandation")
        #inf_div += p('%s' % settings.audits[str_id]['recommandation'])
        recommandation=settings.audits[str_id]['recommandation'].split(";")
        rec_s=ul()
        for rec in recommandation:
            rec_s+=li(rec)
        inf_div+=rec_s
        inf_div += p('%s' % (settings.audits[str_id]['command']),_class='command')
        _list=settings.audits[str_id]['tab']
    square_div=div_o_i_e_f(_list)
    threat_div+=inf_div
    threat_div+=square_div
    d_globaudit+=threat_div
    i+=1

    return 0

# function to retrieve data from the json file (interface audit)

settings.init_securityaudits_intf()
def retrieve_data_from_json_intf(id):
    global i
    str_id = str(id)
    global d_intfaudit
    variables.intf_list_sec_audit.append(settings.audits_intf[str_id]["name"])
    #start interface report generating
    inf_div=div(_class="information")
    threat_div=div(_class="container")
    with inf_div:
        inf_div += h3('%d. %s' % (i,settings.audits_intf[str_id]['name']))
        inf_div+=h5("observation")
        inf_div += p('%s' % settings.audits_intf[str_id]['observation'])
        inf_div+=h5("impact")
        #inf_div += p('%s' % settings.audits_intf[str_id]['impact'])
        impact=settings.audits_intf[str_id]['impact'].split(";")
        rec_s=ul()
        for rec in impact:
            rec_s+=li(rec)
        inf_div+=rec_s
        inf_div+=h5("ease")
        inf_div += p('%s' % settings.audits_intf[str_id]['ease'])
        inf_div+=h5("recommandation")
        #inf_div += p('%s' % settings.audits_intf[str_id]['recommandation'])
        recommandation=settings.audits[str_id]['recommandation'].split(";")
        rec_s=ul()
        for rec in recommandation:
            rec_s+=li(rec)
        inf_div+=rec_s
        #print(recommandation)
        inf_div += p('%s' % (settings.audits_intf[str_id]['command']),_class='command')
        _list=settings.audits_intf[str_id]['tab']
    square_div=div_o_i_e_f(_list)
    threat_div+=inf_div
    threat_div+=square_div
    d_intfaudit+=threat_div
    i=+1
    return 0
#build a dynamic table
def build_table(data,column):
   df = pd.DataFrame(data,columns=column)
   return df.to_html()

       
#iterate over Key-chain as input and return of the key-strins as output 
def get_key_strings(key_chain):
    key_strings=list()
    for key_c in variables.parse.find_objects(r"^key chain\s"+key_chain):
        local_key=[]
        for key_c_child in key_c.children:
            
            local_key.append(key_chain)
            key_id=key_c_child.re_match_typed(r"key\s(\d+)",default=NO_MATCH)
            if(key_id!=NO_MATCH):
                local_key.append(key_id)
                for obj in key_c_child.children:
                    key_string=obj.re_match_typed(r"key-string\s(\S+)",default=NO_MATCH)
                    if(key_string!=NO_MATCH):
                        local_key.append(key_string)
        key_strings.append(local_key)
    return key_strings

#generate div for overall,impact,ease,fix
def div_o_i_e_f(l):
    _s=['Overall','Impact','Ease','Fix']
    i=0
    d=div(_class='square')
    with d:
        for elt in l:
            d+=div(_s[i],':','%s'%elt)
            i+=1
            
    return d

def wildcard_to_netmasks(address_str: str, wildcard_str: str):
   

    ip_addr = ipaddress.ip_address(address_str)
    wildcard = ipaddress.ip_address(wildcard_str)

    if wildcard.version != ip_addr.version:
        raise ValueError(f"IP version mismtach: address_str({address_str}), wildcard_str({wildcard_str})")

    # default values for v4
    _length = ipaddress.IPV4LENGTH
    _net_cls = ipaddress.IPv4Network
    if wildcard.version == 6:
        # values for v6
        _length = ipaddress.IPV6LENGTH
        _net_cls = ipaddress.IPv6Network

    mask_bits = [int(b) for b in format(int(wildcard), F"0{_length}b")]

    # We keep count of zero bits position (left-most is 0)
    dont_care_bits_index = [i for i, e in enumerate(reversed(mask_bits)) if e == 1]

    # We count how many contiguous zeros are from left-most bit, and we will mask them with a netmask
    hostmask_length = 0
    for (pos, bit) in enumerate(dont_care_bits_index):
        if pos != bit:
            break
        hostmask_length += 1

    # We only keep the bits that can't be dealt with by a netmask and need to be expanded to cartesian product
    dont_care_to_expand_index = dont_care_bits_index[hostmask_length:]

    # reverse in order to have the final loop iterate last through high order bits
    dont_care_to_expand_index.reverse()

    if len(dont_care_to_expand_index) > MAX_DONT_CARE_BITS:
        raise NetmaskValueError(f"{wildcard_str} contains more than {MAX_DONT_CARE_BITS} non-contiguous wildcard bits")

    ip_int_original = int(ip_addr)
    subnets = []
    for bits_values in itertools.product((0,1), repeat=len(dont_care_to_expand_index)):
        # enforce the bits_values in the IP address
        ip_int = ip_int_original
        for (index, val) in zip(dont_care_to_expand_index, bits_values):
            sb_mask = 1 << index
            if val:
                ip_int |= sb_mask
            else:
                ip_int &= ~sb_mask

        subnets.append(_net_cls((ip_int, _length-hostmask_length), strict=False))

    return subnets

 
#function to determine interfaces that belongs to the subnet (router)
def get_interfaces(networks,parse,interfaces):
    
    
    for intf in parse.find_objects_w_child(r'^interface',r'ip\saddress'):
        for intf_obj in intf.children:

            net_addr=intf_obj.re_match_typed(r'ip\saddress\s(\d+\.\d+\.\d+\.\d+)',default="_NO_MATCH_")
            if(net_addr!="_NO_MATCH_"):
       
                for addr in networks:
                    if ipaddress.ip_address(net_addr) in ipaddress.ip_network(addr[0],strict=False):
                        interfaces.append(intf)
                        

    return interfaces

#function to determine interfaces that belongs to the subnet (firewall)
def get_interfaces_firewall(parse,network):
    interfaces=list()
    for intf in parse.find_objects_w_child(r'^interface',r'ip\saddress'):
        for intf_obj in intf.children:

            net_addr=intf_obj.re_match_typed(r'ip\saddress\s(\d+\.\d+\.\d+\.\d+)',default="_NO_MATCH_")
            if(net_addr!="_NO_MATCH_"):
               if(ipaddr.IPNetwork(network).Contains(ipaddr.IPAddress(str(net_addr.text)))):
                   interfaces.append(intf)
    return interfaces

#function to read and write data to variable rating file to exchange data between python and javascript
def r_w_ratingFile(data):
    
    with open('file.txt', 'w') as f:
    
        for i in data:
            f.write('%d \n' % i)

    with open('file.txt', 'r', encoding='utf-8') as g:
        data = [int(i) for i in g.readlines()]

    for i in data:
        print(i)
    return True