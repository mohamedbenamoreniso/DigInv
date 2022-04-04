import json


from dominate.tags import *


#initialise glob json
def init():

    # list that contain all audits found in the global security audit
    global_list_sec_audit = list()

    with open('securityaudits.json') as json_file_glob:

        global audits
        
        audits = json.load(json_file_glob)
#initialise intf json
def init_securityaudits_intf():

    #list that contain all audits found in the interface audit
    intf_list_sec_audit = list()

    with open('securityaudits_intf.json') as json_file_intf:

        global audits_intf

        audits_intf=json.load(json_file_intf)
#initialise device configuration json
def init_device_conf():

    with open('device_conf.json') as json_conf_file:

        global device_conf

        device_conf=json.load(json_conf_file)

   


    
