import sys
from termcolor import colored
#never change this path 
sys.path.extend(('./Router','./Switch','./Firewall'))
from variables import *
print("the device is {} and the file name is {}".format(device_type,file_name))
from func import *
glob_str="\nStart Auditing in Global configuration mode\n"
intf_str="Start Auditing in Interfaces configuration\n"
vul_str="Start auditing vulnerabilities\nAlmost done,DigInv is creating your report..... "
if device_type=="router":
        print(colored(glob_str,'red'))
        from Router.GlobAudit import *
        print(colored(intf_str,'green'))
        from Router.IntfAudit import *
        print(vul_str)
        from vulnerabilityAudit import *
elif device_type=="switch":
        print(colored(glob_str,'red'))
        from Switch.GlobAudit import *
        print(colored(intf_str,'green'))
        from Switch.IntAudit import *
        print(vul_str)
        from vulnerabilityAudit import *
elif device_type=="firewall":
        print(colored(glob_str,'red'))
        from Firewall.GlobAudit import *
        print(colored(intf_str,'green'))
        from Firewall.IntAudit import *
        print(vul_str)
        from vulnerabilityAudit import *
       



from dominate import *
from dominate.tags import *
from dominate.util import raw
from datetime import date
import matplotlib.pyplot as plt
import numpy as np





#get current datetime
_date_time=str(date.today())

#create the HTML report with dominate
report = document(title="DigInv")



with report.head:
        link(rel='stylesheet', href='style.css')


        
report+=h1("DigInv")
report+=h1("Audit report")
report+=h4(_date_time)
report+=h3("Summary")
report+=p("DigInv performed an audit on %s of the network device detailed in the scope.The audit consisted of the following components:"%_date_time)
names=["a best practice security audit (Part 2)","a software vulnerability audit report (Part 3)"]
links=["#part2","#part3","#part4"]
menu_itmes=zip(names,links)

report+=ul(li(a(name, href=link), __pretty=False) for name, link in menu_itmes)
report+=h3("scope")
hostname=parse.find_objects(r'hostname')[0]
hostname=hostname.re_match_typed(r'hostname\s(\S+)')
versio_os=parse.find_objects(r'ersion')[0]
versio_os=versio_os.re_match_typed(r'ersion\s(\d+\.\d+)')
version=versio_os
report+=raw(build_table([[hostname,device_type,versio_os]],["Name","Device","OS"]))


sec_sum=CRITICAL_RATING+HIGH_RATING+MEDUIM_RATING+LOW_RATING+INFORMATIONAL_RATING

report+=h2("Security Audit Summary")
report+=p("DigInv  performed a security audit of the device detailed in the scope and identified %s security-related issues. Each of the issues identified is described in greater detail in the main body of this report."%sec_sum)
#report+=p("DigInv can draw the following statistics from the results of this security assessment, (percentages have been rounded). %s issue(s) (%s %) was rated as critical, %s issues (%s%) were rated as high, %s issues (%s%) were rated as medium, %s issues (%s%) were rated as low and %s issues (%s%) were rated as informational."%CRITICAL_RATING %(CRITICAL_RATING/sec_sum)*100 %HIGH_RATING %(HIGH_RATING/sec_sum)*100 %MEDUIM_RATING %(MEDUIM_RATING/sec_sum)*100 %LOW_RATING %(LOW_RATING/sec_sum)*100 %INFORMATIONAL_RATING %(INFORMATIONAL_RATING/sec_sum)*100)
#report+=p("DigInv can draw the following statistics from the results of this security assessment, {} issue(s) ({}%)  was rated as critical, {} issues ({}%) were rated as high, {} issues ({}%) were rated as medium, {} issues ({}%) were rated as low and {} issues ({}%) were rated as informational.".format(CRITICAL_RATING ,(CRITICAL_RATING/sec_sum)*100 ,HIGH_RATING ,(HIGH_RATING/sec_sum)*100 ,MEDUIM_RATING ,(MEDUIM_RATING/sec_sum)*100 ,LOW_RATING ,(LOW_RATING/sec_sum)*100 ,INFORMATIONAL_RATING ,(INFORMATIONAL_RATING/sec_sum)*100))
y = np.array([CRITICAL_RATING, HIGH_RATING, MEDUIM_RATING, LOW_RATING, INFORMATIONAL_RATING])
mylabels = ["CRITICAL", "HIGH", "MEDIUM", "LOW","INFORMATIONNAL"]


#plt.pie(y,labels=mylabels)

#plt.savefig('cache/graph.png',bbox_inches='tight',transparent=True)

#report+=img(src="./cache/graph.png")

report+=h2("Contents")
contents=div(_class="contents")

your_report=div()

your_report+=h5("1 Your Report")
your_report_s=div()
your_report_s+=h5("1.1 Introduction",_class="rp_section")
#your_report_s+=h5("1.2 Evaluation Use Only",_class="rp_section")
your_report+=your_report_s
contents+=your_report

Security_Audit=div(_class="Security_Audit")
Security_Audit+=h5("2.1 Introduction")
globalaudit=div(_class="globalaudit")

intf_audit=div(_class="intf_section")
globalaudit+=h5("2.2 Global Audit")

interfaceaudit=div()
i=1
for sec in global_list_sec_audit:
        globalaudit+=h5("2.2.{} {}".format(i,sec))
        i+=1

interfaceaudit+=h5("2.3 Interface Audit")
i=1
for sec in intf_list_sec_audit:
        intf_audit+=h5("2.3.{} {}".format(i,sec))
        i+=1
interfaceaudit+=intf_audit
Security_Audit+=globalaudit
Security_Audit+=interfaceaudit
Security_Audit+=h5("3. Vulnerability Audit")

vulnerability_audit=div()
i=1
for cve in cve_list:
        vulnerability_audit+=h5("3.{} {}".format(i,cve))
        i=i+1
        

#list of vuln audit
Security_Audit+=vulnerability_audit

#list of report configuration


contents+=Security_Audit
report+=contents

#start generation body report
report+=h2("1. Your Report")
report+=h3("1.1 Introduction")
report+=p("This report was produced by DigInv on %s. This report is comprised of the following sections:"%_date_time)
names=["a security audit section which details any identified \
        security-related issues. Each security issue identified includes details of what was found together with the impact of the issue, \
        how easy it would be for an attacker to exploit and a recommendation. \
        The recommendations may include alternatives and, where relevant, the commands to resolve the issue;"
        ,"a software vulnerability audit section that provides a comparison of the device software versions against a database of known vulnerabilities. In addition to a \
        brief description, each potential vulnerability includes a score and references to more specific information provided by the device manufacturers and \
        third parties;",
        "a configuration report which details the configuration settings of all the audited devices in an easy to read format. The configuration settings are divided in to \
report sub-sections which group related settings together and provide additional information about their purpose;"
        ]
report+=ul(li(name) for name in names)

report+=h2("2 Security Audit")
report+=p("DigInv performed a security audit on %s of the device detailed in the Table below."%_date_time)
report+=raw(build_table([[hostname,device_type,versio_os]],["Device","Name","OS"]))

report+=h2("2.1.1 Security Issue Overview")
report+=p("Each security issue identified by DigInv is described with a finding, the impact of the issue, how easy it would be for an attacker to exploit the issue and a recommendation.")
report+=h4("Issue Finding")
report+=p("The issue finding describes what DigInv identified during the security audit. Typically, the finding will include background information on what particular configuration settings are prior to describing what was found.")
report+=h4("Issue Impact")
report+=p("The issue impact describes what an attacker could achieve from exploiting the security audit finding. However, it is worth noting that the impact of an issue can often be influenced by other configuration settings, \
        which could heighten or partially mitigate the issue. For example, a weak password could be partially \
        mitigated if the access gained from using it is restricted in some way.")
report+=h4("Issue Ease")
report+=p("The issue ease describes the knowledge, skill, level of access and time scales that would be required by an attacker in order to exploit an issue. The issue ease will describe, where relevant, if any Open Source or commercially available tools could be used to exploit an issue.")
report+=h4("Issue Recommandation")
report+=p("Each issue includes a recommendation section which describes the steps that DigInv recommends should be taken in order to mitigate the issue. The recommendation includes, where relevant, the commands that can be used to resolve the issue.")

report+=h2("2.1.2 Rating System Overview")
report+=p("Each issue identified in the security audit is rated against both the impact of the issue and how easy it would be for an attacker to exploit. The fix rating provides \
a guide to the effort required to resolve the issue. The overall rating for the issue is calculated based on the issue's impact and ease ratings.")
report+=h4("Impact Rating")
report+=p("An issue's impact rating is determined using the criteria outlined in the Table below.")
_header=["Rating","Description"]
description_rating=[ 
                
                ["CRITICAL",
                "These issues can pose a very significant security threat. The issues that have a critical impact are typically those that would allow an attacker to gain full administrative access to the device. For a firewall device, allowing all traffic to pass through the device unfiltered would receive this rating as filtering traffic to protect other devices is the primary purpose of a firewall."],
                [ "HIGH",
                "These issues pose a significant threat to security, but have some limitations on the extent to which they can be abused. User level access to a device and a DoS vulnerability in a critical service would fall into this category. A firewall device that allowed significant unfiltered access, such as allowing entire subnets through or not filtering in all directions, would fall into this category. A router that allows significant modification of its routing configuration would also fall into this category."],
                ["MEDIUM",
                "These issues have significant limitations on the direct impact they can cause. Typically, these issues would include significant information leakage issues, less significant DoS issues or those that provide significantly limited access. An SNMP service that is secured with a default or a dictionary-based community string would typically fall into this rating, as would a firewall that allows unfiltered access to a range of services on a device."],
                ["LOW",
                "These issues represent a low level security threat. A typical issue would involve information leakage that could be useful to an attacker, such as a list of users or version details"],
                
                ["INFORMATIONAL",
                "These issues represent a very low level of security threat. These issues include minor information leakage, unnecessary services or legacy protocols that present no real threat to security"],
                
                ]
report+=raw(build_table(description_rating,_header))
report+=h4("Ease Rating")
report+=p("An issue's ease rating is determined using the criteria outlined in the Table below.")
description_rating=[
        ["TRIVIAL","The issue requires little-to-no knowledge on behalf of an attacker and can be exploited using standard operating system tools. A firewall device which had a network filtering configuration that enables traffic to pass through would fall into this category."],
        ["EASY","The issue requires some knowledge for an attacker to exploit, which could be performed using standard operating system tools or tools downloaded from the Internet. An administrative service without or with a default password would fall into this category, as would a simple software vulnerability exploit."],
        ["MODERATE","The issue requires specific knowledge on behalf of an attacker. The issue could be exploited using a combination of operating system tools or publicly available tools downloaded from the Internet."],
        ["CHALLENGE","A security issue that falls into this category would require significant effort and knowledge on behalf of the attacker. The attacker may require specific physical access to resources or to the network infrastructure in order to successfully exploit the vulnerability. Furthermore, a combination of attacks may be required."],
        ["N/A","The issue is not directly exploitable. An issue such as enabling legacy protocols or unnecessary services would fall into this rating category."]
        ]
report+=raw(build_table(description_rating,_header))
report+=h4("Fix Rating")
description_rating=[
        ["INVOLVED","The resolution of the issue will require significant resources to resolve and is likely to include disruption to network services, and possibly the modification of other network device configurations. The issue could involve upgrading a device's OS and possible modifications to the hardware."],
        ["PLANNED","The issue resolution involves planning, testing and could cause some disruption to services. This issue could involve changes to routing protocols and changes to network filtering."],
        ["QUICK","The issue is quick to resolve. Typically this would just involve changing a small number of settings and would have little-to-no effect on network services."],
     
]
report+=p("An issue's fix rating is determined using the criteria outlined in the Table below.")
report+=raw(build_table(description_rating,_header))
report+=h2("Global Audit")
report+=d_globaudit
report+=h2("Interfaces Audit")
report+=d_intfaudit
#the vulnerability section
report+=h2("Vulnerabilty Audit")
report+=d_vulnerability


with open(report_name+".html","w") as f:
        f.write(report.render())
glob_list=list(set(glob_list))

import webbrowser
webbrowser.open('file://' + os.path.realpath(report_name+".html"))


if(pdf):
        import pdfkit
        pdfkit.from_file(report_name+'.html', report_name+'.pdf')
        



