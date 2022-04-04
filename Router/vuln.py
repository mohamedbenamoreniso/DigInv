from nvdlib import *
from dominate.tags import *
from variables import d_vulnerability

def vuln(v2severity,score):
    global d_vulnerability
    d=div()
    d+=p(v2severity)
    d+=p(score)
    d_vulnerability+=d
    return d

r = searchCVE(pubStartDate = '2021-09-08 00:00', pubEndDate = '2021-12-01 00:00', keyword = 'Cisco 15', cvssV3Severity = 'Critical', key='92db6ce5-1190-4ce3-a1aa-d8de6b33e87c')
for rr in r:
    vuln(rr.v2severity,rr.score)