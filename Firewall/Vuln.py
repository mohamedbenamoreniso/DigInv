from nvdlib import *
from dominate.tags import *
from variables import d_vulnerability

def vuln(score):
    global d_vulnerability
    d=div()
    
    d+=p(score)
    d_vulnerability+=d
    return d

r = searchCVE(keyword = 'cisco asa 10', key='92db6ce5-1190-4ce3-a1aa-d8de6b33e87c')
for rr in r:
    try:
        vuln(rr.score)
        vuln(rr.cve.description.description_data[0].value)
    except:
        pass