import json
import settings
from dominate.tags import *
from dominate.util import raw
import pandas as pd

from func import build_table


#data is ready !!
settings.init_device_conf()
d_device_conf=div(_class="device_conf")
device_conf=settings.device_conf
data=list()

for key in device_conf['General']:
    l=list()
    if(key!='header'):
        l.extend((key,device_conf['General'][key]))
        data.append(l)
  
d_device_conf+=raw(build_table(data,device_conf['General']['header']))






