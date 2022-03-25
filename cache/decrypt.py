import re
import numpy as np
import pandas as pd

xlat = [0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64
, 0x4a, 0x4b, 0x44, 0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39, 0x38, 0x33, 0x34, 0x6e, 0x63,
0x78, 0x76, 0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37]

def decrypt_type7(ep):
	"""
	Based on http://pypi.python.org/pypi/cisco_decrypt/
	Regex improved
	"""
	dp = ''
	regex = re.compile('(^[0-9A-Fa-f]{2})([0-9A-Fa-f]+)')
	result = regex.search(ep)
	s, e = int(result.group(1)), result.group(2)
	for pos in range(0, len(e), 2):
		magic = int(e[pos] + e[pos+1], 16)
		if s <= 50:
			# xlat length is 51
			newchar = '%c' % (magic ^ xlat[s])
			s += 1
		if s == 51: s = 0
		dp += newchar
	return dp


# Python program to check validation of password
# Module of regular expression is used with search()
import re
password = "4aa4(fgG"
def c(password):
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
		elif not re.search("[_()@$]", password):
			flag = -1
			break
		elif re.search("\s", password):
			flag = -1
			break
		else:
			flag = 0
			return True
			break

	if flag ==-1:
		return False
num = np.array([
				[ 0.17899619,  0.33093259,  0.2076353,   0.06130814],
                [ 0.20392888,  0.42653105,  0.33325891,  0.10473969],
                [ 0.17038247,  0.19081956,  0.10119709,  0.09032416],
                [-0.10606583, -0.13680513, -0.13129103, -0.03684349],
                [ 0.20319428,  0.28340985,  0.20994867,  0.11728491],
                [ 0.04396872,  0.23703525,  0.09359683,  0.11486036],
                [ 0.27801304, -0.05769304, -0.06202813,  0.04722761]
				])

days = ['5 days', '10 days', '20 days', '60 days']



df = pd.DataFrame(num,  columns=days)
print(df)

html = df.to_html()

with open("file.html","w") as f:
	f.write(html)
