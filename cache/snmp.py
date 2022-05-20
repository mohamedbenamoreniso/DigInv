data=[0,0,1,2,3]
with open('file.txt', 'w') as f:
    
    for i in data:
        f.write('%d \n' % i)

with open('file.txt', 'r', encoding='utf-8') as g:
    data = [int(i) for i in g.readlines()]

for i in data:
    print(i)