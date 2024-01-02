f = open('./Extracted_port.txt', 'r').read().replace('	Source Port:		', '').replace('-\n', '').split('\n')[:-1]

# for i in range(len(f)):
#     print(f[i])
print(f'Min: {min(f)}, Max: {max(f)}')