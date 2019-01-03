import subprocess

count = 5

jit_command = './bench/jit.sh'
nojit_command = './bench/nojit.sh'
bfi_command = './bench/bfi.sh'
bff4_command = './bench/bff4.sh'

commands = [
        #jit_command,
        #nojit_command,
        #bfi_command,
        bff4_command
        ]

l = []
for command in commands:
    print(command)
    tmp = []
    for i in range(count):
        print(i)
        r = subprocess.check_output(['/usr/bin/time','-f', '%e', command] ,
                stderr=subprocess.STDOUT, shell=False)
        s = r.rstrip('\n')
        tmp.append(float(s))
    l.append((command.split('/')[-1].strip('.sh'), tmp))

for x, y in l:
    print(x)
    m = 0.0
    for z in y:
        m += z
    m /= count
    print(m)
    v = 0.0
    for z in y:
        v += (z - m) ** 2
    v /= count
    print(v)

print(l)
