import subprocess

count = 1

jit_command = './bench/jit.sh'
nojit_command = './bench/nojit.sh'
bfi_command = './bench/bfi.sh'

commands = [
        jit_command,
        nojit_command,
        bfi_command,
        ]

for command in commands:
    cnt = 0.0
    for i in range(count):
        r = subprocess.check_output(['/usr/bin/time','-f', '%e', command] ,
                stderr=subprocess.STDOUT, shell=False)
        s = r.rstrip('\n')
        cnt += float(s)

    print(command.split('/')[-1].strip('.sh'), cnt / count)
