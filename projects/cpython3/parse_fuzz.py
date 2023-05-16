import subprocess
from multiprocessing import Process

def fuzz(harness, corpus):
    start_time=time.time()
    with subprocess.Popen(f'{harness} {corpus}', shell=True, stderr=subprocess.PIPE, encoding="utf-8",
	    executable='/bin/bash') as proc:
	f = open(f'results/{harness}.log', "w+")
	for line in proc.stderr:
	    if 'NEW' in line:
	        start_time=time.time()
	    new_time=int(time.time()-start_time)
	    f.write("Last new path:"+str(new_time)+'sec '+line)
	    if new_time>=7200:
	        break

corpus_find_cmd = subprocess.run("cat product/*.toml | grep 'corpus' | awk -F'\"' '{print $2}'", capture_output=True,shell=True)
corpus_list=corpus_find_cmd.stdout.split()
harness_find_cmd = subprocess.run("cat product/fuzz_tests.txt", capture_output=True,shell=True)
harness_list=harness_find_cmd.stdout.split()

procs = []
#Run parallel fuzzing
for i in range(len(corpus_list)):
    proc = Process(target=fuzz, args=(harness_list[i], corpus_list[i]))
    procs.append(proc)
    proc.start() 

for proc in procs:
    proc.join() 
