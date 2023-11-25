---
title: "Fuzzing - 1"
date: 2023-10-25
description: "Basics of Blind Fuzzing"
tags: ["Fuzzing"]
type: post
weight: 20
showTableOfContents: true
---
# Fuzzers and Fuzzing



### <u>Introduction</u>
Fuzzing is a software testing method that involves sending random or unexpected input to a program to uncover vulnerabilites and bugs. The process includes generating diverse inputs, injecting them into the target software, and observing how it reacts. If the program crashes or exhibits unexpected behavior, it signals potential issues. Fuzzing is valuable for finding security vulnerabilities, and it comes in various types like random, mutation-based and generation-based fuzzing. Many organizations integrate fuzz testing into their development process to enhance software security and reliability.

### <u>How does a fuzzer works??</u>
In simple terms a fuzzer is a program written that goes on a mutuate-execute-reapeat loop and keeps on exloring the state space of the program. Point to be noted is that it does these things "randomly". Well a fuzzer doesn't actually finds an exploit but gives the paves the pathway for it. The core part of a fuzzer is the mutator itself.


### <u>So what about the output from the fuzzer!!</u>
Well considering me, someone who is like 2 days into fuzzing at the time of writing the post.I believe attaching a debugger to application we aim to fuzz is a nice way to get details about our crash, so that it becomes easy for us to understand whether it is benign or a security vulnerability.


### <u>Some Random Thoughts</u>
* We tend to aim for specific parts in a program that needs to be fuzzed.
* Old-school fuzzers are the one we are goin to look at this blogpost, which are known as blind-fuzzers.
* Fuzzers mainly look for the "low-hanging fruits", meaning easy bugs which might not be visible while manual analysis.
* Fuzzers generally take file as input to fuzz applications.


### <u>Let's Code One</u>

#### Sample Program
```
//C code


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv){
    if (argc!=2){
        return 1;
    }
    FILE *f = fopen(argv[1],"rb");
    if (f == NULL){
        return 2;
    }
    
    int w,h;
    fread(&w,4,1,f);
    fread(&h,4,1,f);
    
    unsigned char *buf = malloc(w*h);
    
    for (int j = 0; j < h; j++){
        fread(&buf[j*w],w,1,f);
    }
    
    fclose(f);
    return 0;
}
```

#### <u>Explaination</u>
1. The code reads a file and does some basic file descriptor checking.
2. It then assumes that the first 4 bytes of the file when opened in binary mode is the width and then the following 4 bytes is its height.
3. We then dynamically allocate memory and the size is the product of both width and height.  
4. Finally we just read the file data for each 'h' row and the process continues for 'w' bytes.

So we understand the code nice and clear, now the fuzz-time.

#### <u>Fuzzer - Code</u>

```
import subprocess
import random
import sys
import struct

def load_file(fname):
    with open(fname, 'rb') as f:
        return bytearray(f.read())
        
def save_file(fname, data):
    with open(fname,"wb") as f:
        f.write(str(data))

def mutate_bits(data):
    count = int((len(data)*8) * 0.01)
    if count == 0:
        count = 1
    for _ in range(count):
        bit = random.randint(0,len(data)*8 - 1)
        idx_bit = bit % 8
        idx_byte = bit / 8
        data[idx_byte] ^= 1 << idx_bit
    
    return data

def mutate_bytes(data):
    count = int(len(data) * 0.01)
    if count == 0:
        count = 1
    for _ in range(count):
        data[random.randint(0, len(data)-1)] = random.randint(0,255)
    return data

def mutate_magic(data):

    numbers = [
 (1,struct.pack("B", 0xff)),
 (1,struct.pack("B", 0x7f)),
 (1,struct.pack("B", 0)),
 (2,struct.pack("H", 0xffff)),
 (2,struct.pack("H", 0)),
 (4,struct.pack("I", 0xffffffff)),
 (4,struct.pack("I", 0)),
 (4,struct.pack("I", 0x80000000)),
 (4,struct.pack("I", 0x40000000)),
 (4,struct.pack("I", 0x7fffffff))

]

    count = int(len(data) * 0.01)
    if count == 0:
        count = 1

    for _ in range(count):
        n_size, n = random.choice(numbers)
        sz = len(data) - n_size
        if sz < 0:
            continue
        idx = random.randint(0,sz)
        data[idx:idx + n_size] = bytearray(n)
    
    return data

def mutate(data):
    return random.choice([
    mutate_bits,
    mutate_bytes,
    mutate_magic
    ])(data[::])

def run(exename):
    p = subprocess.Popen(["gdb","--batch","-x","detect.gdb",exename],
    stdout = subprocess.PIPE,
    stderr = None)
    output, _ = p.communicate()
    if "Program recieved signal" in output:
        return output.split("----+----+----+----+")[1]
    
    return None
    
input_samples = [

load_file("input.sample")

]

i = 0
while True:
     i += 1
     if True:
         sys.stdout.write(".")
         sys.stdout.flush()
    mutated_sample = mutate(random.choice(input_samples))
    save_file("test.sample", mutated_sample)
   
   output = run("program")
   if output is not None:
       print("Crash!")
       save_file("crash.samples.%i" % i, mutated_sample)
       save_file("crash.samples.%i.txt" % i, output)
       print(output)
```
#### <u>Explaination</u>
1. the bits funtions mutates individual bits in the data by randomly toggling between them.
2. First up it calculates the numbers of bits to mutate, the minimu is 1 as we have taken i% of total bits into consideration.
3. It then iterates through range of bits to be mutated, randomly selecting a bit index and calculating the respective byte index and bit index within the byte.
4. The selected bit is toggled using a bitwise XOR encryption.
5. The bytes functioniterates through the range of bytes to be muted, randomly selecting a byte index and replacing the byte with a random integer value in the range of [0,255].
6. The magic function sets some magic numbers.
7. After iterating through the range of mutations, randomly selecting a magic number from the list and replacing a portion of the data with the bytes of the chosen magic number.
8. The fuzzer code also takes into cosideration of a gdb script which does the job of logging the crashes.

#### <u>gdb-script</u>
```
set height 0
set disassembly-flavor intel
echo ----+----+----+----+
r test.sample
x/10i $rip
where
i r
echo ----+----+----+----+

```
#### <u>Explaination</u>
1. A very simple gdb-script which runs the test.sample file as an input.
2. Print the next instructions.
3. Find where the crash happened. 
4. Get the details about where in the call stack we got the error.
5. print the values of the registers at that state of crash.

#### <u>It's show time !!!</u>
Do try out the code for both the vulnerable program and the fuzzer.
Some of the resuts signify that I have error in my program and some point to internal c library .
However I would suggest you to try it and have fun!!!!.
# Happy Fuzzing
