# GPCSSI 2024 – Systems and Security Research Repository

This repository contains a series of low-level system programming and security research projects developed during the **Gurgaon Police Cybersecurity Summer Internship 2024** program by **Neev Datta**.  
The work explores **Windows API**, **Native API**, and **malware analysis** concepts through C, C++, and Assembly code, emphasizing the interaction between user-space processes and the underlying operating system.

---

## Overview

The repository consists of multiple independent modules focusing on:

- Windows system internals and API interaction  
- Native API research (NTDLL-level calls and structures)  
- Malware design and defensive reverse engineering (for educational and research purposes only)  
- Integration of Assembly with C/C++ for low-level operations  
- Security and process introspection techniques  

Each module demonstrates theoretical principles through practical, controlled code implementations for research and learning.

---

## Repository Structure

| Folder | Description |
|---------|-------------|
| `Native API/` | Implements and analyses low-level Windows Native API calls such as `NtCreateThreadEx` and `ZwQuerySystemInformation` |
| `Windows API/` | Demonstrates higher-level process management, DLL injection, and API hooking using Win32 APIs |
| `Malware/` | Contains proof-of-concept programs simulating malware-like behavior in a controlled research setting |
| `Assembly/` | Inline and standalone Assembly code for direct system call execution and process manipulation |

---

## Research Focus

### 1. Native API Analysis
This module examines undocumented or semi-documented Windows system calls. Functions from `ntdll.dll` are invoked directly to bypass certain Win32 abstractions, providing insight into internal OS behavior. Examples include system information enumeration, thread creation, and privilege manipulation.

### 2. Windows API Exploration
This section focuses on user-mode API-level programming and demonstrates how common system tasks—such as module enumeration, process injection, and handle manipulation—are executed using standard Windows API calls.

### 3. Malware and Reverse Engineering
The malware component implements benign proof-of-concept code that replicates techniques such as process hollowing, API hooking, and in-memory code execution. These modules are designed solely for research and defensive analysis and must only be executed in **isolated, sandboxed environments**.

### 4. Assembly Integration
Certain modules utilize x86/x64 assembly to directly interface with processor registers or system calls. This allows precise control over execution flow and demonstrates the interactions between compiled C/C++ programs and low-level system routines.

---

## Methodology

Each module follows a general structure:

1. Identify a system or API concept to investigate.  
2. Design a controlled experiment implemented in C/C++ (and optionally Assembly).  
3. Use debugging tools (x64dbg, Process Hacker, IDA) to monitor system behavior.  
4. Record observations and evaluate code stability, security implications, and potential for both legitimate and malicious use cases.  

This workflow bridges **academic research** with **applied cybersecurity** and **systems engineering**.

---

## Building and Execution

### Requirements
- Windows 10 or later  
- Visual Studio or MinGW toolchain  
- Administrative privileges for selected modules  
- Virtual machine or sandboxed environment for malware components

### Steps
```bash
git clone https://github.com/NeevtheGreat875/GPCSSI-2024.git
cd GPCSSI-2024
```
Open any module folder (e.g., `Windows API/`) and compile the code using your preferred IDE or command-line compiler.

> **Note:** Execute only within a sandboxed or virtualized environment to prevent unintended system modification.

---

## Key Learning Outcomes

- Understanding distinctions between **Native API** and **Win32 API** layers.  
- Implementing and analyzing **process injection**, **API hooking**, and **thread creation** techniques.  
- Bridging **high-level programming** with **assembly-level control**.  
- Evaluating the security implications of direct system-level code.  
- Building foundational knowledge for **malware analysis** and **OS-level debugging**.

---

## Ethical and Legal Disclaimer

All modules are designed strictly for **educational and research purposes**.  
None of the provided code is intended for malicious use. Running or modifying this code outside of a controlled environment is neither recommended nor supported.  
Users are responsible for compliance with local laws and institutional policies.

---

## Future Directions

- Comparative study of Windows and Linux system APIs  
- Development of kernel-mode drivers for privilege research  
- Integration with monitoring tools for live analysis of injected processes  
- Visualization of system call trees and API dependencies  

---

## Author

**Neev Datta**  
The Shriram Millennium School, Noida  
Researcher in Mechatronics, Cybersecurity, and System Simulation  
GitHub: [NeevtheGreat875](https://github.com/NeevtheGreat875)

---

## References

1. Microsoft Developer Documentation – Windows API and Native API references  
2. Alex Ionescu, *Windows Internals and Native API Analysis*  
3. Matt Pietrek, *Windows System Programming Techniques*  
4. Bruce Dang et al., *Practical Reverse Engineering*  
5. GPCSSI 2024 Workshop on Systems and Security Integration
