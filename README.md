# ***Welcome to User-Mode Rootkit***



## Introduction

Welcome to user-mode Rootkit project, this program is written in c/c++. <br>
This project is a demonstration of a user-mode rootkit designed strictly for educational purposes. The rootkit includes functionality for DLL injection, API hooking, and process hiding in a Windows environment. It showcases techniques for injecting a custom DLL into a process, hooking Windows API functions to alter their behavior, and concealing specific processes from the process list. This tool is intended to serve as an educational resource for understanding the mechanics of software hooking, process manipulation, and the implications of rootkit behavior on system security. <br><br>


**Warning**

The techniques demonstrated by this project are powerful and can be misused if applied maliciously. This tool is provided with the intention of advancing knowledge and should only be used in ethical hacking scenarios where explicit permission has been obtained. Misuse of this software can result in significant harm and legal consequences. By using this software, you agree to do so responsibly, ethically, and within legal boundaries.<br><br>


**Important Note: Before you proceed, it's crucial to understand and acknowledge the following:**

1. ***Purpose of the Script:*** This script is developed strictly for educational purposes. It aims to demonstrate the vulnerabilities present in wireless networks and how they can be exploited. By understanding these vulnerabilities, users can take proactive measures to enhance the security of their networks.
   
2. ***Legal Implications:*** Unauthorized access or disruption of computer networks, including wireless networks, is illegal in many jurisdictions. ***This script should only be used on networks that you own or have explicit permission to test***. Do not use this script against networks that you do not own or do not have authorization to test. Any misuse of this script is entirely the responsibility of the user.

3. ***Ethical Considerations:*** It is essential to use this script responsibly and ethically. Always respect the privacy and rights of others. Avoid causing harm or disruption to network users. The primary goal is to learn and understand network security, not to cause harm or engage in malicious activities.

4. ***Disclaimer:*** I do not endorse or encourage any illegal or malicious activities. The script is provided as-is, without any warranties or guarantees. Users are solely responsible for their actions and should use this script responsibly. <br><br>


**By accessing and using this script, you acknowledge and agree to the terms and guidelines mentioned above. Always prioritize ethical considerations, safety, and legal compliance.**
<br><br>




## Features

1. **injector:** it has a cpp file called [injector.cpp](https://github.com/eliyaballout/User_Mode_Rootkit/blob/main/injector/injector/injector.cpp), this code is responsible for injecting a custom DLL into a target process using the process ID (PID).

2. **APIHooking:** it has a cpp file called [dllmain.cpp](https://github.com/eliyaballout/User_Mode_Rootkit/blob/main/APIHooking/APIHooking/dllmain.cpp), this is a DLL file, this code is responsible for modifying the behavior of system-level API calls using Import Address Table (IAT) patching.

3. **hideInject:** it has a cpp file called [hideInject.cpp](https://github.com/eliyaballout/User_Mode_Rootkit/blob/main/hideInject/hideInject/hideInject.cpp), this code is responsible for reverting the hook, and restore the original behavior of the target process using the process ID (PID).

<br><br>




## Requirements, Installation & Usage

**I will explain here the requirements, installation and the usage of this rootkit:** <br>

**Requirements:**
1. Ensure you have a C++ compiler and Windows SDK installed.
2. You need to modify the dll path to `YOUR_APIHooking.dll_PATH`. in the cpp file [injector.cpp](https://github.com/eliyaballout/User_Mode_Rootkit/blob/main/injector/injector/injector.cpp), in line **83** `char dllPath[] = "PATH_TO_APIHooking.dll";`, you need to change the `PATH_TO_APIHooking.dll` to the path where you actually stores the APIHoooking.dll dll file, for example: `"C:\\Users\\user\\source\\repos\\injected\\x64\\Debug\\APIHooking.dll"`. Make sure to put the **absolute** path for the DLL.
3. You need to modify process name that you want to hide: in the DLL file [dllmain.cpp](https://github.com/eliyaballout/User_Mode_Rootkit/blob/main/APIHooking/APIHooking/dllmain.cpp), in line **12** `#define HIDE_PROCNAME L"notepad.exe"`, you need to change `notepad.exe` to the process that you want to hide (I did it on notepad.exe just for demonstration).
4. Compile both `.cpp` files to generate the executable and DLL files. <br><br>


**Installation:**
1. Download and extract the [ZIP file](https://github.com/eliyaballout/User_Mode_Rootkit/archive/refs/heads/main.zip).<br>
2. Navigate to **injector --> x64 --> Debug**, you will find the `injector.exe` executable file, this is the executable that you need to run in order to inject the DLL file.<br>
3. Navigate to **hideInject --> x64 --> Debug**, you will find the `hideInject.exe` executable file, this is the executable that you need to run in order to revert the hook, and restore the original behavior of the target process. <br><br>


**Usage:**

**Running the injector:**
```
injector.exe <PID>
```
where `<PID>` should be the PID of the process that you want to attack. <br><br>

**Running the hideInject:**
```
hideInject.exe <PID>
```
where `<PID>` should be the PID of the same process that you attacked, in order to revert the hook.

<br><br>




## Ethical Considerations

This tool is intended for educational use only to demonstrate techniques commonly used by rootkits. It should be used in a controlled environment, such as a penetration testing lab, where explicit permission has been granted. Always practice responsible disclosure and use ethical hacking principles.<br><br>




## Technologies Used
<img src="https://github.com/devicons/devicon/blob/master/icons/c/c-original.svg" title="c" alt="c" width="40" height="40"/>&nbsp;
<img src="https://github.com/devicons/devicon/blob/master/icons/cplusplus/cplusplus-original.svg" title="c++" alt="c++" width="40" height="40"/>&nbsp;
<br><br><br>




## Demonstration of the rootkit

**I did the demonstration on the Task Manager process and notepad for educational purposes only**
