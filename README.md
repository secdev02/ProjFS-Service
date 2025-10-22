# ProjFS-Service
Run A Local Deception Projected File System - Canarytoken

Sample Setup - Change .config as needed

```
PS C:\dev> Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart


Path          :
Online        : True
RestartNeeded : False



PS C:\dev> C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe .\ProjFS-Service.cs
Microsoft (R) Visual C# Compiler version 4.8.9232.0
for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240

PS C:\dev> C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe .\ProjFS-Service.exe
Microsoft (R) .NET Framework Installation utility Version 4.8.9032.0
Copyright (C) Microsoft Corporation.  All rights reserved.


Running a transacted installation.

Beginning the Install phase of the installation.
See the contents of the log file for the C:\dev\ProjFS-Service.exe assembly's progress.
The file is located at C:\dev\ProjFS-Service.InstallLog.
Installing assembly 'C:\dev\ProjFS-Service.exe'.
Affected parameters are:
   logtoconsole =
   logfile = C:\dev\ProjFS-Service.InstallLog
   assemblypath = C:\dev\ProjFS-Service.exe
Installing service WindowsFakeFileSystem...
Service WindowsFakeFileSystem has been successfully installed.
Creating EventLog source WindowsFakeFileSystem in log Application...

The Install phase completed successfully, and the Commit phase is beginning.
See the contents of the log file for the C:\dev\ProjFS-Service.exe assembly's progress.
The file is located at C:\dev\ProjFS-Service.InstallLog.
Committing assembly 'C:\dev\ProjFS-Service.exe'.
Affected parameters are:
   logtoconsole =
   logfile = C:\dev\ProjFS-Service.InstallLog
   assemblypath = C:\dev\ProjFS-Service.exe

The Commit phase completed successfully.

The transacted install has completed.
PS C:\dev> net start WindowsFakeFileSystem
The Windows Fake File System Service service is starting.
The Windows Fake File System Service service was started successfully.

PS C:\dev> dir C:\SecretsAppConfig\


    Directory: C:\SecretsAppConfig


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         12/2/2024   4:29 PM                Access Control
d-----         10/4/2025  11:29 AM                Antivirus
d-----        12/12/2024  12:29 AM                CCTV
d-----          3/6/2025  10:29 AM                Disaster Recovery
d-----          7/3/2025   1:29 AM                Firewall
d-----        10/16/2025   7:29 AM                Incident Response
d-----         9/27/2024   4:29 AM                IT Infrastructure
d-----          4/6/2025   6:29 AM                Network
d-----          8/8/2025   3:29 PM                Security Policies
d-----         7/13/2025   4:29 AM                Server
d-----         3/30/2025   4:29 PM                Training and Education
d-----          9/6/2025  11:29 PM                User Management
d-----         4/13/2025   5:29 PM                VPN
d-----         3/30/2025   9:29 PM                Vulnerability Management
d-----        10/15/2025  10:29 AM                Wireless Network


PS C:\dev>
```
