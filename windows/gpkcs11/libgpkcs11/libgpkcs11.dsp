# Microsoft Developer Studio Project File - Name="libgpkcs11" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** NICHT BEARBEITEN **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=libgpkcs11 - Win32 final check
!MESSAGE Dies ist kein gültiges Makefile. Zum Erstellen dieses Projekts mit NMAKE
!MESSAGE verwenden Sie den Befehl "Makefile exportieren" und führen Sie den Befehl
!MESSAGE 
!MESSAGE NMAKE /f "libgpkcs11.mak".
!MESSAGE 
!MESSAGE Sie können beim Ausführen von NMAKE eine Konfiguration angeben
!MESSAGE durch Definieren des Makros CFG in der Befehlszeile. Zum Beispiel:
!MESSAGE 
!MESSAGE NMAKE /f "libgpkcs11.mak" CFG="libgpkcs11 - Win32 final check"
!MESSAGE 
!MESSAGE Für die Konfiguration stehen zur Auswahl:
!MESSAGE 
!MESSAGE "libgpkcs11 - Win32 Release" (basierend auf  "Win32 (x86) Dynamic-Link Library")
!MESSAGE "libgpkcs11 - Win32 Debug" (basierend auf  "Win32 (x86) Dynamic-Link Library")
!MESSAGE "libgpkcs11 - Win32 final check" (basierend auf  "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libgpkcs11 - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "i:\src\pkcs11\libgpkcs11" /I "i:\src\pkcs11" /D "NDEBUG" /D "NO_MEM_LOGGING" /D "_MT" /D "_WINDOWS" /D "WIN32" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o /win32 "NUL"
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o /win32 "NUL"
# ADD BASE RSC /l 0x407 /d "NDEBUG"
# ADD RSC /l 0x407 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386 /out:"release\gpkcs11.dll"
# Begin Special Build Tool
OutDir=.\Release
SOURCE="$(InputPath)"
PostBuild_Desc=Kopieren der DLLs in install Verzeichniss
PostBuild_Cmds=copy  $(OutDir)\gpkcs11.dll c:\gpkcs11_install_rel
# End Special Build Tool

!ELSEIF  "$(CFG)" == "libgpkcs11 - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /GX /Zi /Od /I "i:\openssl_install\include" /I "i:\src\pkcs11\libgpkcs11" /I "i:\src\pkcs11" /D "_DEBUG" /D "_MT" /D "_WINDOWS" /D "WIN32" /YX /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o /win32 "NUL"
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o /win32 "NUL"
# ADD BASE RSC /l 0x407 /d "_DEBUG"
# ADD RSC /l 0x407 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /incremental:no /debug /machine:I386 /out:"debug\gpkcs11.dll" /pdbtype:sept
# Begin Special Build Tool
SOURCE="$(InputPath)"
PostBuild_Desc=Kopieren der DLLs in install Verzeichniss
PostBuild_Cmds=copy i:\src\pkcs11\windows\gpkcs11\libgpkcs11\debug\gpkcs11.dll  c:\gpkcs11_install
# End Special Build Tool

!ELSEIF  "$(CFG)" == "libgpkcs11 - Win32 final check"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "libgpkcs11___Win32_final_check"
# PROP BASE Intermediate_Dir "libgpkcs11___Win32_final_check"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "final_check"
# PROP Intermediate_Dir "final_check"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /GX /ZI /Od /I "i:\openssl_install\include" /I "i:\src\pkcs11\libgpkcs11" /I "i:\src\pkcs11" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /GX /Zi /Od /I "i:\openssl_install\include" /I "i:\src\pkcs11\libgpkcs11" /I "i:\src\pkcs11" /D "_DEBUG" /D "_WINDOWS" /D "WIN32" /YX /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o /win32 "NUL"
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o /win32 "NUL"
# ADD BASE RSC /l 0x407 /d "_DEBUG"
# ADD RSC /l 0x407 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /incremental:no /debug /machine:I386 /out:"debug\gpkcs11.dll" /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /incremental:no /debug /machine:I386 /out:"final_check\gpkcs11.dll" /pdbtype:sept
# Begin Special Build Tool
OutDir=.\final_check
SOURCE="$(InputPath)"
PostBuild_Desc=Kopieren der DLLs in install Verzeichniss
PostBuild_Cmds=copy $(OutDir)\gpkcs11.lib  c:\gpkcs11_install	copy $(OutDir)\gpkcs11.exp  c:\gpkcs11_install	copy $(OutDir)\gpkcs11.dll  c:\gpkcs11_install
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "libgpkcs11 - Win32 Release"
# Name "libgpkcs11 - Win32 Debug"
# Name "libgpkcs11 - Win32 final check"
# Begin Source File

SOURCE=..\..\..\libgpkcs11\cryptoki.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\decrypt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\digest.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\dll_wrap.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\dual.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\encrypt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\error.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\error.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\fkt_dummy.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\fkt_dummy.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\getInfo.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\hash.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\hash.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\init.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\init.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\internal_def.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\internal_slot.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\key_mng.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\mutex.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\mutex.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\obj_defaults.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\objects.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\objects.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\other_fkts.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\pkcs11.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\pkcs11f.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\pkcs11t.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\random.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\sessions.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\sign.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\slot.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\slot.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\thread.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\utils.c
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\utils.h
# End Source File
# Begin Source File

SOURCE=..\..\..\libgpkcs11\verify.c
# End Source File
# End Target
# End Project
