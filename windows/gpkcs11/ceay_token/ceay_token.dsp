# Microsoft Developer Studio Project File - Name="ceay_token" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** NICHT BEARBEITEN **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=ceay_token - Win32 final check
!MESSAGE Dies ist kein gültiges Makefile. Zum Erstellen dieses Projekts mit NMAKE
!MESSAGE verwenden Sie den Befehl "Makefile exportieren" und führen Sie den Befehl
!MESSAGE 
!MESSAGE NMAKE /f "ceay_token.mak".
!MESSAGE 
!MESSAGE Sie können beim Ausführen von NMAKE eine Konfiguration angeben
!MESSAGE durch Definieren des Makros CFG in der Befehlszeile. Zum Beispiel:
!MESSAGE 
!MESSAGE NMAKE /f "ceay_token.mak" CFG="ceay_token - Win32 final check"
!MESSAGE 
!MESSAGE Für die Konfiguration stehen zur Auswahl:
!MESSAGE 
!MESSAGE "ceay_token - Win32 Release" (basierend auf  "Win32 (x86) Dynamic-Link Library")
!MESSAGE "ceay_token - Win32 Debug" (basierend auf  "Win32 (x86) Dynamic-Link Library")
!MESSAGE "ceay_token - Win32 final check" (basierend auf  "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ceay_token - Win32 Release"

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
# ADD CPP /nologo /MT /W3 /GX /O2 /I "i:\src\pkcs11\libgpkcs11" /I "i:\src\pkcs11" /I "i:\src\pkcs11\win_gdbm" /I "i:\src\pkcs11\ceay_token\openssl\include" /D "NDEBUG" /D "_WINDOWS" /D "WIN32" /D "_MT" /D "NO_MEM_LOGGING" /FD /c
# SUBTRACT CPP /YX
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x407 /d "NDEBUG"
# ADD RSC /l 0x407 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 ws2_32.lib libeay32.lib gdbm.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386 /nodefaultlib:"libcd.lib" /out:"release\ceay_tok.dll" /libpath:"c:\gpkcs11_install"
# SUBTRACT LINK32 /incremental:yes
# Begin Special Build Tool
OutDir=.\Release
SOURCE="$(InputPath)"
PostBuild_Desc=kopieren der libs nach dem erstellen
PostBuild_Cmds=copy $(OutDir)\ceay_tok.dll c:\gpkcs11_install_rel	copy $(OutDir)\ceay_tok.exp c:\gpkcs11_install_rel	copy $(OutDir)\ceay_tok.lib c:\gpkcs11_install_rel
# End Special Build Tool

!ELSEIF  "$(CFG)" == "ceay_token - Win32 Debug"

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
# ADD CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "i:\src\pkcs11\libgpkcs11" /I "i:\src\pkcs11" /I "i:\src\pkcs11\win_gdbm" /I "i:\src\pkcs11\ceay_token\openssl\include" /D "_DEBUG" /D "_WINDOWS" /D "WIN32" /D "_MT" /FD /c
# SUBTRACT CPP /YX
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x407 /d "_DEBUG"
# ADD RSC /l 0x407 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 gdbm.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /incremental:no /debug /machine:I386 /out:"ceay_tok.dll" /pdbtype:sept /libpath:"c:\gpkcs11_install"
# Begin Special Build Tool
OutDir=.\Debug
SOURCE="$(InputPath)"
PostBuild_Desc=kopieren der libs nach dem erstellen
PostBuild_Cmds=cp $(OutDir)/ceay_tok.dll c:\gpkcs11_install	cp $(OutDir)/ceay_tok.exp c:\gpkcs11_install	cp $(OutDir)/ceay_tok.ib c:\gpkcs11_install
# End Special Build Tool

!ELSEIF  "$(CFG)" == "ceay_token - Win32 final check"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "ceay_token___Win32_final_check"
# PROP BASE Intermediate_Dir "ceay_token___Win32_final_check"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "final_check"
# PROP Intermediate_Dir "final_check"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /I "i:\src\pkcs11\libgpkcs11" /I "i:\src\pkcs11" /I "i:\src\pkcs11\win_gdbm" /I "i:\src\pkcs11\ceay_token\openssl\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FD /c
# SUBTRACT BASE CPP /YX
# ADD CPP /nologo /W3 /Gm /GX /Zi /Od /I "i:\src\pkcs11\libgpkcs11" /I "i:\src\pkcs11" /I "i:\src\pkcs11\win_gdbm" /I "i:\src\pkcs11\ceay_token\openssl\include" /D "_DEBUG" /D "_WINDOWS" /D "WIN32" /FD /c
# SUBTRACT CPP /YX
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x407 /d "_DEBUG"
# ADD RSC /l 0x407 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /incremental:no /debug /machine:I386 /out:"ceay_tok.dll" /pdbtype:sept
# ADD LINK32 ws2_32.lib libeay32.lib gdbm.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib /nologo /subsystem:windows /dll /incremental:no /debug /machine:I386 /out:"final_check\ceay_tok.dll" /pdbtype:sept /libpath:"c:\gpkcs11_install" /libpath:"i:\src\pkcs11\windows\gpkcs11\openssl\final_check"
# SUBTRACT LINK32 /nodefaultlib
# Begin Special Build Tool
OutDir=.\final_check
SOURCE="$(InputPath)"
PostBuild_Desc=kopieren der libs nach dem erstellen
PostBuild_Cmds=copy $(OutDir)\ceay_tok.dll c:\gpkcs11_install	copy $(OutDir)\ceay_tok.exp c:\gpkcs11_install	copy $(OutDir)\ceay_tok.lib c:\gpkcs11_install
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "ceay_token - Win32 Release"
# Name "ceay_token - Win32 Debug"
# Name "ceay_token - Win32 final check"
# Begin Source File

SOURCE=..\..\..\ceay_token\ceay_token.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ceay_token\ceay_token.h
# End Source File
# Begin Source File

SOURCE=..\..\..\ceay_token\cryptdb.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ceay_token\cryptdb.h
# End Source File
# Begin Source File

SOURCE=..\..\..\ceay_token\ctok_mem.c
# End Source File
# Begin Source File

SOURCE=..\..\..\ceay_token\ctok_mem.h
# End Source File
# Begin Source File

SOURCE=..\..\..\ceay_token\TCCGenKey.h
# End Source File
# End Target
# End Project
