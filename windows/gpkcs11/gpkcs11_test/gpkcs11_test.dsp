# Microsoft Developer Studio Project File - Name="gpkcs11_test" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** NICHT BEARBEITEN **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=gpkcs11_test - Win32 final check
!MESSAGE Dies ist kein gültiges Makefile. Zum Erstellen dieses Projekts mit NMAKE
!MESSAGE verwenden Sie den Befehl "Makefile exportieren" und führen Sie den Befehl
!MESSAGE 
!MESSAGE NMAKE /f "gpkcs11_test.mak".
!MESSAGE 
!MESSAGE Sie können beim Ausführen von NMAKE eine Konfiguration angeben
!MESSAGE durch Definieren des Makros CFG in der Befehlszeile. Zum Beispiel:
!MESSAGE 
!MESSAGE NMAKE /f "gpkcs11_test.mak" CFG="gpkcs11_test - Win32 final check"
!MESSAGE 
!MESSAGE Für die Konfiguration stehen zur Auswahl:
!MESSAGE 
!MESSAGE "gpkcs11_test - Win32 Release" (basierend auf  "Win32 (x86) Console Application")
!MESSAGE "gpkcs11_test - Win32 Debug" (basierend auf  "Win32 (x86) Console Application")
!MESSAGE "gpkcs11_test - Win32 final check" (basierend auf  "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "gpkcs11_test - Win32 Release"

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
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /I "i:\src\pkcs11\libgpkcs11" /I "i:\src\pkcs11" /D "NDEBUG" /D "_MT" /D "_CONSOLE" /D "_MBCS" /D "WIN32" /YX /FD /c
# ADD BASE RSC /l 0x407 /d "NDEBUG"
# ADD RSC /l 0x407 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 gpkcs11.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386 /libpath:"c:\gpkcs11_install"
# Begin Special Build Tool
SOURCE="$(InputPath)"
PostBuild_Desc=copy test prg into package dir
PostBuild_Cmds=copy ${OutDir}\gpkcs11_test.exe c:\gpkcs11_install
# End Special Build Tool

!ELSEIF  "$(CFG)" == "gpkcs11_test - Win32 Debug"

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
# ADD BASE CPP /nologo /W3 /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /GZ /c
# ADD CPP /nologo /W3 /GX /ZI /Od /I "i:\src\pkcs11\libgpkcs11" /I "i:\src\pkcs11" /D "_DEBUG" /D "_MT" /D "_CONSOLE" /D "_MBCS" /D "WIN32" /YX /FD /GZ /c
# ADD BASE RSC /l 0x407 /d "_DEBUG"
# ADD RSC /l 0x407 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 gpkcs11.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept /libpath:"i:\src\pkcs11\windows\gpkcs11\libgpkcs11\debug" /libpath:"c:\gpkcs11_install"
# Begin Special Build Tool
OutDir=.\Debug
ProjDir=.
SOURCE="$(InputPath)"
PostBuild_Desc=copy test prg into package dir
PostBuild_Cmds=echo "copy $(OutDir)\gpkcs11_test.exe c:\gpkcs11_install"	copy  $(OutDir)\gpkcs11_test.exe c:\gpkcs11_install	echo copy  $(ProjDir)\gpkcs11_test.c c:\gpkcs11_install	copy $(ProjDir)\gpkcs11_test.c  c:\gpkcs11_install
# End Special Build Tool

!ELSEIF  "$(CFG)" == "gpkcs11_test - Win32 final check"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "gpkcs11_"
# PROP BASE Intermediate_Dir "gpkcs11_"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "final_check"
# PROP Intermediate_Dir "final_check"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /ZI /Od /I "i:\src\pkcs11\libgpkcs11" /I "i:\src\pkcs11" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /GZ /c
# ADD CPP /nologo /W3 /GX /Z7 /Od /I "i:\src\pkcs11\libgpkcs11" /I "i:\src\pkcs11" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /D "WIN32" /YX /FD /GZ /c
# ADD BASE RSC /l 0x407 /d "_DEBUG"
# ADD RSC /l 0x407 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 gpkcs11.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept /libpath:"i:\src\pkcs11\windows\gpkcs11\libgpkcs11\debug" /libpath:"c:\gpkcs11_install"
# ADD LINK32 gpkcs11.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept /libpath:"i:\src\pkcs11\windows\gpkcs11\libgpkcs11\final_check" /libpath:"c:\gpkcs11_install"
# Begin Special Build Tool
OutDir=.\final_check
ProjDir=.
SOURCE="$(InputPath)"
PostBuild_Desc=copy test prg into package dir
PostBuild_Cmds=echo "copy $(OutDir)\gpkcs11_test.exe c:\gpkcs11_install"	copy  $(OutDir)\gpkcs11_test.exe c:\gpkcs11_install	echo copy  $(ProjDir)\gpkcs11_test.c c:\gpkcs11_install	copy $(ProjDir)\gpkcs11_test.c  c:\gpkcs11_install
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "gpkcs11_test - Win32 Release"
# Name "gpkcs11_test - Win32 Debug"
# Name "gpkcs11_test - Win32 final check"
# Begin Source File

SOURCE=.\gpkcs11_test.c
# End Source File
# End Target
# End Project
