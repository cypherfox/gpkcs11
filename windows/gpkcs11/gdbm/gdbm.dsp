# Microsoft Developer Studio Project File - Name="gdbm" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** NICHT BEARBEITEN **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=gdbm - Win32 final check
!MESSAGE Dies ist kein gültiges Makefile. Zum Erstellen dieses Projekts mit NMAKE
!MESSAGE verwenden Sie den Befehl "Makefile exportieren" und führen Sie den Befehl
!MESSAGE 
!MESSAGE NMAKE /f "gdbm.mak".
!MESSAGE 
!MESSAGE Sie können beim Ausführen von NMAKE eine Konfiguration angeben
!MESSAGE durch Definieren des Makros CFG in der Befehlszeile. Zum Beispiel:
!MESSAGE 
!MESSAGE NMAKE /f "gdbm.mak" CFG="gdbm - Win32 final check"
!MESSAGE 
!MESSAGE Für die Konfiguration stehen zur Auswahl:
!MESSAGE 
!MESSAGE "gdbm - Win32 Release" (basierend auf  "Win32 (x86) Static Library")
!MESSAGE "gdbm - Win32 Debug" (basierend auf  "Win32 (x86) Static Library")
!MESSAGE "gdbm - Win32 final check" (basierend auf  "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "gdbm - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /I "$(WkspDir)\..\..\win_gdbm" /D "NDEBUG" /D "_MBCS" /D "_LIB" /D "WIN32" /D "_MT" /YX /FD /c
# ADD BASE RSC /l 0x407 /d "NDEBUG"
# ADD RSC /l 0x407 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo
# Begin Special Build Tool
OutDir=.\Release
SOURCE="$(InputPath)"
PostBuild_Desc=Kopieren der Bibliothek
PostBuild_Cmds=copy $(OutDir)\gdbm.lib c:\gpkc11_install_rel
# End Special Build Tool

!ELSEIF  "$(CFG)" == "gdbm - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /W3 /Gm /GX /ZI /Od /I "$(WkspDir)\..\..\win_gdbm" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D "WIN32" /D "_MT" /YX /FD /GZ /c
# ADD BASE RSC /l 0x407 /d "_DEBUG"
# ADD RSC /l 0x407 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo
# Begin Special Build Tool
OutDir=.\Debug
SOURCE="$(InputPath)"
PostBuild_Desc=Kopieren der Bibliothek
PostBuild_Cmds=copy $(OutDir)\gdbm.lib c:\gpkc11_install
# End Special Build Tool

!ELSEIF  "$(CFG)" == "gdbm - Win32 final check"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "gdbm___Win32_final_check"
# PROP BASE Intermediate_Dir "gdbm___Win32_final_check"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "final_check"
# PROP Intermediate_Dir "final_check"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /W3 /Gm /GX /Zi /Od /D "_DEBUG" /D "_MBCS" /D "_LIB" /D "WIN32" /YX /FD /GZ /c
# ADD BASE RSC /l 0x407 /d "_DEBUG"
# ADD RSC /l 0x407 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo
# Begin Special Build Tool
OutDir=.\final_check
SOURCE="$(InputPath)"
PostBuild_Desc=Kopieren der Bibliothek
PostBuild_Cmds=copy $(OutDir)\gdbm.lib c:\gpkcs11_install
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "gdbm - Win32 Release"
# Name "gdbm - Win32 Debug"
# Name "gdbm - Win32 final check"
# Begin Source File

SOURCE=..\..\..\win_gdbm\autoconf.h
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\bucket.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\close.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\dbm.h
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\dbmclose.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\dbmdelete.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\dbmdirfno.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\dbmfetch.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\dbminit.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\dbmopen.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\dbmpagfno.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\dbmrdonly.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\dbmseq.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\dbmstore.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\delete.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\extern.h
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\falloc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\fetch.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\findkey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\gdbm.h
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\gdbmclose.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\gdbmconst.h
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\gdbmdefs.h
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\gdbmdelete.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\gdbmerrno.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\gdbmerrno.h
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\gdbmexists.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\gdbmfdesc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\gdbmfetch.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\gdbmopen.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\gdbmreorg.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\gdbmseq.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\gdbmsetopt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\gdbmstore.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\gdbmsync.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\global.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\hash.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\ndbm.h
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\proto.h
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\seq.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\store.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\systems.h
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\update.c
# End Source File
# Begin Source File

SOURCE=..\..\..\win_gdbm\version.c
# End Source File
# End Target
# End Project
