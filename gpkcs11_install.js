// -*- c++ -*- only for the folding mode
/////////////////////////////////////////////////////////////////////////////////////// 
//
// This file is part of GPKCS11. 
// (c) 1999-2001 TC TrustCenter for Security in DataNetworks GmbH 
//
// GPKCS11 is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2, or (at your option)
// any later version.
//  
// GPKCS11 is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//  
// You should have received a copy of the GNU Lesser General Public License
// along with GPKCS11; see the file COPYING.LIB.  If not, write to the Free
// Software Foundation, 59 Temple Place - Suite 330, Boston, MA 02111, USA.  
// 
// RCSID:       $Id$
// Source:      $Source$
// Last Delta:  $Date$ $Revision$ $Author$
// State:       $State$ $Locker$
// NAME:        gpkcs11_install.js
// SYNOPSIS:    -
// DESCRIPTION: -
// FILES:       -
// SEE/ALSO:    -
// AUTHOR:      lbe
// BUGS:        -
//
// {{{ Crypto Mechanism Flags 
CEAY_MECH_RSA_FLAG           =  0x1<<0; 
CEAY_MECH_DSA_FLAG           =  0x1<<1; 
CEAY_MECH_RC2_FLAG           =  0x1<<2; 
CEAY_MECH_RC4_FLAG           =  0x1<<3; 
CEAY_MECH_DES_FLAG           =  0x1<<4; 
CEAY_MECH_DH_FLAG            =  0x1<<5; //Diffie-Hellman 
CEAY_MECH_SKIPJACK_FLAG      =  0x1<<6; //SKIPJACK algorithm as in Fortezza cards 
CEAY_MECH_RC5_FLAG           =  0x1<<7; 
CEAY_MECH_SHA1_FLAG          =  0x1<<8; 
CEAY_MECH_MD5_FLAG           =  0x1<<9; 
CEAY_MECH_MD2_FLAG           =  0x1<<10; 
CEAY_MECH_RANDOM_FLAG        =  0x1<<27; //Random number generator 
CEAY_PUB_READABLE_CERT_FLAG  =  0x1<<28; //Stored certs can be read off the token w/o logging in 
CEAY_DISABLE_FLAG            =  0x1<<30; //tell Navigator to disable this slot by default 

// Important: 
// 0x1<<11, 0x1<<12, ... , 0x1<<26, 0x1<<29, and 0x1<<31 are reserved 
// for internal use in Navigator. 
// Therefore, these bits should always be set to 0; otherwise, 
// Navigator might exhibit unpredictable behavior. 

// These flags indicate which mechanisms should be turned on by 
var ceay_MechanismFlags = ( PKCS11_PUB_READABLE_CERT_FLAG); 
var tcsc_MechanismFlags = ( PKCS11_PUB_READABLE_CERT_FLAG); 
//////////////////////////////////////////////////////////////////////////////////////// 
// Ciphers that support SSL or S/MIME 
PKCS11_CIPHER_FORTEZZA_FLAG    = 0x1<<0; 

// Important: 
// 0x1<<1, 0x1<<2, ... , 0x1<<31 are reserved 
// for internal use in Navigator. 
// Therefore, these bits should ALWAYS be set to 0; otherwise, 
// Navigator might exhibit unpredictable behavior. 

// These flags indicate which SSL ciphers are supported 
var pkcs11CipherFlags = 0; 

// }}}
// {{{ Return values of pkcs11.addmodule() & pkcs11.delmodule() 
// success codes 
JS_OK_ADD_MODULE                 = 3; // Successfully added a module 
JS_OK_DEL_EXTERNAL_MODULE        = 2; // Successfully deleted ext. module 
JS_OK_DEL_INTERNAL_MODULE        = 1; // Successfully deleted int. module 

// failure codes 
JS_ERR_OTHER                     = -1; // Other errors than the followings 
JS_ERR_USER_CANCEL_ACTION        = -2; // User abort an action 
JS_ERR_INCORRECT_NUM_OF_ARGUMENTS= -3; // Calling a method w/ incorrect # of arguments 
JS_ERR_DEL_MODULE                = -4; // Error deleting a module 
JS_ERR_ADD_MODULE                = -5; // Error adding a module 
JS_ERR_BAD_MODULE_NAME           = -6; // The module name is invalid 
JS_ERR_BAD_DLL_NAME              = -7; // The DLL name is bad 
JS_ERR_BAD_MECHANISM_FLAGS       = -8; // The mechanism flags are invalid 
JS_ERR_BAD_CIPHER_ENABLE_FLAGS   = -9; // The SSL, S/MIME cipher flags are invalid 
JS_ERR_ADD_MODULE_DULICATE       =-10; // Module with the same name already installed 
// }}}
// {{{ bool javaInstall()
// Install the needed java class
function javaInstall() {
  // Create a version object and a software update object. 
  j_vi = new netscape.softupdate.VersionInfo(1, 0, 0, 0); 
  j_su = new netscape.softupdate.SoftwareUpdate(this, "TrustCenter Utility Java Class"); 
  // the logical name of the bundle 
  
  // Start the install process. 
  err = j_su.StartInstall("java/"+vendor+"/misc", // component folder (logical). 
			j_vi, 
			netscape.softupdate.SoftwareUpdate.FULL_INSTALL);   
  if (err!=0) { return false; }
  
  // Find out the physical location of the Program dir. 
  Java_Folder = j_su.GetFolder("Java Download"); 
  
  // Install the files. Unpack them and list where they go.
  class_name="ConfFile.class"
  err = j_su.AddSubcomponent("ConfFile", //component name (logical) 
                             j_vi, // version info 
			     class_name, // source file in JAR (physical) 
			     Java_Folder, // target folder (physical) 
			     class_name, // target path & filename (physical) 
			     true); // forces update 
  if (err != 0) { 
    errmsg = ErrorMsg(err);
    window.alert("Error adding sub-component ConfFile: "+"("+err+")"+errmsg+"\n"+
		 class_name); 
    return false; 
  }

  err = j_su.FinalizeInstall(); 
  if (err != 0) { 
    j_su.AbortInstall(); 
    errmsg = ErrorMsg(err);
    window.alert("Error adding sub-component ConfFile: "+"("+err+")"+errmsg+"\n"+
		 class_name); 
    return false; 
  }

 return true;
}
// }}}
// {{{ string ErrorMsg(err)
function ErrorMsg(errcode) {
  if (err == -900) { errmsg = "Restart the computer, and install again."; } 
  else if (err == -200) { errmsg = "Bad Package Name."; } 
  else if (err == -201) { errmsg = "Unexpected error."; } 
  else if (err == -202) { errmsg = ("Access denied. Make sure you have the "+
				    "permissions to write to the disk."); } 
  else if (err == -203) { errmsg = "Installation script was signed by more than one certificate."; } 
  else if (err == -204) { errmsg = "Installation script was not signed."; } 
  else if (err == -205) { errmsg = "The file to be installed is not signed."; } 
  else if (err == -206) { errmsg = ("The file to be installed is not present, "+
				    "or signed with a different certificate than "+
				    "the one used to sign the install script."); } 
  else if (err == -207) { errmsg = "JAR archive has not been opened."; } 
  else if (err == -208) { errmsg = "Bad arguments to AddSubcomponent( )."; } 
  else if (err == -209) { errmsg = "Illegal relative path."; } 
  else if (err == -210) { errmsg = "User cancelled installation."; } 
  else if (err == -211) { errmsg = "A problem occurred with the StartInstall( )."; }
  else { errmsg = "Unknown error\n"+
	   "(If you already have a Dummy module installed, try deleting it first.)"; } 
  
  return errmsg;
}
// }}}
// {{{ object LibInfo( comp_name, lib_name, maj, min, rev, bld)
function LibInfo( comp_name, lib_name, maj_v, min_v, rev_v, bld_v ) {
  this.component = comp_name;
  this.library = lib_name;
  this.maj = maj_v;
  this.min = min_v;
  this.rev = rev_v;
  this.bld = bld_v;
} 
// }}}
// {{{ bool WriteConfigFile()
function WriteConfigFile(name) {
  
  if(javaInstall() != true) { return false; }
  
  if(plat != "Win32")
    {
      global = window.confirm("You are installing on a Unix-style System.\n"+
			      "You may try to install the system wide configuration file\n"+
			      "For this you need the permission to create the file in\n"+
			      "\t\t/usr/local/etc/"+name+".rc\n\n"+
			      "do you want to do a system wide-installation?");
      if(global) { conffile = new Packages.ConfFile(Packages.ConfFile.Global); }
      else { conffile = new Packages.ConfFile(Packages.ConfFile.User); }
    }
  else
    conffile = new Packages.ConfFile(Packages.ConfFile.Win32);
  
  conffile.setActiveSession("PKCS11-DLL");
  conffile.setProperty("TokenList","CEAY-TOKEN TCSC-TOKEN1 TCSC-TOKEN2");
  conffile.setProperty("ExtraLibraryPath", Folder + dir);
  conffile.setProperty("LoggingLevel", "10");
  conffile.setProperty("LoggingFile", "c:\pkcs11.log");
  conffile.setProperty("MemLoggingFile", "c:\pkcs11_mem.log");
  
  conffile.setActiveSession("CEAY-TOKEN");
  conffile.setProperty("TokenDLL",Folder + dir + "\ceay_token.dll");
  conffile.setProperty("InitSym", "ceayToken_init");
  conffile.setProperty("PersistenRootDir", "c:\tmp\cert_test");

  conffile.setActiveSession("TCSC-TOKEN1");

  
  
  
  if(conffile.writeFile("gpkcs11"))
    { 
      return conffile.conf_file;
    } else {
      window.alert("could not write Configuration File '"+conffile.conf_file+"':"+conffile.reason);
     return null;
    }
}

// }}}
// {{{ bool DoInstall() return true if the install was successful
function DoInstall( lib_arr ) {
  
  // ensure that Java is enabled
  if ( !navigator.javaEnabled() ) {
    window.alert("Error activating LiveConnect! \nYou must activate Java in your Browser");
    return false;
  }

  Packages.java.lang.System.out.println("Greetings Earthlings");
  
  // Create a version object and a software update object. 
  vi = new netscape.softupdate.VersionInfo(2, 1, 1, 0); 
  su = new netscape.softupdate.SoftwareUpdate(this, "TrustCenter PKCS#11 Module"); 
  // the logical name of the bundle 
  
  // Start the install process. 
  err = su.StartInstall("pkcs11/"+vendor+"/gpkcs11", // component folder (logical). 
			vi, 
			netscape.softupdate.SoftwareUpdate.FULL_INSTALL);   
  if (err!=0) { return false; }
  
  // Find out the physical location of the Program dir. 
  Folder = su.GetFolder("Program"); 
  
  // Install the files. Unpack them and list where they go. 
  for ( i = 0 ; i < lib_arr.length ; i++)
    {
      sub_vi = new netscape.softupdate.VersionInfo(lib_arr[i].maj,
						   lib_arr[i].min,
						   lib_arr[i].rev,
						   lib_arr[i].bld);
      
      fileName = lib_arr[i].library;
      err = su.AddSubcomponent(lib_arr[i].component, //component name (logical) 
			       sub_vi, // version info 
			       archDir + "/" + fileName, // source file in JAR (physical) 
			       Folder, // target folder (physical) 
			       dir + fileName, // target path & filename (physical) 
			       true); // forces update 
      if (err != 0) { 
	errmsg = ErrorMsg(err);
	window.alert("Error adding sub-component "+lib_arr[i].component+": "+"("+err+")"+errmsg+"\n"+
		     archDir+"/"+fileName); 
	return false; 
      }
    }


  // Find out the physical location of the Program dir. 
  Folder = su.GetFolder("Program"); 

  // Write the config file. If there is a problem we still can rollback the installation
  // write before the call to the crypto modules or the DLL-Loading will fail
  conf_file = WriteConfigFile("gpkcs11");
  if(conf_file == null) {
    window.alert("Error writing config file '"+conf_file+"'"); 
    return false; 
  }
  
  // Unless there was a problem, move files to final location 
  // and update the Client Version Registry. 
  err = su.FinalizeInstall(); 
  if (err != 0) { 
    errmsg = ErrorMsg(err);
    window.alert("Error adding sub-component "+comp_name+": "+"("+err+")"+errmsg+"\n"+
		 archDir+"/"+cryptoName); 
    return false; 
  }

  return true; // All clear  
} 
// }}}

// Find out which file is to be installed depending on the platform 

// pathname seperator is platform specific 
var sep = "/"; 
var vendor = "trustcenter"; 
var moduleName = "not_supported"; 
var plat = navigator.platform; 

bAbort = false; 
if ((plat == "SunOS5.4") || (plat == "SunOS5.5.1")) { 
  /* ist das gleiche, aber wir erzeugen den Kram unter Solaris 2.5.1 */
  archDir = "solaris2.5.1"; 

  library_array = new Array( new LibInfo("gpkcs11",   "libgpkcs11.so",  2, 1, 5, 0),
			     new LibInfo("ceay_token","libceay_tok.so", 0, 5, 6, 0),
			     new LibInfo("crypto_eay","liblibeay32.so", 0, 9, 4, 0),
			     new LibInfo("tcsc_token","libtcsc_tok.so", 0, 5, 6, 0),
			     new LibInfo("tc_scard",  "libtc_scard.so", 0, 1, 0, 0),
			     new LibInfo("tcr_sni",   "libtcr_sni.so",  0, 1, 0, 0),
			     new LibInfo("tcc_sle",   "libtcc_sle.so",  0, 1, 0, 0),
			     );

} else if (plat == "Win32") { 
  archDir = "windows32"; 

  library_array = new Array( LibInfo("gpkcs11",   "gpkcs11.dll",  2, 1, 5, 0),
			     LibInfo("ceay_token","ceay_tok.dll", 0, 5, 6, 0),
			     LibInfo("crypto_eay","libeay32.dll", 0, 9, 4, 0),
			     LibInfo("tcsc_token","tcsc_tok.dll", 0, 5, 6, 0),
			     LibInfo("tc_scard",  "tc_scard.dll", 0, 1, 0, 0),
			     LibInfo("tcr_sni",   "tcr_sni.dll",  0, 1, 0, 0),
			     LibInfo("tcc_sle",   "tcc_sle.dll",  0, 1, 0, 0),
			     );
  
  sep = "\\"; 

} else if (plat == "Linux2.0") {
  archDir = "Linux2.0";

  library_array = new Array( LibInfo("gpkcs11",   "libgpkcs11.so",  2, 1, 5, 0),
			     LibInfo("ceay_token","libceay_tok.so", 0, 5, 6, 0),
			     LibInfo("crypto_eay","liblibeay32.so", 0, 9, 4, 0),
			     LibInfo("tcsc_token","libtcsc_tok.so", 0, 5, 6, 0),
			     LibInfo("tc_scard",  "libtc_scard.so", 0, 1, 0, 0),
			     LibInfo("tcr_sni",   "libtcr_sni.so",  0, 1, 0, 0),
			     LibInfo("tcc_sle",   "libtcc_sle.so",  0, 1, 0, 0),
			     );

} else { 
  window.alert("Sorry, platform "+plat+" is not supported."); 
  bAbort = true; 
} 

if (!bAbort) 
{
  // destination of module 
  var dir = "pkcs11" + sep + vendor + sep + plat + sep; 
  
  if (confirm("This script will install a cryptographic module. \n"+
	      "It may over-write older files having the same name. \n"+
	      "Do you want to continue?")) 
    { 
      
      bAbort = !DoInstall();
      if (bAbort) { 
	su.AbortInstall(); 
      } else { 
	if (err != 0) { 
	  
	  errmsg = ErrorMsg(err);
	  window.alert("Error Finalizing Install: "+"("+err+")"+errmsg); 
	  
	} else { 
	  
      	  // Platform specific full path 
	  fullpath = Folder +  "pkcs11" + sep + vendor + sep + plat + sep + fileName; 
	  
	  // Step 6: Call pkcs11.addmodule() to register the newly downloaded module 
	  moduleCommonName = "TrustCenter PKCS11 Module " + plat; 

	  result = pkcs11.addmodule(moduleCommonName, 
				    fullpath, 
				    pkcs11MechanismFlags, 
				    pkcs11CipherFlags); 
	  if (result == -10) { 
	    window.alert("New module was copied to destination, \n"+
			 "but setup failed because a module "+
			 "having the same name has been installed. \n"+
			 "Try deleting the module "+ 
			 moduleCommonName +" first.") 
	      } else if (result < 0) { 
		window.alert("New module was copied to destination, but setup failed.\n"+
			     "  Error code: " + result); 
	      } 
	} 
      }
      
    }
}






