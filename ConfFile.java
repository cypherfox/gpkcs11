// -*- java -*- */
/*
 * Copyright (c) TC TrustCenter for Security in Data Networks GmbH - all rights reserved
 * RCSID:       $Id$
 * Source:      $Source$
 * Last Delta:  $Date$ $Revision$ $Author$
 * State:	$State$ $Locker$
 * NAME:	ConfFile.java
 * SYNOPSIS:	-
 * DESCRIPTION: -
 * FILES:	-
 * SEE/ALSO:	-
 * AUTHOR:	lbe
 * BUGS: *	-
 * HISTORY:	$Log$
 * HISTORY:	Revision 1.2  1998/10/12 11:19:48  lbe
 * HISTORY:	clampdown
 * HISTORY:	
 * HISTORY:	Revision 1.1  1998/08/12 09:19:24  lbe
 * HISTORY:	Initial revision
 * HISTORY:
 */

import netscape.security.*;
import java.io.*;
import java.util.*;
import java.lang.*;

/** Class generates Windows/TrustCenter style config files. 
 */
public class ConfFile 
{
  String RCSID="$Id$";
  
  public static final int Win32  =0;
  public static final int User   =1;
  public static final int Global =2;
  
  // Dictionary of sections with Dictionary of fields as 
  Dictionary sections = new Hashtable();
  Dictionary active_section = null;

  int filetype = 0;

  // file will hold the actual file that was used. It is not read by the methods.
  // This is only for calling objects to check the filename of the used file.
  public String conf_file = null;

  // in case some operation fails this will hold some info why it failed
  public String reason;

  //{{{ ConfFile(int ftype)
  /** construct a new config file
   * @param ftype type of configuration file. sets the directory into 
   *              which the file will be written
   */
  public ConfFile(int ftype)
  {
    filetype = ftype;
  }
  //}}}

  //{{{ setActiveSession(String sec_name)
  public void setActiveSession(String sec_name)
  {    
    active_section = (Dictionary)sections.get(sec_name);
    if(active_section == null)
      {
	active_section = new Hashtable();
	sections.put(sec_name,active_section);
      }
  }
  //}}}
  //{{{ setProperty(String sec_name, String property, String value)
  public void setProperty(String sec_name, String property, String value)
  {
    Dictionary curr_section = (Dictionary)sections.get(sec_name);
    if(curr_section == null)
      {
	curr_section = new Hashtable();
	sections.put(sec_name,curr_section);
      }

    curr_section.put(property,value);
  }
  //}}}
  //{{{ setProperty(String property, String value)
  /** this function sets the property in the active section.
   */
  public void setProperty(String property, String value)
  {
    active_section.put(property,value);
  }
  //}}}
  //{{{ selectConfFile(String basename)
  /** returns a filename based on the system
   */
  private String selectConfFile(String basename)
  {
    String ret_dir = null; 
    File tmp_file = null;
    String suffix = null;
    String file_sep = null;
    boolean d_create = false;

    try {
      // TODO: turn this in a file base privilege
      PrivilegeManager.enablePrivilege("UniversalPropertyRead");
      PrivilegeManager.enablePrivilege("UniversalFileRead");
      PrivilegeManager.enablePrivilege("UniversalFileWrite");
    } catch (Exception e) {
      System.err.println("Failed! Permission to read system properties denied by user.");
      e.printStackTrace();
    } 
    
    try { 
      file_sep = System.getProperty("file.separator");
      
      // write file depending on the type supplied with the constructor
      switch(filetype)
	{
	case Win32:
      System.err.println("Win32 choosen");
	  ret_dir = "c:\\winnt";
	  suffix = ".ini";
	  break;
	case User:
      System.err.println("User choosen");
	  ret_dir = System.getProperty("user.home");
      System.err.println("User.home:"+((ret_dir != null)?ret_dir:"(null)"));
	  suffix = ".rc";
	  break;
	case Global:
      System.err.println("Global choosen");
	  ret_dir = "/usr/local/etc";
	  d_create = true;
	  suffix = ".rc";
	  break;
	default:
	  System.err.println("\tFailed! Invalid file-type!");	  
	  return null;
	}

      System.err.println("trying ret_dir = "+ret_dir+" and suffix = "+suffix);	  

      tmp_file = new File(ret_dir);
      ret_dir += file_sep + basename + suffix;
      if(tmp_file.exists() && tmp_file.isDirectory())
	return ret_dir;
      else if(d_create)
	{
	  // will fail if this is a file, wich is okay
	  if(tmp_file.mkdirs())
	    // no need to check file access. If we can create the dir, 
	    // we can create the files in it
	    return ret_dir;
	  else
	    return null;
	}
      
    } catch (Exception e) {
      System.err.println("exception");
      e.printStackTrace(System.err);
    }

    return null;
  }
  //}}}
  //{{{ boolean writeFile(String basename)
  /** Write the configuration to disk.
   * to avoid others turining this into a disk-killer, the 
   * calling application may only provide a basename of the config file.
   * the function selects the actual name of the file itself.
   */
  public boolean writeFile(String basename)
  {
    String line_sep = null;
    String filename = null;
    FileWriter file = null;
    PrintWriter printer= null;
    Enumeration iter1= null, iter2 = null;
    String key = null, sec_name=null;
    Dictionary curr_section = null;

    System.err.println("setting filename (basename: "+basename+")");
    filename = selectConfFile(basename);
    if(filename == null) 
      {
	conf_file = null;
	return false;
      }
    System.err.println("done setting filename:"+filename);

    try {
      PrivilegeManager.enablePrivilege("UniversalPropertyRead");
      PrivilegeManager.enablePrivilege("UniversalFileWrite");
    } catch (netscape.security.ForbiddenTargetException e) {
      reason = "cannot open file '"+filename+"': "+e.getMessage();
      System.err.println("\tFailed! Permission to read system properties denied by user.");
      e.printStackTrace();
    }

    System.err.println("Got here1");
    line_sep = System.getProperty("line.separator");

    try {
      file = new FileWriter(filename);
    } catch(java.io.IOException ioe) { 
      reason = "cannot open file '" + filename + "': " + ioe.getMessage();
      System.err.println("cannot open file '"+filename+"': "+ioe.getMessage());
      ioe.printStackTrace();
    }
    printer = new PrintWriter(file);
    
    System.err.println("Got here2");

    // for each section
    for(iter1 = sections.keys(); iter1.hasMoreElements();)
      {
	sec_name = (String)iter1.nextElement();
	curr_section = (Dictionary)sections.get(sec_name);
        System.err.println("Got here2.1");

	printer.print("\n["+sec_name+"]"+line_sep);

	// for each property	
	for(iter2 = curr_section.keys();iter2.hasMoreElements();)
	{
	  key = (String)iter2.nextElement();
	  printer.print(key+" = "+(String)curr_section.get(key)+line_sep);
	}
      }
    System.err.println("Got here3");

    printer.print(line_sep);

    printer.flush();
    printer.close();

    conf_file = filename;
    return true;
  }
  //}}}
}

/*
 * Local variables:
 * folded-file: t
 * end:
 */
