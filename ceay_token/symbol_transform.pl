#!/usr/local/bin/perl
#
# This file is part of GPKCS11. 
# (c) 1999-2001 TC TrustCenter GmbH 
#
# GPKCS11 is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#  
# GPKCS11 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#  
# You should have received a copy of the GNU General Public License
# along with GPKCS11; see the file COPYING.  If not, write to the Free
# Software Foundation, 59 Temple Place - Suite 330, Boston, MA 02111, USA.  
#
# replace symbol in a tree of source files.
#
# symbol_transform <symbol_file> <top_dir> <prefix>
#
# The scripts takes symbols (one per line) from <symbol_file> and prepends them in all
# file found under <top_dir> with <prefix>
#

use File::Copy;

$SYMBOL_FILE=$ARGV[0];
$TOP_DIR=$ARGV[1];
$PREFIX=$ARGV[2];

print "using: SYMBOL_FILE: $SYMBOL_FILE, TOP_DIR: $TOP_DIR, PREFIX: $PREFIX\n";

# read symbols;
open(SYMS,"<$SYMBOL_FILE") || die "cannot open symbol file $SYMBOL_FILE : $!";
while(<SYMS>)
{
    chop;
    push(@all_syms,$_);
}
close(SYMS);

# no directories and no symlinks (but follow symlinks into the directory)
print "using file expression: find $TOP_DIR -follow \\( -name \"*.c\" -o -name \"*.h\" \\) -type f -print | \n";
open(FILES,"find $TOP_DIR -follow \\( -name \"*.c\" -o -name \"*.h\" \\) -type f -print |") || die "cannot start find: $!";

while(<FILES>)
{
    chop;
    $filename=$_;

    print "doing $filename:\n";
    
    # move orig out of the way if there is not alread one
    # this way we can allways re-map a directory that was allready done
    if(! -e "$filename.orig")
    {
	print "   moving $filename -> $filename.orig\n";
	rename $filename, "$filename.orig";
    }
    
    open(CURR_IN,"<$filename.orig") || die "cannot open input file $filename.orig : $!";
    open(CURR_OUT,">$filename") || die "cannot open output file $filename : $!";

    while(<CURR_IN>)
    {
	foreach $sym (@all_syms)
	{
	    s/([^_0-9a-zA-Z])($sym)([^_0-9a-zA-Z])/$1$PREFIX$2$3/g;
	}
	print CURR_OUT $_;
    }

    close(CURR_OUT);
    close(CURR_IN);
}
close(FILES);

# and now do it all over again for those windows defs (or rather their input files)
open(FILES,"find $TOP_DIR -follow -name \"*.num\" -type f -print |") || die "cannot start find: $!";
while(<FILES>)
{
    chop;
    $filename=$_;
 
    print "doing $filename:\n";
 
    # move orig out of the way if there is not alread one
    # this way we can allways re-map a directory that was allready done
    if(! -e "$filename.orig")
    {
        print "   moving $filename -> $filename.orig\n";
        rename $filename, "$filename.orig";
    }
 
    open(CURR_IN,"<$filename.orig") || die "cannot open input file $filename.orig : $!";
    open(CURR_OUT,">$filename") || die "cannot open output file $filename : $!";
 
    while(<CURR_IN>)
    {
        foreach $sym (@all_syms)
        {
            s/(\s*)($sym)(\s)/$1$PREFIX$2$3/g;
        }
        print CURR_OUT $_;
    }
 
    close(CURR_OUT);
    close(CURR_IN);
}
close(DEFS);






