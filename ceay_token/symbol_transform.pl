#!/usr/local/bin/perl

use File::Copy;
#
# replace symbol in a tree of source files.
#
# symbol_transform <symbol_file> <top_dir> <prefix>
#
# The scripts takes symbols (one per line) from <symbol_file> and prepends them in all
# file found under <top_dir> with <prefix>
#

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






