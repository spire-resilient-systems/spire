#!/usr/bin/perl -w

# Make the Copyright notices in Spread appear and disappear

sub remove_notice_from_file()
{
    my ($filename, $notice_file) = @_;
    my ($newfilename, $line, $ln, @notice_lines, $mode, $first_line, $n_size, $f_size);
    
    open(NOTICE, "< $notice_file") or die "can't open $notice_file: $!";
    @notice_lines = <NOTICE>;
    close(NOTICE);

    open(IN, "< $filename") or die "can't open $filename: $!";
    @file_lines = <IN>;
    $mode = (stat IN)[2];
    close(IN);

    $n_size = @notice_lines;
    $f_size = @file_lines;

    for ($ln = 0; $ln < $n_size && $ln < $f_size && $file_lines[$ln] eq $notice_lines[$ln]; $ln++) {
    }

    if ($ln != $n_size) {
	print "$filename didn't start with notice ... skipping!\n";
	return 0;
    }

    $newfilename = $filename . ".new";
    open(OUT, "> $newfilename") or die "can't open $filename.new: $!";

    if (-f $newfilename && ! -w $newfilename) {
	chmod(0600, $newfilename) or die "Failed to make $newfilename Writable: $!\n";
    }

    for (; $ln < @file_lines; ++$ln) {
        print OUT $file_lines[$ln];
    }

    chmod ($mode, $newfilename) or die "chmod failed: $!";
    close(IN);
    close(OUT);
    rename( $filename, "$filename.bak") or die "Can't rename $filename to $filename.bak\n";
    rename( $newfilename, $filename) or die "can't rename $newfilename to $filename\n";
    return 1;
}
    
sub add_notice_to_file()
{
    my ($filename, $notice_file) = @_;
    my ($newfilename, $line, @notice_lines, $mode);
    
    open(NOTICE, "< $notice_file") or die "can't open $notice_file: $!";
    @notice_lines = <NOTICE>;
    close(NOTICE);

    $newfilename = $filename . ".new";
    open(IN, "< $filename") or die "can't open $filename: $!";
    open(OUT, "> $newfilename") or die "can't open $filename.new: $!";

    $mode = (stat IN)[2];
    if (-f $newfilename && ! -w $newfilename) {
	chmod(0600, $newfilename) or die "Failed to make $newfilename Writable: $!\n";
    }
    foreach $line (@notice_lines) {
	print OUT $line;
    }
    while(<IN>)
    {
	print OUT $_;
    }

    chmod ($mode, $newfilename) or die "chmod failed: $!";
    close(IN);
    close(OUT);
    rename( $filename, "$filename.bak") or die "Can't rename $filename to $filename.bak\n";
    rename( $newfilename, $filename) or die "can't rename $newfilename to $filename\n";
    return 1;
}

use Getopt::Long;

$sourcedir = "./";

GetOptions( "remove" => \$remove_opt,
	    "add" => \$add_opt,
	    "copyright=s" => \$arg_copyright_file,
            "dir=s" => \$sourcedir );

#main function
if (! defined($arg_copyright_file) ) {
    $copyright_file = "copyright_notice";
} else {
    $copyright_file = $arg_copyright_file;
}

# ENSURE THAT SOURCE DIR ENDS WITH THE CHARACTER '/'
if ($sourcedir !~ /\/$/) {
  $sourcedir = $sourcedir . "/";
}

print "the copyright file is $copyright_file\n";
print "the source directory is $sourcedir\n";

opendir(DIR, $sourcedir) or die "can't opendir $sourcedir: $!";
while (defined($file = readdir(DIR))) {
    if ( ($file  !~ /^\./ ) && ( 
				 ( $file =~ /\.[ch]$/) ||
				 ( $file =~ /\.java$/) ) ) {
        $file = $sourcedir . $file;

	if ($remove_opt ) {
	    &remove_notice_from_file($file, $copyright_file);
	}
	if ($add_opt ) {
	    &add_notice_to_file($file, $copyright_file);
	}
    } else {
	print "Skipping... $file\n";
    }
}
closedir(DIR);
