#!/usr/bin/perl
#
# nfields.pl
#
# A tool for adding extra fields to mod_watch spool files.
#
# Copyright 2002 by Anthony Howe.  All rights reserved.
#
# usage: nfields.pl nnn [WatchSpoolDirectory]
#

#
# Where to store the weenie files.
#
$SPOOLDIR = '/var/spool/mod_watch';

##########################################################################
#	Nothing to be configured below this point.
##########################################################################
$VERSION = '1.0';
$AUTHOR = 'achowe@snert.com';

my $usage = "usage: nfields.pl n [WatchSpoolDirectory]\n";
die($usage) unless @ARGV == 1 || @ARGV == 2;
die($usage) unless $ARGV[0] =~ /\d+/;
($nfields, $SPOOLDIR) = @ARGV;

if (opendir(SPOOLDIR, $SPOOLDIR)) {
	@list = readdir(SPOOLDIR);
	closedir(SPOOLDIR);

	foreach $file (@list) {
		unless (open(FILE, "$SPOOLDIR/$file")) {
			print "Could not open for reading \"$SPOOLDIR/$file\": $!\n";
			next;
		}		
		
		# Read the line of fields.
		$line = <FILE>;		
		close(FILE);		

		# Strip newline.
		$line =~ s/(?:\r?\n|\r)//;
		
		# Check that there are N fields.
		@fields = split(' ', $line);
		if (@fields < $nfields) {
			for ($i = @fields; $i < $nfields; ++$i) {
				push(@fields, 0);
			}
		} elsif ($nfields < @fields) {
			delete @fields[$nfields..$#fields];
		} else {
			next;
		}
					
		unless (open(FILE, ">$SPOOLDIR/$file")) {
			print "Could not open for writing \"$SPOOLDIR/$file\": $!\n";
			next;
		}		

		# Append more fields.
		print FILE join(' ', @fields) . "\n";
		
		close(FILE);
	}
}

exit(0);

__END__