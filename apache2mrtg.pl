#!/usr/bin/perl
#
# apache2mrtg.pl
#
# Copyright 2001, 2003 by Anthony Howe.  All rights reserved.
#

# Where the scripts should live
$SCRIPTDIR = "/usr/local/sbin";

##########################################################################
#	Nothing to be configured below this point.			 #
##########################################################################
$AUTHOR = 'achowe@snert.com';
$VERSION = '2.0';


unless (@ARGV == 1) {
	print STDERR "usage: apache2mrtg.pl path/to/httpd.conf\n";
	exit 2;
}

%seen = ();

sub target {
	my $name = shift;

	if ($seen{$name}) {
		print STDERR "DUPLICATE entry \"$name\"\n";
		return;
	}

	$seen{$name} = 1;

	print <<EOT;
Title[$name]: $name Data Traffic
Target[$name]: `${SCRIPTDIR}/mod_watch.pl http://$name/watch-info`
MaxBytes[$name]: 1250000
PageTop[$name]: <h2><a href="http://$name/">$name</a> Data Traffic</h2>

EOT
}

while (<ARGV>) {
	# Skip commented blocks
	next if m!\#.*</?virtualhost!i;

	if (m!<virtualhost\s!i .. m!</virtualhost>!i) {
		$name = $1 if m!ServerName\s+(\S+)!;
	}

	if (m!</virtualhost>!i) {
		target($name);
	}
}
