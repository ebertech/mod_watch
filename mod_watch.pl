#!/usr/bin/perl
#
# mod_watch.pl
#
# Interface for Apache mod_watch and MRTG
#
# Copyright 2001, 2003 by Anthony Howe.  All rights reserved.
#
# usage: mod_watch.pl [-f a,b] url
#
# Fetch the current counters associated with the given URL. The URL refers
# to either a virtual host, file owner, or the SERVER.
#
#	http://www.snert.com/watch-info
#	http://www.snert.com/~achowe/watch-info
#	http://www.snert.com/~SERVER/watch-info
#
# The mod_watch handler "watch-info" returns a line of plain text
# containing the following space separated fields:
#
#	ifName ifUptime ifInOctets ifOutOctets ifRequests ifDocuments ifAvgRate ifActive
#
# This script returns output suitable for MRTG's target script command
# directive: line with the input bytes, line with the output bytes, line
# with the web server uptime, and the target name.
#

##########################################################################
#	Nothing to be configured below this point.
##########################################################################
$VERSION = '2.7';
$AUTHOR = 'achowe@snert.com';

use Socket;
use Getopt::Std;
use Sys::Hostname;
use AnyDBM_File;

my $usage = "usage: mod_watch.pl [-f a,b] url\n";
die($usage) unless getopts('f:');
die($usage) unless @ARGV == 1;

#########################################################################
#	Open connection to URL.
#########################################################################

# Figure out who we have to call.
($host, $port, $path) = ($ARGV[0] =~ m!http://([^:/]+)(?:\:(\d*))?(/.*)!);
$port = 80 unless defined $port;

# Get a socket...
#
# TODO add Timeout support, eg.
#
#$sock = IO::Socket::INET->new(PeerAddr => 'www.vhost.com', PeerPort => 'http(80)', Proto => 'tcp', Timeout => 10);
#

unless (socket(HTTP, PF_INET, SOCK_STREAM, getprotobyname('tcp'))) {
#	print("0\n0\n0\n$host:$port ($!)\n");
	print("\n\n\n$host:$port ($!)\n");
	exit(0);
}

# ...set socket to be line buffered...
select( (select(HTTP), $| = 1)[0] );

# .. make the connection.
unless (connect(HTTP, sockaddr_in($port, inet_aton("$host")))) {
#	print("0\n0\n0\n$host:$port ($!)\n");
	print("\n\n\n$host:$port ($!)\n");
	exit(0);
}

#########################################################################
#	Make the HTTP request.
#########################################################################

# Proxy request style.
#print HTTP "GET $ARGV[0] HTTP/1.0\n\n";

print HTTP "GET $path HTTP/1.0\nHost: $host\n\n";

$answer = <HTTP>;
($status, $reason) = ($answer =~ m!HTTP/1.[01] (\d+) (.*)\r!);

unless ($status == 200) {
#	print("0\n0\n0\n$host:$port ($reason)\n");
	print("\n\n\n$host:$port ($reason)\n");
	exit(0);
}

# Discard remaining HTTP headers.
while (<HTTP>) {
	last if /^\s*$/;
}

#########################################################################
#	Parse the information line.
#########################################################################

# Field names in order.
@fieldnames = qw(ifName ifUptime ifInOctets ifOutOctets ifRequests ifDocuments ifActive ifOutRate);

# Default fields to return.
($a, $b) = qw(ifInOctets ifOutOctets);

# User wants other fields?
($a, $b) = ($opt_f =~ m!(\w+),(\w+)!) if defined $opt_f;

# Get the information line.
my $line = <HTTP>;
close(HTTP);

# Select the fields to return.
($in, $out) = (0, 0);
#if ($line =~ /^\S+\s\d+\s\d+\s\d+\s\d+\s\d+\s\d+\s\d+/) {
if ($line =~ /^\S+\s\d+\s\d+\s\d+\s\d+\s\d+/) {
	@counters{@fieldnames} = split(/\s+/, $line);
	($in, $out) = ($counters{$a}, $counters{$b});
}

#########################################################################
#	Write MRTG output.
#########################################################################

sub ml_elapsed_time {
	my ($s) = @_;
	my ($d, $h, $m);

	$d = int($s / 86400);
	$s %= 86400;

	$h = int($s / 3600);
	$s %= 3600;

	$m = int($s / 60);
	$s %= 60;

	return sprintf("%lu+%02d:%02d.%02d", $d, $h, $m, $s) if 0 < $d;
	return sprintf("%d:%02d.%02d", $h, $m, $s) if 0 < $h;
	return sprintf("%d.%02d", $m, $s) if 0 < $m;
	return sprintf("%d", $s);
}

print "$in\n$out\n" . ml_elapsed_time($counters{ifUptime}) . "\n$counters{ifName}\n";

exit 0;

#########################################################################
#
#########################################################################
__END__
