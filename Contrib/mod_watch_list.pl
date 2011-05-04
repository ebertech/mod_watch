#!/usr/bin/perl -w
#
# mod_watch_list.pl
#
# Interface for Apache mod_watch and MRTG using the watch-list handler.
#
# See --help for usage information, and full documentation.
#


##########################################################################
#       Nothing to be configured below this point.
##########################################################################
require 5.002;
use strict;
use IO::Handle;
use IO::Socket;
use Getopt::Long;


##########################################################################
#       GLOBALS
##########################################################################
$::VERSION     = "1.02";
%::opt_hash    = ();
$::timeout     = 30;
$::in_field    = "ifInOctets";
$::out_field   = "ifOutOctets";

@::fieldnames  = qw(ifName ifUptime ifInOctets ifOutOctets ifRequests ifDocuments ifActive ifOutRate periodOctets periodMarker);


##########################################################################
#
#       MAIN
#
##########################################################################
GetOptions(\%::opt_hash, "--fetch=s",   "--dump=s",
                         "--mrtg=s",    "--fields=s",
                         "--timeout=i",
                         "--version:s", "--help:s");

handle_arguments(\%::opt_hash);
exit 0;


##########################################################################
#       usage
#
#       Print usage for --help and unknown arguments.
##########################################################################
sub usage
{
  print <<EOF;
Usage: mod_watch_list.pl [OPTION]...

  --fetch=<URL>              fetch watch-list data from URL
  --dump=<HOST>              dump raw watch-list output for vhost HOST
  --mrtg=<HOST>              dump MRTG-formatted output for vhost HOST
  --fields=<FIELD1,FIELD2>   show only specific interface fields
  --timeout=<TIMEOUT>        set TCP socket timeout to TIMEOUT seconds
  --help                     display this help and exit
  --version                  output version information and exit

Only one (1) host permitted for HOST.  TIMEOUT defaults to 15 seconds.  If
unspecified, the default port for URL is 80.

All data fetched (i.e. --fetch) is output to STDOUT.  All data read (i.e.
--mrtg or --dump) is read from STDIN.

When using interface fields, FIELD1 is input, and FIELD2 is output.  By
default, "ifInOctet" and "ifOutOctet" are used, respectively.

Available fields are: @::fieldnames

Report bugs to <software\@jdc.parodius.com.NOSPAM>
EOF
  return;
}


##########################################################################
#       version
#
#       Print version and licensing information.
##########################################################################
sub version
{
  print <<EOF;
mod_watch_list.pl $::VERSION

Written by Jeremy Chadwick <software\@jdc.parodius.com.NOSPAM>.

For licensing information, see LICENSE.txt which comes with mod_watch.

See http://www.snert.com/mod_watch/ for more information about mod_watch.
See http://www.snert.com/mod_throttle/ for information about mod_throttle.

EOF
  return;
}


##########################################################################
#       fetch_data_HTTP
#
#       Use the IO::Socket library's INET function to open up a socket
#       to a webserver, and obtain the watch-list data.  The URL is
#       parsed (see provided regex).  timeout argument is mandatory.
##########################################################################
sub fetch_data_HTTP
{
  my ($hashref, $url, $timeout) = @_;
  my $status;

  my ($host, $port, $path) = ($url =~ m#http://([^:/]+)(?:\:(\d*))?(/.*)#);

  $port = 80 unless defined $port;

  my $sock = IO::Socket::INET->new(PeerAddr => $host,
                                   PeerPort => $port,
                                   Proto    => 'tcp',
                                   Timeout  => $timeout) or die;

  $sock->print("GET $path HTTP/1.0\nHost: $host\n\n");

  $status = $sock->getline;

  if ($status !~ m#HTTP/1.[01] 200 (.*)#)
  {
    undef $sock;
    chomp $status;
    print "0\n0\n0\nERROR: $host -- $status\n";
    exit 1;
  }

  # Discard remaining HTTP headers.
  while ($_ = $sock->getline)
  {
    last if /^\s*$/;
  }

  while ($_ = $sock->getline)
  {
    parse_line($hashref, $_);
  }

  # Close the socket and clean up.
  undef $sock;

  return 0;
}


##########################################################################
#       fetch_data_STDIN
#
#       Read formatted data from STDIN.  See parse_line for formatting.
##########################################################################
sub fetch_data_STDIN
{
  my ($hashref, $host) = @_;
  my $retcode = 0;

  while(<>)
  {
    next unless /^$host\s/;
    parse_line($hashref, $_);
    $retcode = 1;
  }

  return $retcode;
}


##########################################################################
#       parse_line
#
#       Verify correct syntax for parsed input.  The format used for
#       watch-list (eg. fetch_data_HTTP) and for files is the same:
#
#       ifName ifUptime ifInOctets ifOutOctets ifRequests ifDocuments ifActive ifOutRate periodOctets periodMarker\n
#
##########################################################################
sub parse_line
{
  my ($hashref, $line) = @_;

  chomp($_ = $line);

  if (/^(\S+) \d+ \d+ \d+ \d+ \d+ [\d\-]+ [\d\.]+ \d+ \d+/)
  {
    my $host = $1;
    my @data = split(/\s+/, $_);

    my $group;
    for $group (reverse @::fieldnames)
    {
      $$hashref{$host}{$group} = pop @data;
    }
  }
  else
  {
    print STDERR "ERROR: Invalid input.  The line in error is:\n";
    print STDERR $_, "\n";
    die;
  }

  return;
}


##########################################################################
#       dump_mrtg_host
#
#       Dumps the a hosts content from the hash reference, formatted
#       for MRTG (in\nout\nuptime\nhostname\n).
##########################################################################
sub dump_mrtg_host
{
  my ($hashref, $host, $field_in, $field_out) = @_;

  if (defined $$hashref{$host}{"ifName"})
  {
    my $in  = $$hashref{$host}{$field_in};
    my $out = $$hashref{$host}{$field_out};
    my $up  = $$hashref{$host}{"ifUptime"};

    print $in, "\n";
    print $out, "\n";
    print ml_elapsed_time($up), "\n";
    print $host, "\n";
  }

  return;
}


##########################################################################
#       dump_data_STDOUT
#
#       Dump the contents of the hash reference $hashref to STDOUT.
##########################################################################
sub dump_data_STDOUT
{
  my ($hashref) = shift;
  my $host;

  foreach $host (keys %$hashref)
  {
    my $group;
    my @data;

    for $group (@::fieldnames)
    {
      push(@data, $$hashref{$host}{$group});
    }

    print join(" ", @data), "\n";
  }

  return;
}


##########################################################################
#       ml_elapsed_time
#
#       Convert ifUptime into something that looks pretty for MRTG.
##########################################################################
sub ml_elapsed_time
{
  my ($s) = shift;
  my ($d, $h, $m);

  $d  = int($s / 86400);
  $s %= 86400;

  $h  = int($s / 3600);
  $s %= 3600;

  $m  = int($s / 60);
  $s %= 60;

  return sprintf("%lu+%02d:%02d:%02d", $d, $h, $m, $s)  if ($d > 0);
  return sprintf("%d:%02d:%02d", $h, $m, $s)            if ($h > 0);
  return sprintf("%d.%02d", $m, $s)                     if ($m > 0);
  return sprintf("%d", $s);
}


##########################################################################
#       handle_arguments
#
#       Handle command-line arguments taken from Getopt::Long.
##########################################################################
sub handle_arguments
{
  if (exists $::opt_hash{"fields"})
  {
    #
    # NOTE: Might be a good idea to add some error-checking here; check
    #       to make sure the fields listed actually exists in @::fieldnames
    #
    if ($::opt_hash{"fields"} =~ /(\w+),(\w+)/)
    {
      ($::in_field, $::out_field) = ($1,$2);
    }
    else
    {
      usage();
      exit 1;
    }
  }
  if (exists $::opt_hash{"timeout"})
  {
    $::timeout = $::opt_hash{"timeout"};
  }

  if (exists $::opt_hash{"fetch"})
  {
    my %data;

    fetch_data_HTTP(\%data, $::opt_hash{"fetch"}, $::timeout);
    dump_data_STDOUT(\%data);
  }
  elsif (exists $::opt_hash{"dump"})
  {
    my %data;

    fetch_data_STDIN(\%data, $::opt_hash{"dump"});
    dump_data_STDOUT(\%data);
  }
  elsif (exists $::opt_hash{"mrtg"})
  {
    my %data;
    my $host = $::opt_hash{"mrtg"};

    if (fetch_data_STDIN(\%data, $host) == 0)
    {
      print "0\n0\n0\nERROR: $host -- Data missing from watch-list.\n";
      exit 1;
    }
    dump_mrtg_host(\%data, $::opt_hash{"mrtg"}, $::in_field, $::out_field);
  }
  elsif (exists $::opt_hash{"version"})
  {
    version();
    exit 1;
  }
  else
  {
    usage();
    exit 1;
  }
  return;
}


__END__
