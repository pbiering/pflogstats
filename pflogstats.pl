#!/usr/bin/perl -w
eval 'exec perl -S $0 "$@"'
    if 0;

###
# Project:     pflogstats
# Program:     pflogstats.pl
# Description: Main program
#
# Based on:    pflogsumm.pl - Produce summaries of Postfix/VMailer MTA in logfile -
#               Copyright (C) 1998-2002 by James S. Seymour (jseymour@LinxNet.com)
#               Release 1.0.4.
#               http://jimsun.LinxNet.com/postfix_contrib.html
#
# All not overtaken code:
#              Copyright (C) 2002-2005 by Dr. Peter Bieringer <pbieringer@aerasec.de>
#               ftp://ftp.aerasec.de/pub/linux/postfix/pflogsumm/
#
# License:     GNU GPL v2
# CVS:         $Id: pflogstats.pl,v 1.46 2005/06/17 11:07:05 peter Exp $
#
# See also following files: CREDITS ChangeLog TODO LICENSE README INSTALL
###


# Debug values
#                                    | 0x1000 : add verp_mung match token to address
#                                    | 0x2000 : show check of net for skip
#                                    | 0x0002 : show qid
#                                    | 0x0004 : show log line

# ***** Sorry for some coding confusion, this is a developer version *****

# Minium required Perl version
require 5.00503;

use strict;

# Global used Perl modules
use Time::Local;
use locale;
use Getopt::Long;


## Name and version
use vars qw{$release $progName};
our $release = "1.1.3";
our $progName = "pflogstats.pl";
our $copyright = "(P) & (C) by Dr. Peter Bieringer - based on pflogsumm.pl by James S. Seymour";


## Defines before module loader
# Extend module search path !!!! REVIEW before using !!!!

# 1st: look into current directory
push @INC, ".";

# 2nd: look into /usr/local/lib/pflogstats
push @INC, "/usr/local/lib/pflogstats";

# 3rd: look into /usr/lib/pflogstats
push @INC, "/usr/lib/pflogstats";

## Define global variables

# option handling
use vars qw{%options %opts %types};

# Default value
$types{'default'} = 0;

# Temp defines here
$types{'test_verp_mung'} = 0;

# module hooks
use vars qw{%hooks};

# module info
use vars qw{%moduleinfo};

# Format options
use vars qw{@opt_format %format};
# @opt_format; # from option parsing
# %format; # used format

my @opt_types;

# Preset options
%options = (
    "e"                  => \$opts{'e'},
    "q"                  => \$opts{'q'},
  ## extra
    "show_users"         => \$opts{'show_users'},
);


## Module loader

# General
require "pflogstats-common-support.pm";

# Optional common modules
eval { require "pflogstats-common-profiling.pm"; } || warn "Module disabled: pflogstats-common-profiling.pm: $@\n";

# Optional intermediate XML storage
eval { require "pflogstats-common-intermediatexml.pm"; } || warn "Module disabled: pflogstats-common-intermediatexml.pm: $@\n";

# Features/Enhancements

# Statistics/Accounting (postfix)
require "pflogstats-statistics-accounting.pm";

# Statistics/Antivirus
require "pflogstats-statistics-antivirus.pm";

# Statistics/Accounting (pop/imap)
require "pflogstats-statistics-accpopimap.pm";

# Statistics/UCE
require "pflogstats-statistics-uce.pm";

# Statistics/Rejects
require "pflogstats-statistics-reject.pm";

# Statistics/SpamAssassin
require "pflogstats-statistics-spamassassin.pm";

# Extensions/Addressmapping
require "pflogstats-extensions-addressmapping.pm";

# Extensions/VerpMung
require "pflogstats-extensions-verpmung.pm";

# Optional extensions/Network related filtering (for accounting)
eval { require "pflogstats-extensions-networking.pm"; } || warn "Module disabled: pflogstats-extensions-networking.pm: $@\n";


## Hook 'early_begin'
for my $p_hook (keys %{$hooks{'early_begin'}}) {
	&{$hooks{'early_begin'}->{$p_hook}};
};

## Print options (debug)
#for my $key (keys %options) {
#	print $key . "\n";
#};
#exit 0;

## Print types (debug)
#for my $type (keys %types) {
#	print $type . "\n";
#};
#exit 0;

# Number formats
use vars qw{%numberformat};

# Time range of logdata
use vars qw{$timemin $timemax};
my ($time);


###
#
#
###
# Usage:
#    pflogstats.pl -[eq] [-r <today|yesterday>]
#        [--verp_mung[=<n>]]
#        [-i|--ignore_case]
#        [file1 [filen]]
#
#    pflogstats.pl -[help|version]
#
# Options:
#
#    -e             extended (extreme? excessive?) detail - emit detailed
#                   reports.  At present, this includes only a per-message
#                   report, sorted by sender domain, then user-in-domain,
#                   then by queue i.d.
#
#                   WARNING: the data built to generate this report can
#                   quickly consume very large amounts of memory if a lot
#                   of log entries are processed!
#
#    -q             quiet - don't print headings for empty reports (note:
#                   headings for warning, fatal, and "master" messages will
#                   always be printed.)
#
#    If no file(s) specified, reads from stdin.  Output is to stdout.
#
# Typical usage:
#    Produce a report of previous day's activities:
#        pflogstats.pl -t acc -r yesterday /var/log/maillog
#    A report of prior week's activities (after logs rotated):
#        pflogstats.pl -t acc /var/log/maillog.1
#    What's happened so far today:
#        pflogstats.pl -t acc -r today /var/log/maillog
#
# Debug/developent options:
#   -t|--type test_verp_mung
#     Test addresses given on stdin for verp_mung rewriting


#### Reviewed main options ####
my @mainhelptext;

# Help
push @mainhelptext, "    [--help|-h|-?]            Display help/usage message";
$options{'help|h|?'}  = \$opts{'help'};

# Type
my $temp = "    [--type|-t <type>]        Do type of statistics (more than one can be specified)\n                               Examples:";
$options{"type|t=s"}  = \@opt_types;
foreach my $type (keys %types ) {
	$temp .= " '" . $type . "'";	

};
push @mainhelptext, $temp;

# Time range
push @mainhelptext, "    [--range|-r <timerange>]  Timerange of collecting data\n                               Default: all data\n                               More examples: 'yesterday' 'today'  'Mar 1'";
$options{"range|r=s"}  = \$opts{'range'};

# Table sort
push @mainhelptext, "    [--sort <sorttype>]       Sort output\n                               Default: 'alpha'\n                               More examples: 'maxmin' 'minmax'";
$options{"sort=s"}  = \$opts{'sort_type'};

# Ignore case
push @mainhelptext, "    [--ignore_case|-i]        Handle complete email address in a case-insensitive manner\n                               Default: lower-cases only the host and domain parts\n                               If used, entire email address will be lower-cased";
$options{"ignore_case|i"}  = \$opts{'i'};

# Version
push @mainhelptext, "    [--version]               Displays version of main program and modules";
$options{"version"}  = \$opts{'version'};

# Variables and constants used
use vars qw(
    $progName
    $usageMsg
    @monthNames %monthNums $thisYr $thisMon
	%numberformat @opt_format %format
);

# Constants used
@monthNames = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
%monthNums = qw(
    Jan  0 Feb  1 Mar  2 Apr  3 May  4 Jun  5
    Jul  6 Aug  7 Sep  8 Oct  9 Nov 10 Dec 11);
($thisMon, $thisYr) = (localtime(time()))[4,5];
$thisYr += 1900;


# time range of log data
my ($dateStr, $msgMonStr, $msgDay, $msgTimeStr, $msgHr, $msgMin, $msgSec, $msgYr, $msgMon);
my %timerange;

## Main start
$usageMsg =
    "usage: $progName -[eq]
       [-i|--ignore_case]
       [file1 [filen]]

     usage for normal statistics: $progName

     general
      [--show_users]               Display statistics also per user

";

## Print help function
sub print_help() {
	print "$progName $release\n";
	print $copyright . "\n\n";

	print STDERR "  Options (reviewed):\n\n";
	foreach my $line (@mainhelptext) {
		print STDERR $line . "\n\n";
	};
	print STDERR "\n";

	print STDERR "  Options from included modules (new style):\n\n";

	## Hook 'help'
	for my $p_hook (sort keys %{$hooks{'help'}}) {
		my $helpstring = &{$hooks{'help'}->{$p_hook}};
		print STDERR "    Options from module '" . $p_hook . "':";
		print STDERR $helpstring . "\n";
	};

	print STDERR "  Options (still not reviewed):\n\n";
	print STDERR $usageMsg . "\n\n";
};

if (defined $main::opts{'verbose'}) {
	print "Calling options: " . "@ARGV" . "\n";
};

my $ret = GetOptions(%options);

if (! $ret ) {
	print "Use help to see more\n";
	exit 1;
};

# Print help or version
if(defined($opts{'help'})) {
	print_help();
	exit 0;
};
if(defined($opts{'version'})) {
	print "$progName $release\n";
	print $copyright . "\n\n";
	exit 0;
};


#### Check values of given options

##  Check sort option
if (! defined $opts{'sort_type'}) {
	# Default
	$opts{'sort_type'} = "alpha";
};
if ($opts{'sort_type'} ne "alpha" && $opts{'sort_type'} ne "maxmin" && $opts{'sort_type'} ne "minmax") {
	die "ERROR: Unsupported sort type: " . $opts{'sort_type'} . "\n";
};


# internally: 0 == none, undefined == -1 == all
$opts{'h'} = -1 unless(defined($opts{'h'}));


## Hook 'early_checkoptions'
for my $p_hook (keys %{$hooks{'early_checkoptions'}}) {
	&{$hooks{'early_checkoptions'}->{$p_hook}};
};

## Hook 'checkoptions'
for my $p_hook (keys %{$hooks{'checkoptions'}}) {
	&{$hooks{'checkoptions'}->{$p_hook}};
};


## Parse and check type
if ( $#opt_types < 0 ) {
	$types{'default'} = 1;
} else {
	foreach my $type ( @opt_types ) {
		print STDERR "DEBUG: Got type: " . $type . "\n" if ($opts{'debug'});
		if (defined $types{$type}) {
			print STDERR "DEBUG: valid type: " . $type . "\n" if ($opts{'debug'});
			$types{$type} = 1;
		} else {
			die "ERROR: unsupported type: " . $type . "\n";
		};
	};
};
	

$dateStr = get_datestr($opts{'range'}) if(defined($opts{'range'}));


print "\nStatistics generated by: $progName $release";

if (defined $main::opts{'verbose'}) {
	print "\n" . $copyright . "\n";
	print " Included modules:\n";

	for my $module ( sort { $moduleinfo{$a}->{'name'} cmp $moduleinfo{$b}->{'name'} } sort { $moduleinfo{$a}->{'type'} cmp $moduleinfo{$b}->{'type'} } keys %moduleinfo) {
		print "  " . $moduleinfo{$module}->{'type'} . "/" . $moduleinfo{$module}->{'name'} . ":" .  $moduleinfo{$module}->{'version'} . "\n";
	};
	print "\n";
} else {
	my $modulesum = 0;
	for my $module ( keys %moduleinfo) {
		$modulesum += $moduleinfo{$module}->{'version'};
	};
	printf " (module version sum: %0.2f)\n", $modulesum;
	print $copyright . "\n";
};


## Any data to read from stdin?
#if (-t) {
#	# Skip log file parsing
#	print "\nINFO: no data given, proceed without parsing\n";
#	goto("LABEL_end_logfileparsing");
#};

## Show timerange on log file parsing
if ( defined($opts{'range'}) ) {
	print "Statistics generated for timerange: $dateStr\n";
};
print "\n\n";

## Hook 'beforemainloopstarts'
for my $p_hook (keys %{$hooks{'beforemainloopstarts'}}) {
	&{$hooks{'beforemainloopstarts'}->{$p_hook}};
};


## Start parsing logfile #################################################
print "DEBUG: start parsing logfile\n" if ($opts{'debug'});

## Hook 'loop_beforestart'
for my $p_hook (keys %{$hooks{'loop_beforestart'}}) {
	&{$hooks{'loop_beforestart'}->{$p_hook}};
};

while(<>) {
	chomp;
	$_ =~ s/$//g; # Remove trailing CR
	$~ =~ s/^[[:space:][:cntrl:]]+$//g; # Remove spaces and ctrl chars only

	next if (length($_) == 0); # skip empty lines

	if ( $types{'test_verp_mung'} != 0 ) {
		die "Currently not supported at the moment";

		# Debug/developing: test verp_mung code
		my $addr = lc($_);

		print "\n" . $addr . "\n";

		$opts{'verpMung'} = 1;
		#my $verpmung1 = do_verp_mung($addr);
		# print " -> " . $verpmung1 . "\n";

		$opts{'verpMung'} = 2;
		#my $verpmung2 = do_verp_mung($addr);
		# print " -> " . $verpmung2 . "\n";

		next; # No others here for testing
	};

	## Now starting here, only a maillog is valid!

	# Skip not selected date
	next if (defined($dateStr) && ! /^$dateStr/);

	# Extract date & time
	($msgMonStr, $msgDay, $msgTimeStr) = /^(...)\s+([0-9]+)\s(..:..:..)\s.*/;

	if (! defined $msgMonStr || ! defined $msgDay || ! defined $msgTimeStr) {
		warn "WARNING(skipped-line): Date&Time in logline is not valid: $_";
		next;
	};
	
	# snatch out log entry date & time
	($msgHr, $msgMin, $msgSec) = split(/:/, $msgTimeStr);
	$msgMon = $monthNums{$msgMonStr};
	$msgYr = $thisYr; --$msgYr if($msgMon > $thisMon);

	if (! defined $msgHr || ! defined $msgMin || ! defined $msgSec ) {
		warn "WARNING(skipped-line): Date&Time in logline is not valid: $_";
		next;
	};

	# Calculate Unixtime
	$time = timelocal( $msgSec, $msgMin, $msgHr, $msgDay, $msgMon, $msgYr );

	# Catch min/max times for later timerange display
	if (! defined $timemin || ! defined $timemax ) {
		# initial values
		if (! defined $timemin) { $timemin = $time };
		if (! defined $timemax) { $timemax = $time };
	} else {
		# get min/max
		if    ($time < $timemin) { $timemin = $time; }
		elsif ($time > $timemax) { $timemax = $time; };
	};

	# Hook "loglineparser"
	for my $p_hook (keys %{$hooks{'loglineparser'}}) {
		&{$hooks{'loglineparser'}->{$p_hook}} (\$time, \$_);
	};
}

## Hook 'loop_afterfinish'
for my $p_hook (keys %{$hooks{'loop_afterfinish'}}) {
	&{$hooks{'loop_afterfinish'}->{$p_hook}} (\$_);
};

print "DEBUG: end parsing logfile\n" if ($opts{'debug'});


##### end of log file parsing

if ( $types{'test_verp_mung'} != 0 ) {
	goto "LABEL_end";
};

## Hook 'register_intermediate_storage' (register global data)
$timerange{'timemin'} = $timemin;
$timerange{'timemax'} = $timemax;
for my $p_hook (keys %{$main::hooks{'register_intermediate_data'}}) {
	&{$main::hooks{'register_intermediate_data'}->{$p_hook}} ("timerange", \%timerange);
};

LABEL_end_logfileparsing:

## Hook 'intermediate_storage'
for my $p_hook (keys %{$hooks{'intermediate_storage'}}) {
	&{$hooks{'intermediate_storage'}->{$p_hook}} ();
};


## explicit disable of printing statistics
if (defined $format{'none'}) {
	goto "LABEL_end";
};

## Hook 'before_print_result'
for my $p_hook (keys %{$hooks{'before_print_result'}}) {
	&{$hooks{'before_print_result'}->{$p_hook}} ();
};

## Hook 'retrieve_intermediate_data' (retrieve global data)
for my $p_hook (keys %{$main::hooks{'retrieve_intermediate_data'}}) {
	&{$main::hooks{'retrieve_intermediate_data'}->{$p_hook}} ("timerange", \%timerange);
};

$timemin = $timerange{'timemin'};
$timemax = $timerange{'timemax'};

## Hook 'print_result'
for my $p_hook (keys %{$hooks{'print_result'}}) {
	&{$hooks{'print_result'}->{$p_hook}};
};

## Hook 'printstatistics'
if (defined $main::opts{'printstatistics'}) {
	for my $p_hook (keys %{$hooks{'print_additional_statistics'}}) {
		&{$hooks{'print_additional_statistics'}->{$p_hook}};
	};
};



LABEL_end:

## Hook 'final_end'
for my $p_hook (keys %{$hooks{'final_end'}}) {
	&{$hooks{'final_end'}->{$p_hook}};
};



##################### End of main program


# return a date string to match in log
sub get_datestr {
    my $dateOpt = $_[0];
    my ($t_mday, $t_mon);

    my $aDay = 60 * 60 * 24;

    my $time = time();
    if($dateOpt eq "yesterday") {
	$time -= $aDay;
    	($t_mday, $t_mon) = (localtime($time))[3,4];
    } elsif($dateOpt eq "today") {
    	($t_mday, $t_mon) = (localtime($time))[3,4];
    } else {
	my ($m, $d) = split / +/, $dateOpt;
	if (! defined $monthNums{$m} ) {
		die "Illegal month string in: " . $dateOpt . "\n";
	};
	if ($d < 1 || $d >31) {
		die "Illegal day in: " . $dateOpt . "\n";
	};
	$t_mday = $d;
	$t_mon = $monthNums{$m};
    }

    return sprintf("%s %2d", $monthNames[$t_mon], $t_mday);
}
