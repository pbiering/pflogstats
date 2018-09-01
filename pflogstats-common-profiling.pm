#!/usr/bin/perl -w

###
# Project:     pflogstats
# Module:      pflogstats-common-profiling.pm
# Description: Profiling functions
# Copyright:   Dr. Peter Bieringer <pbieringer at aerasec dot de>
#               AERAsec GmbH <http://www.aerasec.de/> 
# License:     GNU GPL v2
# CVS:         $Id: pflogstats-common-profiling.pm,v 1.5 2003/05/22 14:02:23 rootadm Exp $
###

###
# ChangeLog:
#	0.01
#	 - initial split-off from common-support
#	0.02
#	 - make printing of profiling information optional
#	0.03
#	 - make Perl 5.0 compatible
###

## Todo:
# - correct module function export
##

use strict;
use Proc::ProcessTable;	# required by "memusage"


package pflogstats::common::profiling;


## Local constants
my $module_type = "common";
my $module_name = $module_type . "-profiling";
my $module_version = "0.03";

## Export module info
$main::moduleinfo{$module_name}->{'version'} = $module_version;
$main::moduleinfo{$module_name}->{'type'} = $module_type;
$main::moduleinfo{$module_name}->{'name'} = $module_name;

## Global prototyping

## Local prototyping

## Global variables

## Register options
$main::options{'enable-profiling'} = \$main::opts{'enable-profiling'};


## Register calling hooks
$main::hooks{'loop_beforestart'}->{$module_name} = \&loop_beforestart;
$main::hooks{'loop_afterfinish'}->{$module_name} = \&loop_afterfinish;
$main::hooks{'final_end'}->{$module_name} = \&loop_finalend;
$main::hooks{'early_begin'}->{$module_name} = \&loop_earlybegin;
$main::hooks{'help'}->{$module_name} = \&help;


## Local variables
my %statistics;


## Global callable functions

# Help
sub help() {
	my $helpstring = "
    [--enable-profiling]         Enable profiling
";
	return $helpstring;
}


# Early begin
sub loop_earlybegin() {
	my ($user,$system,$cuser,$csystem) = times;
	$statistics{'program'}->{'start'}->{'time'}->{'user'} = $user;
	$statistics{'program'}->{'start'}->{'time'}->{'system'} = $system;
	my ($mem, $mempercent) = &memusage();
	$statistics{'program'}->{'start'}->{'memory'}->{'absolut'} = $mem;
	$statistics{'program'}->{'start'}->{'memory'}->{'relative'} = $mempercent;
};

# Before loop starts
sub loop_beforestart() {
	my ($user,$system,$cuser,$csystem) = times;
	$statistics{'loop'}->{'start'}->{'time'}->{'user'} = $user;
	$statistics{'loop'}->{'start'}->{'time'}->{'system'} = $system;
	my ($mem, $mempercent) = &memusage();
	$statistics{'loop'}->{'start'}->{'memory'}->{'absolut'} = $mem;
	$statistics{'loop'}->{'start'}->{'memory'}->{'relative'} = $mempercent;
};

# After loop ends
sub loop_afterfinish() {
	my ($user,$system,$cuser,$csystem) = times;
	$statistics{'loop'}->{'finish'}->{'time'}->{'user'} = $user;
	$statistics{'loop'}->{'finish'}->{'time'}->{'system'} = $system;
	my ($mem, $mempercent) = &memusage();
	$statistics{'loop'}->{'finish'}->{'memory'}->{'absolut'} = $mem;
	$statistics{'loop'}->{'finish'}->{'memory'}->{'relative'} = $mempercent;
};

# Final end
sub loop_finalend() {
	my ($user,$system,$cuser,$csystem) = times;
	$statistics{'program'}->{'finish'}->{'time'}->{'user'} = $user;
	$statistics{'program'}->{'finish'}->{'time'}->{'system'} = $system;
	my ($mem, $mempercent) = &memusage();
	$statistics{'program'}->{'finish'}->{'memory'}->{'absolut'} = $mem;
	$statistics{'program'}->{'finish'}->{'memory'}->{'relative'} = $mempercent;

	if (defined $main::opts{'enable-profiling'} ) {
		&print_statistics();
	};

};

sub print_statistics() {
	# Print statistics
	print "\n";
	print '#'x75 . "\n";
	printf "# Timing statistics\n";
	printf "#  Complete user        time : %8.2f sec  (%5.2f min)\n", $statistics{'program'}->{'finish'}->{'time'}->{'user'}, $statistics{'program'}->{'finish'}->{'time'}->{'user'} / 60;
	printf "#  Complete system      time : %8.2f sec  (%5.2f min)\n", $statistics{'program'}->{'finish'}->{'time'}->{'system'}, $statistics{'program'}->{'finish'}->{'time'}->{'system'} / 60;
	printf "#  Complete             time : %8.2f sec  (%5.2f min)\n", $statistics{'program'}->{'finish'}->{'time'}->{'user'} + $statistics{'program'}->{'finish'}->{'time'}->{'system'}, ($statistics{'program'}->{'finish'}->{'time'}->{'user'} + $statistics{'program'}->{'finish'}->{'time'}->{'system'}) / 60;
	printf "#  Parser loop user     time : %8.2f sec  (%5.2f min)\n", $statistics{'loop'}->{'finish'}->{'time'}->{'user'} - $statistics{'loop'}->{'start'}->{'time'}->{'user'}, ($statistics{'loop'}->{'finish'}->{'time'}->{'user'} - $statistics{'loop'}->{'start'}->{'time'}->{'user'}) / 60;
	printf "#  Parser loop system   time : %8.2f sec  (%5.2f min)\n", $statistics{'loop'}->{'finish'}->{'time'}->{'system'} - $statistics{'loop'}->{'start'}->{'time'}->{'system'}, ($statistics{'loop'}->{'finish'}->{'time'}->{'system'} - $statistics{'loop'}->{'start'}->{'time'}->{'system'}) / 60;
	printf "#  Parser loop          time : %8.2f sec  (%5.2f min)\n", $statistics{'loop'}->{'finish'}->{'time'}->{'user'} + $statistics{'loop'}->{'finish'}->{'time'}->{'system'} - $statistics{'loop'}->{'start'}->{'time'}->{'user'} + $statistics{'loop'}->{'start'}->{'time'}->{'system'}, ($statistics{'loop'}->{'finish'}->{'time'}->{'user'} + $statistics{'loop'}->{'finish'}->{'time'}->{'system'} - $statistics{'loop'}->{'start'}->{'time'}->{'user'} + $statistics{'loop'}->{'start'}->{'time'}->{'system'}) / 60;
	print "#\n";
	printf "# Memory statistics\n";
	printf "#  On start                  : %8.3f MByte  (%2d %%)\n", $statistics{'program'}->{'start'}->{'memory'}->{'absolut'} / 1048756, $statistics{'program'}->{'start'}->{'memory'}->{'relative'};
	printf "#  Before parser loop starts : %8.3f MByte  (%2d %%)\n", $statistics{'loop'}->{'start'}->{'memory'}->{'absolut'} / 1048756, $statistics{'loop'}->{'start'}->{'memory'}->{'relative'};
	printf "#  After parser loop ends    : %8.3f MByte  (%2d %%)\n", $statistics{'loop'}->{'finish'}->{'memory'}->{'absolut'} / 1048756, $statistics{'loop'}->{'finish'}->{'memory'}->{'relative'};
	printf "#   Loop difference          : %8.3f MByte  (%2d %%)\n", $statistics{'loop'}->{'finish'}->{'memory'}->{'absolut'} / 1048756 - $statistics{'loop'}->{'start'}->{'memory'}->{'absolut'} / 1048756, $statistics{'loop'}->{'finish'}->{'memory'}->{'relative'} - $statistics{'loop'}->{'start'}->{'memory'}->{'relative'};
	printf "#  Before program ends       : %8.3f MByte  (%2d %%)\n", $statistics{'program'}->{'finish'}->{'memory'}->{'absolut'} / 1048756, $statistics{'program'}->{'finish'}->{'memory'}->{'relative'};
	printf "#  Data memory               : %8.3f MByte  (%2d %%)\n", ($statistics{'program'}->{'finish'}->{'memory'}->{'absolut'} - $statistics{'program'}->{'start'}->{'memory'}->{'absolut'}) / 1048756, $statistics{'program'}->{'finish'}->{'memory'}->{'relative'} - $statistics{'program'}->{'start'}->{'memory'}->{'relative'};
	print "#\n";
	printf "#  UserTime * DataMemory     : %8.0f MByte*sec\n", ($statistics{'program'}->{'finish'}->{'memory'}->{'absolut'} - $statistics{'program'}->{'start'}->{'memory'}->{'absolut'}) / 1048756 * $statistics{'program'}->{'finish'}->{'time'}->{'user'};
	print '#'x75 . "\n";
	print "\n";
};

## Get memory usage
# Code taken from: http://archive.develooper.com/perl-crypto@perl.org/msg00036.html
#  hopefully GPL'ed...
#   memusage subroutine
#   usage: memusage [processid]
#   this subroutine takes only one parameter, the process id for
#   which memory usage information is to be returned.  If
#   undefined, the current process id is assumed.
#   Returns array of two values, raw process memory size and
#   percentage memory utilisation, in this order.  Returns
#   undefined if these values cannot be determined.

sub memusage(;$) {
	my @results;
	my $pid = (defined($_[0])) ? $_[0] : $$;
	my $proc = Proc::ProcessTable->new;
	my %fields = map { $_ => 1 } $proc->fields;
	return undef unless exists $fields{'pid'};
	foreach (@{$proc->table}) {
		if ($_->pid eq $pid) {
			push (@results, $_->size) if exists $fields{'size'};
			push (@results, $_->pctmem) if exists $fields{'pctmem'};
		};
	};
	return @results;
};

## End of module
return 1;
