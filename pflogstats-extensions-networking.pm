#!/usr/bin/perl -w

###
# Project:     pflogstats
# Module:      pflogstats-extensions-networking.pm
# Description: Extensions for networking
# Copyright:   Dr. Peter Bieringer <pbieringer at aerasec dot de>
#               AERAsec GmbH <http://www.aerasec.de/> 
# License:     GNU GPL v2
# CVS:         $Id: pflogstats-extensions-networking.pm,v 1.15 2005/12/12 10:24:40 peter Exp $
###

###
# ChangeLog:
#	0.01
#	 - split-off from pflogstats-common-support
#	0.02
#	 - fix display of network exclude list
#       0.03
#        - make Perl 5.0 compatible
#	0.04
#	 - minimal review
#	0.05
#	 - skip_ipv6 didn't work if no other IP network was given
#	 - table width now 75
#	0.06
#	 - check function got an optional flag: returnonerror
#	0.07
#	 - implement caching in check_ip_notaccounted (speed-up: x2)
#	0.08
#	 - fix detection of not valid addresses in returnonerror mode
#	0.09
#	 - use option print-max-width
#	0.10
#	 - remove optional address prefix token
#	0.11
#	 - reorganize hook names
#	0.12
#	 - fix typo in comment, remove IPv4 mapped in IPv6 address prefix
#	0.13
#	 - add switch for output to "beforemainloopstarts"
#	0.14
#	 - add support for "quiet" output to "beforemainloopstarts"
###


use strict;

use Net::IP; # required for IP network calculation


package pflogstats::extensions::networking;


## Local constants
my $module_type = "extensions";
my $module_name = $module_type . "-networking";
my $module_version = "0.13";

## Export module info
$main::moduleinfo{$module_name}->{'version'} = $module_version;
$main::moduleinfo{$module_name}->{'type'} = $module_type;
$main::moduleinfo{$module_name}->{'name'} = $module_name;

## Local prototyping


## Global variables


## Local variables
my @net_excluded;
my @opt_net_excluded;
my %cache;
my %cache_statistics;
$cache_statistics{'new'} = 0;
$cache_statistics{'hit'} = 0;


## Register options
$main::options{'skip_net=s'} = \@opt_net_excluded;
$main::options{'skip_ipv6'} = \$main::opts{'skip_ipv6'};


## Register calling hooks
$main::hooks{'beforemainloopstarts'}->{$module_name} = \&beforemainloopstarts;
$main::hooks{'help'}->{$module_name} = \&help;
$main::hooks{'checkoptions'}->{$module_name} = \&checkoptions;
$main::hooks{'testipaddress'}->{$module_name} = \&check_ip_notaccounted;
$main::hooks{'print_additional_statistics'}->{$module_name} = \&printstatistics;


## Global callable functions
sub help() {
	my $temp;
	my $helpstring = "
    General:
    [--skip_net <network>]   IPv4/v6 network in CIDR notation skipped for accounting
                              (e.g. internal or DMZ, more than one time allowed)
    [--skip_ipv6]            All IPv6 addresses
";


	return $helpstring;
};

# Check options
sub checkoptions() {
	## Excluded networks
	# Fill excluded networks	
	foreach my $net (@opt_net_excluded) {
		print STDERR "INFO: convert net: " . $net .  "\n" if ($main::opts{'debug'} & 0x0020);
		my $ip = new Net::IP ($net) or die (Net::IP::Error());
		print STDERR "INFO: converted to: " . $ip->ip . "/" . $ip->mask .  "\n" if ($main::opts{'debug'} & 0x0020);
		push @net_excluded, $ip;

		if ($ip->version() == 6 ) {
			# nothing more to do
			next;
		};

		# Also as IPv6 compatible address
		$net =~ /^([^\/]+)\/?.*$/;
		$net = "::ffff:" . $1 . "/" . ($ip->prefixlen + 96);
		print STDERR "INFO: convert net (for IPv6): " . $net .  "\n" if ($main::opts{'debug'} & 0x0020);
		$ip = new Net::IP ($net) or die (Net::IP::Error());
		print STDERR "INFO: converted to: " . $ip->ip . "/" . $ip->mask .  "\n" if ($main::opts{'debug'} & 0x0020);
		push @net_excluded, $ip;
	};

};

sub beforemainloopstarts(;$) {
	my $output = $_[0];
	if (! defined $output) { $output = "stdout"; };

	if ($output eq "quiet") {
		# only information, nothing to do
		return;
	};

	if ( scalar (@net_excluded) > 0 || $main::opts{'skip_ipv6'}) {
		if ($output eq "stdout") {
			print '=' x $main::opts{'print-max-width'} . "\n";
			print "Network exclude list\n";
			print '-' x $main::opts{'print-max-width'} . "\n";
		} else {
			print STDERR '=' x $main::opts{'print-max-width'} . "\n";
			print STDERR "Network exclude list\n";
			print STDERR '-' x $main::opts{'print-max-width'} . "\n";
		};
		foreach my $ip (sort {$a->version() <=> $b->version()} @net_excluded) {
			if ($ip->version() == 6) {
				if ($main::opts{'skip_ipv6'}) {
					next;
				};
			};
			if ($output eq "stdout") {
				print $ip->ip . "/" . $ip->mask .  "\n";
			} else {
				print STDERR $ip->ip . "/" . $ip->mask .  "\n";
			};
		};
		if ($main::opts{'skip_ipv6'} ) {
			if ($output eq "stdout") {
				print "*** All IPv6 addresses ***\n";
			} else {
				print STDERR "*** All IPv6 addresses ***\n";
			};
		};
		if ($output eq "stdout") {
			print '=' x $main::opts{'print-max-width'} . "\n";
		} else {
			print STDERR '=' x $main::opts{'print-max-width'} . "\n";
		};
	};
};


# Check IP address for in not-account list
# Arguments:
#  $1: IP address
#  $2 (optional): change behavior in case of $1 is no IP address
#	'returnonerror': don't die, return 0 instead
# Return value: 
#  0=no
#  1=yes
sub check_ip_notaccounted($;$) {
	my $ip_string = $_[0];
	my $flag = $_[1];

	if (! defined $ip_string) { die "ERROR(check_ip_notaccounted): Missing argument (arg1)"; };

	if (defined $flag) {
		if ($flag eq "returnonerror") {
			# ok
			$flag = 1;
		} else {
			die "ERROR(check_ip_notaccounted): Unsupported flag (arg2): $flag";
		};
	} else {
		$flag = 0;
	};

	printf STDERR "DEBUG: Got string: " . $ip_string . "\n" if ($main::opts{'debug'} & 0x2000);

	# Remove leading address type prefix
	$ip_string =~ s/^IPv6://ig;
	$ip_string =~ s/^IPv4://ig;

	# Remove mapped prefix
	$ip_string =~ s/^::ffff://ig;

	# Cache lookup
	if (defined $cache{$ip_string}) {
		$cache_statistics{'hit'}++;
		if ($cache{$ip_string} == 2) {
			# cached return on error
			if ($flag == 1) {
				return 0;
			};
		} else {
			return $cache{$ip_string};
		};
	} else {
		$cache_statistics{'new'}++;
	};

	my $ip;

	if ($flag == 1) {
		$ip = new Net::IP ($ip_string);
		if ($? != 0) {
			$cache{$ip_string} = 2;
			return 0;
		};
		printf STDERR "Debug: successful creation of ip object\n" if ($main::opts{'debug'} & 0x2000);

		eval {
			# Test for version
			$ip->version();
		};
		if ($@) {
			printf STDERR "Debug: skip\n" if ($main::opts{'debug'} & 0x2000);
			$cache{$ip_string} = 2;
			return 0;
		};
	} else {
		$ip = new Net::IP ($ip_string) or die (Net::IP::Error() . " '" . $ip_string . "'");
	};

	printf STDERR "Debug: check IP: %s (Version: %s)\n", $ip->ip(), $ip->version() if ($main::opts{'debug'} & 0x2000);
	if ($main::opts{'skip_ipv6'} && ($ip->version() == 6) ) {
		# skip IPv6

		# Fill cache
		$cache{$ip_string} = 1;

		return 1;
	};

	foreach my $net (@net_excluded) {
		if ( $ip->version() != $net->version() ) {
			# Skip incompatible types
			printf STDERR "Debug: skip check against %s/%s (incompatible)\n", $net->ip(), $net->prefixlen() if ($main::opts{'debug'} & 0x2000);
			next;
		};

		printf STDERR "Debug: check against IP: %s/%s (Version: %s)\n", $net->ip(), $net->prefixlen(), $net->version() if ($main::opts{'debug'} & 0x2000);

		my $result = $ip->overlaps($net);
		if ( $result == $Net::IP::IP_A_IN_B_OVERLAP || $result == $Net::IP::IP_IDENTICAL) {
			# Fill cache
			$cache{$ip_string} = 1;

			return 1;
		};
	};

	# Fill cache
	$cache{$ip_string} = 0;

	return 0;
};


# Print some statistics
sub printstatistics() {
	# About cache usage
	my $requests = $cache_statistics{'new'} + $cache_statistics{'hit'};

	if ($requests == 0) { return; };	

	my $ratehit_percent = ($cache_statistics{'hit'} / $requests) * 100;

	print "# module '" . $module_name . "' internal cache usage:\n";
	print "#        requests=" . $requests . " hits=" . $cache_statistics{'hit'};
	printf " (%2.1f%%)\n", $ratehit_percent;
};



## End of module
return 1;
