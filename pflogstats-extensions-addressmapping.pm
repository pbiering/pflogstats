#!/usr/bin/perl -w

###
# Project:     pflogstats
# Module:      pflogstats-extensions-addressmapping.pm
# Description: Address mapping module
# Copyright:   Dr. Peter Bieringer <pbieringer at aerasec dot de>
#               AERAsec GmbH <http://www.aerasec.de/> 
# License:     GNU GPL v2
# CVS:         $Id: pflogstats-extensions-addressmapping.pm,v 1.13 2005/04/26 15:58:14 peter Exp $
###

## ChangeLog
#	0.01:
#	 - initial
#	0.02:
#	 - add support of regexp
#	0.03:
#	 - don't modify special bounce addresses
#       0.04
#        - make Perl 5.0 compatible
#	0.05
#	 - display table contents only in verbose mode
#	0.06
#	 - add caching and statistics
##

use strict;


## Local constants
my $module_type = "extensions";
my $module_name = $module_type . "-addressmapping";
my $module_version = "0.06";

## Export module info
$main::moduleinfo{$module_name}->{'version'} = $module_version;
$main::moduleinfo{$module_name}->{'type'} = $module_type;
$main::moduleinfo{$module_name}->{'name'} = $module_name;

## Global prototyping
sub beforemainloopstarts();
sub modifyaddress($);
sub help();


## Local prototyping
sub read_address_mapping($);


## Register options
$main::options{'addressmapping_file=s'} = \$main::opts{'addressmapping_file'};


## Register calling hooks
$main::hooks{'beforemainloopstarts'}->{$module_name} = \&beforemainloopstarts;
$main::hooks{'modifyaddress'}->{$module_name} = \&modifyaddress;
$main::hooks{'help'}->{$module_name} = \&help;
$main::hooks{'print_additional_statistics'}->{$module_name} = \&printstatistics;


## Local variables
my %address_mapping;
my %address_mapping_evalpattern;
my %cache;
my %cache_statistics;
$cache_statistics{'new'} = 0;
$cache_statistics{'hit'} = 0;


## Global callable functions

# Help
sub help() {
	my $helpstring = "
    Extension: addressmapping
    [--addressmapping_file <file>]  maps addresses into another addresses
                                     format: 2 colums
                                      regular expressions are also supported
";
	return $helpstring;
};

# Initialization
sub beforemainloopstarts() {
	# print "Called: " . $module_name . "/" . "beforemainloopstarts" . "\n";

	# Read file contents
	if (defined $main::opts{'addressmapping_file'} ) {
		&read_address_mapping($main::opts{'addressmapping_file'});
	};
};

# Modify an address depeding on mapping
sub modifyaddress($) {
	my $address_new;

	my $address = shift || die "ERROR: arg1 (address) missing";

	if (defined $cache{$address}) {
		$cache_statistics{'hit'}++;
		return $cache{$address};
	} else {
		$cache_statistics{'new'}++;
	};

	# Do not modify special bounce addresses
	if ($address eq "from=<>" || $address eq "from=<#@[]>") {
		$cache{$address} = $address;
		return $address;
	};

	# Simple replacement
	if (defined $address_mapping{$address} ) {
		# Match, so replace
		$address_new = $address_mapping{$address};
		$cache{$address} = $address_new;
		return $address_new;
	};

	# regex support
	print STDERR "Check against pattern: " . $address . "\n" if ($main::opts{'debug'} & 0x1000);
	for my $pattern ( keys %address_mapping ) {
		print STDERR "Pattern: " . $pattern . "\n" if ($main::opts{'debug'} & 0x1000);
		if ( $address =~ /^$pattern$/ ) {
			#print STDERR "Patternmatch: " . $address . "\n" if ($main::opts{'debug'} & 0x1000);
			$address_new = eval $address_mapping_evalpattern{$pattern};
			if (! defined $address_new) { $address_new = "EMPTY_ADDRESS"; };
			print STDERR "Replaced: " . $address_new . "\n" if ($main::opts{'debug'} & 0x1000);
			$cache{$address} = $address_new;
			return $address_new;
		};
	};
	
	# Nothing to do
	$cache{$address} = $address;
	return $address;
};


## Local functions

# Read address mapping file
sub read_address_mapping($) {
	my $filename = shift || die "ERROR: arg1 (filename) missing";
	my ($address_found, $address_replacement);

	# open file
	open(ADDRESSMAPPING,"<" . $filename) || die "ERROR: cannot open: " . $filename;

	# read file contents
	while(<ADDRESSMAPPING>) {
		#printf STDERR $_ if ($opts{'debug'} & 0x0040);
		$_ =~ s/([^#]*)#.*/$1/; # Remove comments
                $_ =~ s/[[:space:][:cntrl:]]+$//; # Remove trailing spaces and control chars
                $_ =~ s/^[[:space:][:cntrl:]]+//; # Remove leading spaces and control chars
                if ( length($_) == 0 ) { next; }; # Skip empty lines
	
		# Split
		($address_found, $address_replacement) = split " ", $_, 2;

		if ( (defined $address_found) && (defined $address_replacement) ) {
			if ( (length($address_found) > 0) && (length($address_replacement) > 0) ) {
				if (! defined $address_mapping{$address_found} ) {
					$address_mapping{$address_found} = $address_replacement;

					# Generate eval pattern
					$address_replacement =~ s/@/\\@/;
					$address_replacement = "return \"" . $address_replacement . "\"";
					$address_mapping_evalpattern{$address_found} = $address_replacement;
				} else {
					warn "WARNING: 1st value already found and defined, therefore skipped in " . $filename;
				};
			} else {
				warn "WARNING: line isn't valid and therefore skipped in " . $filename;
			};
		} else {
			warn "WARNING: line isn't valid and therefore skipped in " . $filename;
		};
	};

	close(ADDRESSMAPPING);

	# Print contents (debug)
        if ( scalar (keys %address_mapping) > 0 ) {
		if (defined $main::opts{'verbose'}) {
			print '='x79 . "\n";
			print "Address mapping table\n";
			print '-'x79 . "\n";
			for $address_found (keys %address_mapping) {
				print $address_found . " -> " . $address_mapping{$address_found} . "\n";
			};
			print '='x79 . "\n";
		};
        };
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
