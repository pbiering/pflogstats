#!/usr/bin/perl -w

###
# Project:     pflogstats
# Module:      pflogstats-common-intermediatexml.pm
# Description: Intermediate XML save/load
# Copyright:   Dr. Peter Bieringer <pbieringer at aerasec dot de>
#               AERAsec GmbH <http://www.aerasec.de/> 
# License:     GNU GPL v2
# CVS:         $Id: pflogstats-common-intermediatexml.pm,v 1.2 2003/12/23 17:51:47 rootadm Exp $
###

###
# ChangeLog:
#	0.01
#	 - initial (template: common-profiling)
#	0.02
#	 - add a XML::Dumper version check (0.40 is broken)
#	 - review debug code
###

## Todo:
##

use strict;
use XML::Dumper;

package pflogstats::common::intermediatexml;


## Local constants
my $module_type = "common";
my $module_name = $module_type . "-intermediatexml";
my $module_version = "0.02";

## Module tests
# XML::Dumper version 0.40 is broken, cannot handle ' in hash key
die $module_name . " uses XML::Dumper, but version " . $XML::Dumper::VERSION . " doesn't support used features (use at least 0.67)" if  ($XML::Dumper::VERSION <= 0.40);

# Successful test with 0.67
warn $module_name . " uses XML::Dumper, but version " . $XML::Dumper::VERSION . " wasn't tested" if  ($XML::Dumper::VERSION < 0.67);


## Export module info
$main::moduleinfo{$module_name}->{'version'} = $module_version;
$main::moduleinfo{$module_name}->{'type'} = $module_type;
$main::moduleinfo{$module_name}->{'name'} = $module_name;

## Global prototyping

## Local prototyping

## Global variables

## Register options
$main::options{'save-intermediate-xml=s'} = \$main::opts{'save-intermediate-xml'};
$main::options{'load-intermediate-xml=s'} = \$main::opts{'load-intermediate-xml'};


## Register calling hooks
$main::hooks{'help'}->{$module_name} = \&help;
$main::hooks{'intermediate_storage'}->{$module_name} = \&intermediate_storage;
$main::hooks{'register_intermediate_data'}->{$module_name} = \&register_intermediate_data;
$main::hooks{'retrieve_intermediate_data'}->{$module_name} = \&retrieve_intermediate_data;


## Local variables
my %intermediate_data;


## Global callable functions

# Help
sub help() {
	my $helpstring = "
    [--save-intermediate-xml <filename>]       Save intermediate XML data
    [--load-intermediate-xml <filename>]       Load intermediate XML data
     <filename> may be a .gz, if Compress::Zlib is installed
    [--debug <debug>]                          Debug value
                                                | 0x8000 : show some steps
";
	return $helpstring;
}


# Register data for intermediate storage
sub register_intermediate_data($ \%) {
	if (! defined $main::opts{'save-intermediate-xml'}) {
		# nothing to do
		return 0;
	};

	print "DEBUG(" . $module_name . "): register data: " . $_[0] . "\n" if ($main::opts{'debug'} & 0x8000);
	$intermediate_data{$_[0]} = $_[1];
};

# Retrieve data from intermediate storage
sub retrieve_intermediate_data($ \%) {
	if (! defined $main::opts{'load-intermediate-xml'}) {
		# nothing to do
		return 0;
	};

	print "DEBUG(" . $module_name . "): retrieve data: " . $_[0] . "\n" if ($main::opts{'debug'} & 0x8000);
	%{$_[1]} = %{$intermediate_data{$_[0]}};
};


# Intermediate storage saving
sub intermediate_storage($ \%) {
	my $dump;
	my $xml;

	if (defined $main::opts{'save-intermediate-xml'}) {
		# save data to XML file
		print "INFO(" . $module_name . "): save data as XML to: " . $main::opts{'save-intermediate-xml'} . "\n";

		$dump = new XML::Dumper;
		$xml = $dump->pl2xml(\%intermediate_data, $main::opts{'save-intermediate-xml'});
		if ($? != 0) {
			print STDERR "ERROR: can't open output XML file: " .  $main::opts{'save-intermediate-xml'} . ": " . $! . "\n";
			exit 5;
		};
		print "DEBUG(" . $module_name . "): save data as XML finished\n" if ($main::opts{'debug'} & 0x8000);
	};

	if (defined $main::opts{'load-intermediate-xml'}) {
		# load data from XML file
		print "INFO(" . $module_name . "): load data in XML from: " . $main::opts{'load-intermediate-xml'} . "\n";

		$dump = new XML::Dumper;
		my $ph = $dump->xml2pl($main::opts{'load-intermediate-xml'});
		if ($? != 0) {
			print STDERR "ERROR: can't open input XML file: " .  $main::opts{'load-intermediate-xml'} . ": " . $! . "\n";
			exit 5;
		};

		%intermediate_data = %$ph;
		for my $key (keys %intermediate_data) {
			print "DEBUG(" . $module_name . "): get subtree: " . $key . "\n" if ($main::opts{'debug'} & 0x8000);
		};
		print "DEBUG(" . $module_name . "): load data in XML finished\n" if ($main::opts{'debug'} & 0x8000);
	};
};

## End of module
return 1;
