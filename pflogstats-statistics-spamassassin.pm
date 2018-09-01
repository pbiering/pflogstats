#!/usr/bin/perl -w

###
# Project:     pflogstats
# Module:      pflogstats-statistics-spamassassin.pm
# Type:        statistics
# Description: Statistics module for spamassassin
# Copyright:   Dr. Peter Bieringer <pbieringer at aerasec dot de>
#               AERAsec GmbH <http://www.aerasec.de/> 
# License:     GNU GPL v2
# CVS:         $Id: pflogstats-statistics-spamassassin.pm,v 1.8 2005/04/26 15:55:48 peter Exp $
###

###
# ChangeLog:
#	0.01
#	 - initial copy of -antivirus 0.09 and implement basics
#	0.02
#	 - remove appending of mydomain to local accounts
#	0.03
#	 - replace all hash references with proper code
#	0.04
#	 - make Perl 5.0 compatible, minor cleanup
#	0.05
#	 - reorganize hook names
###

use strict;


## Local constants
my $module_type = "statistics";
my $module_name = $module_type . "-spamassassin";
my $module_version = "0.05";

package pflogstats::statistics::spamassassin;

## Export module info
$main::moduleinfo{$module_name}->{'version'} = $module_version;
$main::moduleinfo{$module_name}->{'type'} = $module_type;
$main::moduleinfo{$module_name}->{'name'} = $module_name;

## Global prototyping

## Local prototyping


## Register options

## Register calling hooks
$main::hooks{'loglineparser'}->{$module_name} = \&loglineparser;
$main::hooks{'print_result'}->{$module_name} = \&print_result;
$main::hooks{'checkoptions'}->{$module_name} = \&checkoptions;
$main::hooks{'help'}->{$module_name} = \&help;

# Define type
$main::types{'spamassassin'} = 0;

## Global variables

## Local variables
my ($type, $rate, $limit, $to, $time);
my ($p_hook);

## Spamassassin counters
my $spamassasin_counter_ham = 0;
my $spamassasin_counter_spam = 0;

# per User
my %spamassassinUserStats;
# per Domain
my %spamassassinDomainStats;


## Global callable functions

# Help
sub help() {
	my $helpstring = "
    Type: spamassassin
    [--debug <debug>]            Debug value
                                    | 0x0100 : display native spamassassin log lines
                                    | 0x0200 : display extracted spamassassin log lines
";
	return $helpstring;
};

# Check options
sub checkoptions() {
	# Nothing to do
};

# Parse logline
sub loglineparser(\$\$) {
	return if ( $main::types{'spamassassin'} == 0);

	if (! defined $_[0]) { die "Missing time pointer (arg1)"; };
	if (! defined $_[1]) { die "Missing logline pointer (arg2)"; };

	#print ${$_[1]} . "\n";

	# Looking for spamassassin daemon lines, nothing else 
	return unless ( ${$_[1]} =~ /.*spamd\[\d+\]: / );

	if ( ${$_[1]} =~ /.*spamd\[\d+\]: identified spam / ) {
		$type = "spam";
		$spamassasin_counter_spam++;
	} elsif ( ${$_[1]} =~ /.*spamd\[\d+\]: clean message / ) {
		$type = "ham";
		$spamassasin_counter_ham++;
	} else {
		return;
	};

	if ( ${$_[1]} =~ /.* identified spam \(([\d\.]+)\/([\d\.]+)\) for (.*):[\d]+ in ([\d\.]+) seconds, [\d]+ bytes.$/o ) {
		printf STDERR "DEBUG: SpamAssassin: %s\n", ${$_[1]} if ($main::opts{'debug'} & 0x0100 ) ;

		return if ( ! defined $1 && ! defined $1 && ! defined $3 && ! defined $4 );
		return if ( $1 eq "" && $2 eq "" && $3 eq "" && $4 eq "");
		
		$rate = $1;
		$limit = $2;
		$to = lc($3);
		$time = $4;

		# Append domain to user
		#if (! ( $to =~ /@/o ) ) {
		#	$to .= "@" . $main::opts{'mydomainname'};
		#};

		# Hook "modifyaddress"
		for $p_hook (keys %{$main::hooks{'modifyaddress'}}) {
			$to   = &{$main::hooks{'modifyaddress'}->{$p_hook}} ($to);
		};
		
		$spamassassinUserStats{'to'}->{$to}++;
		$spamassassinDomainStats{'to'}->{::extract_domain($to)}++;
		printf STDERR "DEBUG: Spamassassin: to=%s msg=%s\n", $to if ($main::opts{'debug'} & 0x0200 ) ;
	};
	return;
};


# Print result
sub print_result() {
	return if ( $main::types{'spamassassin'} == 0);

	my $info = "";
	my $format;

	# Format: treeview
	if (defined $main::format{"treeview"}) {
		$format = "computer";
		print "\n\nWARNING(av): Format '" . $format . "' is currently not supported!\n\n";
	};

	# Format: computer
	if (defined $main::format{"computer"}) {
		$format = "computer";
		print "\n\nWARNING(av): Format '" . $format . "' is currently not supported!\n\n";
	};

	# Format: indented
	if (defined $main::format{"indented"}) {
		$format = "indented";
		print "\n\nWARNING(av): Format '" . $format . "' is currently not supported!\n\n";
	};

	# Format: txttable
	if (defined $main::format{"txttable"}){
		$format = "txttable";
		::print_headline("Spamassassin statistics" . $info, $format);
		::print_timerange($format);

		::print_stat "Spamassassin statistics per recipient"        . $info, $spamassassinUserStats{'to'} if (defined $main::opts{'show_users'});
		::print_stat "Spamassassin statistics per recipient domain" . $info, $spamassassinDomainStats{'to'};
	};
};


## Local functions

## End of module
return 1;
