#!/usr/bin/perl -w

###
# Project:     pflogstats
# Module:      pflogstats-statistics-uce.pm
# Type:        statistics
# Description: Statistics module for accounting
# Copyright:   (P) & (C) 2003 - 2006 by Peter Bieringer <pbieringer at aerasec dot de>
#               AERAsec GmbH <http://www.aerasec.de/> 
# License:     GNU GPL v2
# CVS:         $Id: pflogstats-statistics-uce.pm,v 1.13 2006/08/01 13:36:39 peter Exp $
###

## ChangeLog
#	0.01
#	 - initial split-off
#	0.02
#	 - enable domain treeview code
#	 - support new format code style
#	0.03
#	 - reimplement logline parser for standalone usage (no longer old pflogsumm code is used)
#	0.04
#	 - minor improvements
#	0.05
#	 - fix a bug in qid match (to catch older postfix versions loglines, too)
#	0.06
#	 - enhance bugfix in qid match
#       0.07
#        - make Perl 5.0 compatible
#	0.08
#	 - replace option "treeview" by "show_domain_list"
#	 - add support for intermediate data storage
#	0.09
#	 - move info about show_user|domain_list into options-support
#	0.10
#	 - proper handling of bad e-mail addresses
#	0.11
#	 - reorganize hook names
#	0.12
#	 - [adj] regex now supports qid with 12 hexdigits
##

use strict;


## Local constants
my $module_type = "statistics";
my $module_name = $module_type . "-uce";
my $module_version = "0.12";

package pflogstats::statistics::uce;

## Export module info
$main::moduleinfo{$module_name}->{'version'} = $module_version;
$main::moduleinfo{$module_name}->{'type'} = $module_type;
$main::moduleinfo{$module_name}->{'name'} = $module_name;

# Global prototyping


## Local prototyping


## Register options


## Register calling hooks
$main::hooks{'print_result'}->{$module_name} = \&print_result;
$main::hooks{'checkoptions'}->{$module_name} = \&checkoptions;
$main::hooks{'help'}->{$module_name} = \&help;
$main::hooks{'loglineparser'}->{$module_name} = \&loglineparser;
$main::hooks{'loop_afterfinish'}->{$module_name} = \&loop_afterfinish;
$main::hooks{'before_print_result'}->{$module_name} = \&before_print_result;

# Define type
$main::types{'uce'} = 0;

## Global variables

## Local variables
# Message counters for statistics
my $uceCounter;
# UCE statistics per recipient
my %uceStatsRecipient;
# UCE statistics per recipient domain
my %uceStatsRecipientDomain;
# UCE statistics per sender
my %uceStatsSender;
# UCE statistics per sender domain
my %uceStatsSenderDomain;
# UCE statistics per blocklist
my %uceStatsBlocklist;
# UCE statistics per relay
my %uceStatsRelay;
# UCE treeview
my %uceTreeview;


## Global callable functions

# Help
sub help() {
	my $helpstring = "
    Type: uce
    [-e]                         Extended logging mode parsing logfile
";
	return $helpstring;
};


# Check options
sub checkoptions() {
};


# Parse logline
sub loglineparser(\$\$) {
	return if ( $main::types{'uce'} == 0);

	if (! defined $_[0]) { die "Missing time pointer (arg1)"; };
	if (! defined $_[1]) { die "Missing logline pointer (arg2)"; };

	my ($rejectreason);
	my ($from, $to, $from_domain, $to_domain, $rblserver, $relay);

	# Example: Jan  1 02:55:16 host postfix/smtpd[13756]: D00C713866: reject: RCPT from unknown[212.251.10.251]: 554 Service unavailable; Client host [212.251.10.251] blocked using relays.ordb.org; This mail was handled by an open relay - please visit <http://ORDB.org/lookup/?host=212.251.10.251>; from=<bulkemail@flash.net> to=<account@example.com> proto=ESMTP helo=<jcsc.nato.int>
	#print "DEBUG(uce/loglineparser): get: '" . ${$_[1]} . "\n";
	if (! ( ${$_[1]} =~ /^.*\spostfix\/smtpd\[[0-9]+\]: ([A-F0-9]{8,12}: )?reject: RCPT from (\S+): (.*)$/o ) ) {
		# Unmatched logline
		return;
	};

	$relay = $2;
	$rejectreason = $3;

	#print "DEBUG(uce/loglineparser): RCPT: '" . $rejectreason . "'\n";

	#$rejectreason =~ s/^(?:.*?[:;] )(?:\[[^\]]+\] )?([^;,]+)[;,].*$/$1/oi;
	#$rejectreason =~ s/^(?:.*[:;] )?([^,]+).*$/$1/o;

	#print "DEBUG(uce/loglineparser): stripped reason: '" . $rejectreason . "'\n";

	if (! ( $rejectreason =~ / blocked using ([^ ]+);/o)) {
		# Not interesting
		return;
	};
	$rblserver = $1;

	#print "DEBUG(uce/loglineparser): RBL: '" . $rejectreason . "\n";


	if ($rejectreason =~ / from=<(.*)> to=<(.*)> proto/o ) {
		$from = lc($1);
		$to   = lc($2);
	} else {
		# Not interesting
		return;
	};

	if ($from eq "") { $from = "from=<>" };
	if ($from eq "#@[]") { $from = "from=<#@[]>"; };

	## Currently not needed
	## Hook "modifyaddress"
	#for my $p_hook (keys %{$main::hooks{'modifyaddress'}}) {
	#	$from = &{$main::hooks{'modifyaddress'}->{$p_hook}} ($from);
	#	$to   = &{$main::hooks{'modifyaddress'}->{$p_hook}} ($to);
	#};

	$from_domain = ::extract_domain($from);
	$to_domain   = ::extract_domain($to);

	$uceStatsRecipient{$to}++;
	$uceStatsRecipientDomain{$to_domain}++;
	$uceStatsSender{$from}++;
	$uceStatsSenderDomain{$from_domain}++;
	$uceStatsBlocklist{$rblserver}++;
	$uceStatsRelay{$relay}++;

	$uceCounter++;
	$uceTreeview{$to_domain}->{$to}->{$rblserver}->{$from}++;
};


# After loop finished
sub loop_afterfinish() {
	## Hook 'register_intermediate_data'
	for my $p_hook (keys %{$main::hooks{'register_intermediate_data'}}) {
        	&{$main::hooks{'register_intermediate_data'}->{$p_hook}} ("uceTreeview", \%uceTreeview);
        	&{$main::hooks{'register_intermediate_data'}->{$p_hook}} ("uceStatsRecipient", \%uceStatsRecipient);
        	&{$main::hooks{'register_intermediate_data'}->{$p_hook}} ("uceStatsRecipientDomain", \%uceStatsRecipientDomain);
        	&{$main::hooks{'register_intermediate_data'}->{$p_hook}} ("uceStatsSender", \%uceStatsSender);
        	&{$main::hooks{'register_intermediate_data'}->{$p_hook}} ("uceStatsSenderDomain", \%uceStatsSenderDomain);
        	&{$main::hooks{'register_intermediate_data'}->{$p_hook}} ("uceStatsBlocklist", \%uceStatsBlocklist);
        	&{$main::hooks{'register_intermediate_data'}->{$p_hook}} ("uceStatsRelay", \%uceStatsRelay);
	};
};


# Before printing result
sub before_print_result() {
	## Hook 'retrieve_intermediate_data'
	for my $p_hook (keys %{$main::hooks{'retrieve_intermediate_data'}}) {
        	&{$main::hooks{'retrieve_intermediate_data'}->{$p_hook}} ("uceTreeview", \%uceTreeview);
        	&{$main::hooks{'retrieve_intermediate_data'}->{$p_hook}} ("uceStatsRecipient", \%uceStatsRecipient);
        	&{$main::hooks{'retrieve_intermediate_data'}->{$p_hook}} ("uceStatsRecipientDomain", \%uceStatsRecipientDomain);
        	&{$main::hooks{'retrieve_intermediate_data'}->{$p_hook}} ("uceStatsSender", \%uceStatsSender);
        	&{$main::hooks{'retrieve_intermediate_data'}->{$p_hook}} ("uceStatsSenderDomain", \%uceStatsSenderDomain);
        	&{$main::hooks{'retrieve_intermediate_data'}->{$p_hook}} ("uceStatsBlocklist", \%uceStatsBlocklist);
        	&{$main::hooks{'retrieve_intermediate_data'}->{$p_hook}} ("uceStatsRelay", \%uceStatsRelay);
	};
};


# print result
sub print_result() {
	return if ( $main::types{'uce'} == 0);

	my $format;

	# Format: treeview
	if (defined $main::format{"treeview"}) {
		$format = "treeview";
		my $info = "";
		if (defined $main::opts{'show_domain_list'}) {
			$main::opts{'show_domain_list'} =~ s/,/ /g;
			if ($main::opts{'show_domain_list'} ne "") {
				$info .= ":\n " . $main::opts{'show_domain_list'};
			};
		};

		::print_headline("UCE statistics " . $info, $format);
		::print_timerange($format);

		::print_treeview( \%uceTreeview, $main::opts{'show_domain_list'} );
	};

	# Format: computer
	if (defined $main::format{"computer"}) {
		$format = "computer";
		print "\n\nWARNING(uce): Format '" . $format . "' is currently not supported!\n\n";
	};

	# Format: indented
	if (defined $main::format{"indented"}) {
		$format = "indented";
		print "\n\nWARNING(uce): Format '" . $format . "' is currently not supported!\n\n";
	};

	# Format: txttable
	if (defined $main::format{"txttable"}) {
		$format = "txttable";
		::print_headline("UCE statistics", $format);
		::print_timerange($format);

		::print_stat "Per recipient"        , \%uceStatsRecipient if (defined $main::opts{'show_users'});
		::print_stat "Per recipient domain" , \%uceStatsRecipientDomain;
		::print_stat "Per sender"           , \%uceStatsSender if (defined $main::opts{'show_users'});
		::print_stat "Per sender domain"    , \%uceStatsSenderDomain;
		::print_stat "Per relay"            , \%uceStatsRelay;
		::print_stat "Per blocklist"        , \%uceStatsBlocklist;
	};
};


## Local functions




## End of module
return 1;
