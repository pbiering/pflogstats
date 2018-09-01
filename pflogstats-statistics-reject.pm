#!/usr/bin/perl -w

###
# Project:     pflogstats
# Module:      pflogstats-statistics-reject.pm
# Type:        statistics
# Description: Statistics module for accounting
# Copyright:   (P) & (C) 2003 - 2006 by Peter Bieringer <pbieringer at aerasec dot de>
#               AERAsec GmbH <http://www.aerasec.de/> 
# License:     GNU GPL v2
# CVS:         $Id: pflogstats-statistics-reject.pm,v 1.24 2006/08/01 13:36:39 peter Exp $
###

## ChangeLog
#	0.01
#	 - initial split-off
#	0.02
#	 - add hook "rblblocked"
#	0.03
#	 - print timerange on table header, remove "Counts" on second column header
#	 - reenable domain treeview code
#	0.04
#	 - support new format code style
#	0.05
#	 - adjust loglineparser arguments
#	0.06
#	 - reimplement logline parser for standalone usage (no longer old pflogsumm code is used)
#	0.07
#	 - fix a bug in qid match (to catch older postfix versions loglines, too)
#	0.08
#	 - enhance bugfix in qid match
#       0.09
#        - make Perl 5.0 compatible
#	0.10
#	 - fix code for "Message size exceeds" without from/to logging
#	0.11
#	 - enhance code for body_check rejects
#	 - add option "--reject_skip_sender_statistic"
#	 - add option "--reject_show_clients"
#	0.12
#	 - change data for "--reject_show_clients"
#	0.13
#	 - adjust "--reject_show_clients", disable per user if selected
#	0.14
#	 - add support for intermediate data storage
#	 - replace option "treeview" by "show_domain_list"
#	0.15
#	 - move info about show_user|domain_list into options-support
#	0.16
#	 - proper handling of bad e-mail addresses
#	0.17
#	 - reorganize hook names
#	0.18
#	 - [adj] regex now supports qid with 12 hexdigits
##

use strict;


## Local constants
my $module_type = "statistics";
my $module_name = $module_type . "-reject";
my $module_version = "0.18";

package pflogstats::statistics::reject;

## Export module info
$main::moduleinfo{$module_name}->{'version'} = $module_version;
$main::moduleinfo{$module_name}->{'type'} = $module_type;
$main::moduleinfo{$module_name}->{'name'} = $module_name;

# Global prototyping


## Local prototyping


## Register options
$main::options{'reject_skip_sender_statistic'} = \$main::opts{'reject_skip_sender_statistic'};
$main::options{'reject_show_clients'} = \$main::opts{'reject_show_clients'};


## Register calling hooks
$main::hooks{'print_result'}->{$module_name} = \&print_result;
$main::hooks{'checkoptions'}->{$module_name} = \&checkoptions;
$main::hooks{'help'}->{$module_name} = \&help;
$main::hooks{'loglineparser'}->{$module_name} = \&loglineparser;
$main::hooks{'loop_afterfinish'}->{$module_name} = \&loop_afterfinish;
$main::hooks{'before_print_result'}->{$module_name} = \&before_print_result;

# Define type
$main::types{'reject'} = 0;

## Global variables

## Local variables
my %rejectTreeview;
my %rejectTreeviewClients;
my %rejects;

## Global callable functions

# Help
sub help() {
	my $helpstring = "
    Type: reject
    [--debug <debug>]                Debug value
                                      | 0x0001 : show reject after match
                                      | 0x0002 : show log before match

    [--reject_skip_sender_statistic] Do not show per sender statistics
                                  (rather long since 'Sobig' and body_check)
    [--reject_show_clients]          Show reject statistics per client, not per user

";
	return $helpstring;
};


# Check options
sub checkoptions() {
	# Nothing to check
};


# Parse logline
sub loglineparser(\$\$) {
	return if ( $main::types{'reject'} == 0);

	if (! defined $_[0]) { die "Missing time pointer (arg1)"; };
	if (! defined $_[1]) { die "Missing logline pointer (arg2)"; };

	# Currently nothing to do here
	
	my ($rejectinfo);
	my ($from, $to, $from_domain, $to_domain, $rblserver, $relay);

	my ($rejFrom, $rejTyp, $rejRmdr, $rejData, $rejReas);

	print "DEBUG(reject/loglineparser): get: '" . ${$_[1]} . "\n" if ($main::opts{'debug'} & 0x0002 );

	if (${$_[1]} =~ /^.*\spostfix\/smtpd\[[0-9]+\]: ([A-F0-9]{8,12}: )?reject: (.*)$/o ) {
		# Example: Jan  1 02:55:16 host postfix/smtpd[13756]: D00C713866: reject: ....
		# ok
	} elsif ( ${$_[1]} =~ /^.*\spostfix\/smtpd\[[0-9]+\]: (NOQUEUE: )?reject: (.*)$/o ) {
		# Example: Aug 14 08:03:42 host postfix/smtpd[19256]: NOQUEUE: reject: MAIL from host.domain.example[1.2.3.4.]: 552 Message size exceeds fixed limit; proto=ESMTP helo=<host.domain.example>
		# ok
	} elsif (${$_[1]} =~ /^.*\spostfix\/cleanup\[[0-9]+\]: ([A-F0-9]{8,12}: )?reject: (.*)$/o ) {
		#  Example: Aug 22 12:37:26 postfix postfix/cleanup[24933]: 6B8A9137E6: reject: body RSLxwtYBDB6FCv8ybBcS0zp9VU5of3K4BXuwyehTM0RI9IrSjVuwP94xfn0wgOjouKWzGXHVk3qg from brmea-mail-3.Sun.COM[192.18.98.34]; from=<> to=<rcpt@domain.example> proto=ESMTP helo=<brmea-mail-3.sun.com>: 554 Please clean your infected system (I-Worm.Sobig.f)
		# ok
	} else {
		# Unmatched logline
		return;
	};

	print "DEBUG(reject/loglineparser): match: '" . ${$_[1]} . "'\n" if ($main::opts{'debug'} & 0x0001 );

	$rejectinfo = $2;

	# First: get everything following the "reject: " token
	($rejTyp, $rejFrom, $rejRmdr) = $rejectinfo =~ /^(.*) from (\S+)[:;] (.*)$/o;

	# Next: get the reject "reason"
	$rejReas = $rejRmdr;

	print "DEBUG(reject/loglineparser): rejReas: '" . $rejReas . "'\n" if ($main::opts{'debug'} & 0x0001 );
	print "DEBUG(reject/loglineparser): rejTyp: '" . $rejTyp . "'\n" if ($main::opts{'debug'} & 0x0001 );

	if (($rejTyp eq "RCPT") || ($rejTyp eq "MAIL")) {
		$rejReas =~ s/^(?:.*?[:;] )(?:\[[^\]]+\] )?([^;,]+)[;,].*$/$1/oi;
	} else {
		$rejReas =~ s/^(?:.*[:;] )?([^,]+).*$/$1/o;
	};

	print "DEBUG(reject/loglineparser): rejReas(mod): '" . $rejReas . "'\n" if ($main::opts{'debug'} & 0x0001 );

	print "DEBUG(reject/loglineparser): rejRmdr: '" . $rejRmdr . "'\n" if ($main::opts{'debug'} & 0x0001 );
	($from, $to) = $rejRmdr =~ / ?from=<(.*)> to=<(.*)> proto/o;


	if (defined $from) {
		if ($from eq "") { $from = "from=<>" };
		if ($from eq "#@[]") { $from = "from=<#@[]>"; };
		$from = lc ($from);

		# Hook "modifyaddress"
		for my $p_hook (keys %{$main::hooks{'modifyaddress'}}) {
			$from = &{$main::hooks{'modifyaddress'}->{$p_hook}} ($from);
		};

		$from_domain = ::extract_domain($from);
	} else {
		$from_domain = "UNKNOWN_FROM";
		$from = "UNKOWN_FROM";
	};

	if (defined $to) {
		$to   = lc ($to);
	
		# Hook "modifyaddress"
		for my $p_hook (keys %{$main::hooks{'modifyaddress'}}) {
			$to   = &{$main::hooks{'modifyaddress'}->{$p_hook}} ($to);
		};

		$to_domain = ::extract_domain($to);
	} else {
		$to_domain = "UNKNOWN_RCPT";
		$to = "UNKOWN_RCPT";
	};


	print "DEBUG(reject/loglineparser): from/to: '" . $from . "/" . $to . "'\n" if ($main::opts{'debug'} & 0x0001 );

	if($rejReas =~ m/^Sender address rejected:/o) {
		# Sender address rejected: Domain not found
		# Sender address rejected: need fully-qualified address
		# Sender address rejected: undeliverable sender address: ...
		if ($rejReas =~ /undeliverable sender address:/o) {
			$rejReas = "Sender address rejected: undeliverable sender address" ;
		} elsif ($rejReas =~ /unverified sender address:/o) {
			$rejReas = "Sender address rejected: unverified sender address" ;
		}

		# Fill reject data

	} elsif($rejReas =~ m/^Recipient address rejected:/o) {
		# Recipient address rejected: Domain not found
		# Recipient address rejected: need fully-qualified address

		# Fill reject data
		# Nothing to do

	} elsif($rejReas =~ s/^.*?\d{3} (Improper use of SMTP command pipelining);.*$/$1/o) {
		# Fill reject data
		# Nothing to do

	} elsif($rejReas =~ s/^.*?\d{3} (Message size exceeds fixed limit);.*$/$1/o) {
		# Fill reject data
		# Nothing to do

	} elsif ( $rejReas =~ /blocked using ([^ ]+)$/o ) {
		# Example: Jan  1 02:55:16 host postfix/smtpd[13756]: D00C713866: reject: RCPT from unknown[212.251.10.251]: 554 Service unavailable; Client host [212.251.10.251] blocked using relays.ordb.org; This mail was handled by an open relay - please visit <http://ORDB.org/lookup/?host=212.251.10.251>; from=<bulkemail@flash.net> to=<account@example.com> proto=ESMTP helo=<jcsc.nato.int>

		#print "DEBUG(reject/loglineparser/RBL): get: '" . ${$_[1]} . "\n";

		# Fill reject data
		$rejReas = 'Client host rejected: by RBL';

	} elsif ( $rejRmdr =~ /Client host rejected: cannot find your hostname/oi ) {
		# Example: Feb  1 15:29:46 host postfix/smtpd[10407]: E20D81386D: reject: RCPT from unknown[68.112.217.231]: 450 Client host rejected: cannot find your hostname, [68.112.217.231]; from=<martina4048c@lycos.com> to=<account@example.com> proto=SMTP helo=<mail.lycos.com>
		# Fill reject data
		$rejReas = 'Client host rejected: cannot find your hostname';

	} else {
		# Unhandled reject data
		#$rejData = ::extract_domain($rejFrom);
		#$rejData = $rejFrom;
	};

	$rejData = $from . " (" . $rejFrom . ")";

	# Fill data into hash
	$rejectTreeview{$to_domain}->{$to}->{$rejReas}->{$rejData}++;
	++$rejects{$rejTyp}{$rejReas}{$rejData};

	# Fill special hash
	#$rejectTreeviewClients{$to_domain}->{$to}->{$rejReas}->{$rejFrom}++;
	$rejectTreeviewClients{$rejFrom}->{$rejReas}->{$to}->{$from}++;
};


# After loop finished
sub loop_afterfinish() {
	## Hook 'register_intermediate_data'
	for my $p_hook (keys %{$main::hooks{'register_intermediate_data'}}) {
        	&{$main::hooks{'register_intermediate_data'}->{$p_hook}} ("rejectTreeview", \%rejectTreeview);
        	&{$main::hooks{'register_intermediate_data'}->{$p_hook}} ("rejectTreeviewClients", \%rejectTreeviewClients);
        	&{$main::hooks{'register_intermediate_data'}->{$p_hook}} ("rejects", \%rejects);
	};
};


# Before printing result
sub before_print_result() {
	## Hook 'retrieve_intermediate_data'
	for my $p_hook (keys %{$main::hooks{'retrieve_intermediate_data'}}) {
        	&{$main::hooks{'retrieve_intermediate_data'}->{$p_hook}} ("rejectTreeview", \%rejectTreeview);
        	&{$main::hooks{'retrieve_intermediate_data'}->{$p_hook}} ("rejectTreeviewClients", \%rejectTreeviewClients);
        	&{$main::hooks{'retrieve_intermediate_data'}->{$p_hook}} ("rejects", \%rejects);
	};
};


# print result
sub print_result() {
	return if ( $main::types{'reject'} == 0);

        #for my $key (keys %rejects) {
        #        print "DEBUG(" . $module_name . "): get sub-subtree: " . $key . "\n";
        #};

	my $counter;
	my $format;

	# Format: treeview
	if (defined $main::format{"treeview"}) {
		$format = "treeview";
		my $info = "";
		$info .= " (treeview)";

		if (defined $main::opts{'show_domain_list'}) {
			$main::opts{'show_domain_list'} =~ s/,/ /g;
		};

		if (defined $main::opts{'show_user_list'}) {
			$main::opts{'show_user_list'} =~ s/,/ /g;
			
			# add user domain to domain list, if missing
			foreach my $user (split / /, $main::opts{'show_user_list'}) {
				$user =~ /.*@([^@]+)$/;
				if (defined $1) {
					my $domain = $1;
					if ($main::opts{'show_domain_list'} =~ /^(.*\s)?$domain(\s.*)?/) {
						# in list
					} else {
						#print "DEBUG: add domain: " . $domain . "\n";		
						if (! defined $main::opts{'show_domain_list'} || $main::opts{'show_domain_list'} eq "") {
							$main::opts{'show_domain_list'} .= $domain;
						} else  {
							$main::opts{'show_domain_list'} .= " " . $domain;
						};
					};
				} else {
					die "e-mail address doesn't contain a domain part: " . $user;
				};
			};
		};

		if (defined $main::opts{'reject_show_clients'}) {
			::print_headline("REJECT statistics per client " . $info, $format);
			::print_treeview( \%rejectTreeviewClients, "" );
		} else {
			if (defined $main::opts{'show_domain_list'} && $main::opts{'show_domain_list'} ne "") {
				$info .= ":\n " . $main::opts{'show_domain_list'};	
			};
			if (defined $main::opts{'show_user_list'} && $main::opts{'show_user_list'} ne "") {
				$info .= ":\n " . $main::opts{'show_user_list'};	
			};
			::print_headline("REJECT statistics " . $info, $format);
			::print_timerange($format);
			if (! defined $main::opts{'reject_skip_sender_statistic'}) {
				::print_treeview( \%rejectTreeview, $main::opts{'show_domain_list'}, $main::opts{'show_user_list'} );
			} else {
				::print_treeview2( \%rejectTreeview, 3, $main::opts{'show_domain_list'}, $main::opts{'show_user_list'} );
			};
		};
	};

	# Format: computer
	if (defined $main::format{"computer"}) {
		$format = "computer";
		print "\n\nWARNING(reject): Format '" . $format . "' is currently not supported!\n\n";
	};

	# Format: indented
	if (defined $main::format{"indented"}) {
		$format = "indented";
		print "\n\nWARNING(reject): Format '" . $format . "' is currently not supported!\n\n";
	};

	# Format: txttable
	if (defined $main::format{"txttable"}) {
		$format = "txttable";
		::print_headline("REJECT statistics", $format);
		::print_timerange($format);

		print '=' x $main::opts{'print-max-width'} . "\n";
		printf "Reason\n";
		::print_timerange_normal();
		print '-' x $main::opts{'print-max-width'} . "\n";
		my $mastercounter = 0;
		for my $rejTyp (sort keys %rejects) {
			for my $rejReas (sort keys %{$rejects{$rejTyp}}) {
				my $counter = 0;
				for my $rejRmdr (keys %{$rejects{$rejTyp}->{$rejReas}}) {
					$counter += $rejects{$rejTyp}->{$rejReas}->{$rejRmdr};
				};
				printf "%-*s : %7d\n", $main::opts{'print-max-width'} - 10, substr($rejTyp . ":" . $rejReas,0, 65), $counter;
				$mastercounter += $counter;
			};
		};		
		print '-' x $main::opts{'print-max-width'} . "\n";
		printf "%-*s : %7d\n", $main::opts{'print-max-width'} -10, "Sum:", $mastercounter;
		print '=' x $main::opts{'print-max-width'} . "\n";
	};
};



## Local functions




## End of module
return 1;
