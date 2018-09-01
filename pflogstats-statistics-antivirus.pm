#!/usr/bin/perl -w

###
# Project:     pflogstats
# Module:      pflogstats-statistics-antivirus.pm
# Type:        statistics
# Description: Statistics module for antivirus
# Copyright:   Dr. Peter Bieringer <pbieringer at aerasec dot de>
#               AERAsec GmbH <http://www.aerasec.de/> 
# License:     GNU GPL v2
# CVS:         $Id: pflogstats-statistics-antivirus.pm,v 1.22 2005/04/26 15:55:48 peter Exp $
###

###
# ChangeLog:
#	0.01
#	 - initial creation
#	0.02
#	 - add types hash
#	 - check also reject lines for I-Worm.Sobig (big@boss.com)
#	0.03
#	 - support new format code style
#	0.04
#	 - some speed-ups
#       0.05
#	 - adjust loglineparser arguments
#	0.06
#	 - tag some match patterns with "o"
#	0.07
#	 - check special from addresses
#	0.08
#	 - enable addressmodify hook for reject match also
#	0.09
#	 - replace warning on empty information with a token
#	0.10
#	 - replace all hash references with proper code
#       0.11
#        - make Perl 5.0 compatible
#	0.12
#	 - add support for Sobig.f body_check log line
#	 - be more relaxed on extractin info from avcheck lines
#	 - add option "--av_skip_sender_statistic"
#	0.13
#	 - replace option "treeview" by "show_domain_list"
#	 - add support for intermediate data storage
#	0.14
#	 - move info about show_user|domain_list into options-support
#	0.15
#	 - extend reject/discard for Kaspersky AV to I-Worm.*
#	 - add support for newer amavis log lines
#	 - add support for av_type=amavis (also default now)
#	0.16
#	 - proper handling of bad e-mail addresses
#	0.17
#	 - catch also "warning: (virus message)" on Kaspersky AV
#	0.18
#	 - extend log line parser of amavis
#	 - fix Eicar detection
#	 - minor code optimization
#	0.19
#	 - reorganize hook names
###

use strict;


## Local constants
my $module_type = "statistics";
my $module_name = $module_type . "-antivirus";
my $module_version = "0.19";

package pflogstats::statistics::antivirus;

## Export module info
$main::moduleinfo{$module_name}->{'version'} = $module_version;
$main::moduleinfo{$module_name}->{'type'} = $module_type;
$main::moduleinfo{$module_name}->{'name'} = $module_name;

## Global prototyping

## Local prototyping


## Register options
$main::options{'av_skip_eicar'} = \$main::opts{'av_skip_eicar'};
$main::options{'av_skip_sender_statistic'} = \$main::opts{'av_skip_sender_statistic'};
$main::options{'av_type:s'} = \$main::opts{'av_type'};


## Register calling hooks
$main::hooks{'loglineparser'}->{$module_name} = \&loglineparser;
$main::hooks{'print_result'}->{$module_name} = \&print_result;
$main::hooks{'checkoptions'}->{$module_name} = \&checkoptions;
$main::hooks{'help'}->{$module_name} = \&help;
$main::hooks{'loop_afterfinish'}->{$module_name} = \&loop_afterfinish;
$main::hooks{'before_print_result'}->{$module_name} = \&before_print_result;


# Define type
$main::types{'av'} = 0;

## Global variables

## Local variables
my ($from, $to, $avMsg, $to_new);
my ($p_hook);

## Antivirus statistics
my $antivirusCounter;
# per User
my %antivirusUserStats;
# per Domain
my %antivirusDomainStats;
# per Virus
my %antivirusVirusStats;
# for treeview
my %antivirusTreeview;


## Global callable functions

# Help
sub help() {
	my $helpstring = "
    Type: av
    [--av_skip_eicar]            Do not count EICAR test virus pattern
    [--av_type avp|amavis]       Type of antivirus software
                                  (currently 'avp' and 'amavis' are supported)
    [--av_skip_sender_statistic] Do not show per sender statistics
                                  (rather long since 'Sobig'...)
    [--debug <debug>]            Debug value
                                    | 0x0100 : display native antivirus log lines
                                    | 0x0200 : display extracted antivirus log lines
";
	return $helpstring;
};

# Check options
sub checkoptions() {
	# antivirus statistics
	if ( ! defined $main::opts{'av_type'} ) {
		# default Kasperski AVP
		print STDERR "WARNING(av): no antivirus software type specified, use 'amavis' as default\n" if $main::types{'av'} != 0;
		$main::opts{'av_type'} = "amavis";
	};

	if ($main::opts{'av_type'} !~ /^(amavis|avp)$/) {
		die "Antivirus sofware type not supported: " . $main::opts{'avtype'};
	};
};

# Parse logline
sub loglineparser(\$\$) {
	return if ( $main::types{'av'} == 0);

	if (! defined $_[0]) { die "Missing time pointer (arg1)"; };
	if (! defined $_[1]) { die "Missing logline pointer (arg2)"; };

	#print ${$_[1]} . "\n";

	# Looking for special rejects (e.g. I-Worm.Sorbig)

	if ( ${$_[1]} =~ / reject: RCPT from ([^:]+): [45]54 <big\@boss.com>: Sender address rejected: .* from=<([^>]*)> to=<([^>]*)> /o ) {
		printf STDERR "DEBUG(av): %s\n", ${$_[1]} if ($main::opts{'debug'} & 0x0100 ) ;

		return if (! defined $2 || ! defined $3 );		
		$from  = lc($2);
		$to    = lc($3);

		if ($from eq "") { $from = "from=<>" };
		if ($from eq "#@[]") { $from = "from=<#@[]>"; };

		if ( $main::opts{'av_type'} eq "avp" ) {
			# Kasperski AVP
			$avMsg = "I-Worm.Sobig";
		} else {
			die "Antivirus sofware type not supported: " . $main::opts{'avtype'};
		};

		# Hook "modifyaddress"
		$from = ::modify_address($from);
		$to   = ::modify_address($to);

		$antivirusCounter++;
		$antivirusUserStats{'to'}->{$to}++;
		$antivirusDomainStats{'to'}->{::extract_domain($to)}++;

		$antivirusUserStats{'from'}->{$from}++;
		$antivirusDomainStats{'from'}->{::extract_domain($from)}++;
		$antivirusVirusStats{$avMsg}++;

		$antivirusTreeview{::extract_domain($to)}->{$to}->{$avMsg}->{$from}++;

		printf STDERR "DEBUG(av): from=%s to=%s msg=%s\n", $from, $to, $avMsg if ($main::opts{'debug'} & 0x0200 ) ;

		return;
	};

	# Looking for special discard|rejects (e.g. I-Worm.Sorbig.f) using body checks
	# Catch Aug 22 12:37:26 postfix postfix/cleanup[24933]: 6B8A9137E6: discard: body RSLxwtYBDB6FCv8ybBcS0zp9VU5of3K4BXuwyehTM0RI9IrSjVuwP94xfn0wgOjouKWzGXHVk3qg from brmea-mail-3.Sun.COM[192.18.98.34]; from=<> to=<rcpt@domain.example> proto=ESMTP helo=<brmea-mail-3.sun.com>: 554 Please clean your infected system (I-Worm.Sobig.f)
	if ( ${$_[1]} =~ / (discard|reject): body .*; from=<(.*)> to=<(.*)> .*: [45]54 .*\((.*)\).*$/o ) {
		printf STDERR "DEBUG(av): %s\n", ${$_[1]} if ($main::opts{'debug'} & 0x0100 ) ;

		return if (! defined $2 || ! defined $3 );		
		$from  = lc($2);
		$to    = lc($3);
		$avMsg = $4;

		if ($from eq "") { $from = "from=<>" };
		if ($from eq "#@[]") { $from = "from=<#@[]>"; };

		if ( $main::opts{'av_type'} eq "avp" ) {
			# Kasperski AVP I-Worm.*
			if ($avMsg =~ /I-Worm\./o) {
			} else {
				$avMsg = "UNCHECKED_AV_MESSAGE";
			};
		} else {
			die "Antivirus sofware type not supported here: " . $main::opts{'avtype'};
		};

		# Hook "modifyaddress"
		$from = ::modify_address($from);
		$to   = ::modify_address($to);

		$antivirusCounter++;
		$antivirusUserStats{'to'}->{$to}++;
		$antivirusDomainStats{'to'}->{::extract_domain($to)}++;

		$antivirusUserStats{'from'}->{$from}++;
		$antivirusDomainStats{'from'}->{::extract_domain($from)}++;
		$antivirusVirusStats{$avMsg}++;

		$antivirusTreeview{::extract_domain($to)}->{$to}->{$avMsg}->{$from}++;

		printf STDERR "DEBUG: AV: from=%s to=%s msg=%s\n", $from, $to, $avMsg if ($main::opts{'debug'} & 0x0200 ) ;

		return;
	};
	
	# Looking for antivirus lines, nothing else 
	return unless (${$_[1]} =~ /.*(avcheck|amavis)\[\d+\]: /o);

	if ( ${$_[1]} =~ / (avcheck|amavis)\[\d+\]: infected: from=([^,]*), to=([^,]*),.* msg=(.*)$/o ) {
		printf STDERR "DEBUG(av): %s\n", ${$_[1]} if ($main::opts{'debug'} & 0x0100 ) ;

		return if ( ! defined $2 && ! defined $3 );
		return if ( $2 eq "" && $3 eq "" );
		
		$from  = lc($2);
		$to    = lc($3);
		$avMsg = $4;

		## extract virus information
		if ( $main::opts{'av_type'} eq "avp" ) {
			# Kasperski AVP
			# Example: msg=archive: Mail suspicion: Exploit.IFrame.FileDownload infected: I-Worm.Klez.h ok.
			if ( $avMsg =~ /infected: ([^ ]+).*$/o ) {
				$avMsg = $1;
			} elsif ( $avMsg =~ /suspicion: ([^ ]+).*$/o ) {
				$avMsg = $1;
			} elsif ( $avMsg =~ /warning: ([^ ]+).*$/o ) {
				$avMsg = $1;
			} else {
				$avMsg .= " <no more information given>";
				#warn "Cannot extract virus information: '$avMsg':\nLINE: " . ${$_[1]} . "\n";
			};

			return if ( lc($avMsg) eq "eicar-test-file" &&  defined $main::opts{'av_skip_eicar'} );
		} elsif ( $main::opts{'av_type'} eq "amavis" ) {
			warn "Antivirus sofware type not really supported here: " . $main::opts{'avtype'};
		};

		if ($from eq "") { $from = "from=<>" };
		if ($from eq "#@[]") { $from = "from=<#@[]>"; };

		# Hook "modifyaddress"
		$from = ::modify_address($from);
		$to   = ::modify_address($to);
		
		$antivirusCounter++;

		# Check for more than one recipient
		foreach $to_new (split " ", $to) {
			$antivirusUserStats{'to'}->{$to_new}++;
			$antivirusDomainStats{'to'}->{::extract_domain($to_new)}++;

			$antivirusUserStats{'from'}->{$from}++;
			$antivirusDomainStats{'from'}->{::extract_domain($from)}++;
			$antivirusVirusStats{$avMsg}++;

			$antivirusTreeview{::extract_domain($to_new)}->{$to_new}->{$avMsg}->{$from}++;

			printf STDERR "DEBUG(av): from=%s to=%s msg=%s\n", $from, $to_new, $avMsg if ($main::opts{'debug'} & 0x0200 ) ;
		};

		return;
	};

	# Catch:
	# Jan 20 23:41:26 hostname amavis[6821]: (06821-08) INFECTED (W32/Sober.C@mm), <sender@domain.example> --> <recipient@domain.example>, quarantine virus-20040120-234126-06821-08, Message-ID: <1234567890@domain.example>, Hits: -
	# Feb 16 09:14:15 hostname amavis[16155]: (16155-04) Blocked INFECTED (Trojan-Spy.HTML.Paylap.r), [<IP>] [<IP>] <?@[<IP>]> -> <recipient@domain.example>, quarantine: virus-20050216-091414-16155-04, Message-ID: <20050215210928.D033019373A@leda.snu.ac.kr>, Hits: -, 1232 ms
	if ( ${$_[1]} =~ / amavis\[\d+\]: \([0-9-]+\).* INFECTED \(([^)]*)\),.* <([^>]*)> -?-> <([^>]*)>,/o ) {
		printf STDERR "DEBUG(av): %s\n", ${$_[1]} if ($main::opts{'debug'} & 0x0100 ) ;

		return if ( ! defined $2 && ! defined $3 );
		return if ( $2 eq "" && $3 eq "" );
		
		$from  = lc($2);
		$to    = lc($3);
		$avMsg = $1;

		#printf STDERR "DEBUG(av): from=" . $from . " to=" . $to . " avMsg=" . $avMsg . "\n" if ($main::opts{'debug'} & 0x0100 ) ;

		## extract virus information
		return if ( lc($avMsg) eq "eicar-test-file" &&  defined $main::opts{'av_skip_eicar'} );

		if ($from eq "") { $from = "from=<>" };
		if ($from eq "#@[]") { $from = "from=<#@[]>"; };

		# Hook "modifyaddress"
		$from = ::modify_address($from);
		$to   = ::modify_address($to);
		
		$antivirusCounter++;

		# Check for more than one recipient
		foreach $to_new (split " ", $to) {
			$antivirusUserStats{'to'}->{$to_new}++;
			$antivirusDomainStats{'to'}->{::extract_domain($to_new)}++;

			$antivirusUserStats{'from'}->{$from}++;
			$antivirusDomainStats{'from'}->{::extract_domain($from)}++;
			$antivirusVirusStats{$avMsg}++;

			$antivirusTreeview{::extract_domain($to_new)}->{$to_new}->{$avMsg}->{$from}++;

			printf STDERR "DEBUG(av): from=%s to=%s msg=%s\n", $from, $to_new, $avMsg if ($main::opts{'debug'} & 0x0200 ) ;
		};
	};

	return;
};


# After loop finished
sub loop_afterfinish() {
	## Hook 'register_intermediate_data'
	for my $p_hook (keys %{$main::hooks{'register_intermediate_data'}}) {
        	&{$main::hooks{'register_intermediate_data'}->{$p_hook}} ("antivirusTreeview", \%antivirusTreeview);
        	&{$main::hooks{'register_intermediate_data'}->{$p_hook}} ("antivirusUserStats", \%antivirusUserStats);
        	&{$main::hooks{'register_intermediate_data'}->{$p_hook}} ("antivirusDomainStats", \%antivirusDomainStats);
        	&{$main::hooks{'register_intermediate_data'}->{$p_hook}} ("antivirusVirusStats", \%antivirusVirusStats);
	};
};


# Before printing result
sub before_print_result() {
	## Hook 'retrieve_intermediate_data'
	for my $p_hook (keys %{$main::hooks{'retrieve_intermediate_data'}}) {
        	&{$main::hooks{'retrieve_intermediate_data'}->{$p_hook}} ("antivirusTreeview", \%antivirusTreeview);
        	&{$main::hooks{'retrieve_intermediate_data'}->{$p_hook}} ("antivirusUserStats", \%antivirusUserStats);
        	&{$main::hooks{'retrieve_intermediate_data'}->{$p_hook}} ("antivirusDomainStats", \%antivirusDomainStats);
        	&{$main::hooks{'retrieve_intermediate_data'}->{$p_hook}} ("antivirusVirusStats", \%antivirusVirusStats);
	};
};


# Print result
sub print_result() {
	return if ( $main::types{'av'} == 0);

	my $info = "";
	my $format;

	if ( defined $main::opts{'av_skip_eicar'} ) {
		$info = " (excluding EICAR test virus pattern)";
	};

	# Format: treeview
	if (defined $main::format{"treeview"}) {
		$format = "treeview";
		my $info2 = $info . " (treeview)";
		if (defined $main::opts{'show_domain_list'}) {
			$main::opts{'show_domain_list'} =~ s/,/ /go;
			if ($main::opts{'show_domain_list'} ne "") {
				$info2 .= ":\n " . $main::opts{'show_domain_list'};
			};
		};
		::print_headline("Antivirus statistics" . $info2, $format);
		::print_timerange($format);
		if (! defined $main::opts{'av_skip_sender_statistic'}) {
			::print_treeview( \%antivirusTreeview, $main::opts{'show_domain_list'} );
		} else {
			::print_treeview2( \%antivirusTreeview, 3, $main::opts{'show_domain_list'} );
		};
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
		::print_headline("Antivirus statistics" . $info, $format);
		::print_timerange($format);

		::print_stat "Antivirus statistics per recipient"        . $info, $antivirusUserStats{'to'} if (defined $main::opts{'show_users'});
		::print_stat "Antivirus statistics per recipient domain" . $info, $antivirusDomainStats{'to'};

		if (! defined $main::opts{'av_skip_sender_statistic'}) {
			::print_stat "Antivirus statistics per sender"           . $info, $antivirusUserStats{'from'} if (defined $main::opts{'show_users'});
			::print_stat "Antivirus statistics per sender domain"    . $info, $antivirusDomainStats{'from'};
		};
		::print_stat "Antivirus statistics per virus"            . $info, \%antivirusVirusStats;
	};
};


## Local functions

## End of module
return 1;
