#!/usr/bin/perl -w

###
# Project:     pflogstats
# Module:      pflogstats-statistics-accounting.pm
# Type:        statistics
# Description: Statistics module for accounting
# Copyright:   (P) & (C) 2003 - 2006 by Peter Bieringer <pbieringer at aerasec dot de>
#               AERAsec GmbH <http://www.aerasec.de/> 
# License:     GNU GPL v2
# CVS:         $Id: pflogstats-statistics-accounting.pm,v 1.59 2006/08/01 13:36:39 peter Exp $
###

###
# ChangeLog:
#	0.01
#	 - initial creation
#	 - add special "indented" print function
#	0.02
#	 - import printstatistics function
#	0.03
#	 - import acc_virtual code
#	0.04
#	 - support new format code style
#	0.05
#	 - some coding speed-ups
#	 - enable intermediate statistics update to prevent much memory consumption
#	 - do not count cloned qids for SASL
#	 - enhance/fix cloning (still was too much accounted)
#	 - review garbage collection
#	 - fix qid reusage issue (qids are completly cloned now)
#	 - catch also local pickup
#	0.06
#	 - reimplement logline parser for standalone usage (no longer old pflogsumm code is used)
#	 - tag some match patterns with "o"
#	0.07
#	 - fix a bug in qid match (to catch older postfix versions loglines, too)
#	 - fix a possible die on empty relay_ip
#	0.08
#	 - enhance bugfix in qid match
#	 - rewrite ipaddress check calling code to make this support optional
#	 - fix a bug in cmd match (now "qmgr" is also supported)
#	 - extend logline parser matches (nqmgr/bounces)
#	 - fix bug in debug code
#	 - fix scoping bug of virtual support (check_domain)
#	 - fix delay matching regex (negative allowed for clock strangeness issues)
#	0.09
#	 - minor copy&paste bugfix in waring message
#	0.10
#	 - fix clone id debugging
#	 - fix not working localhost detection
#	0.11
#	 - account mail 'tara' (envelope data), account around additional 1.5 %
#	 - account envelope data of RCPT rejects (around 2%)
#	 - estimate TCP overhead also (MTU 1500, 40 Byte TCP/IP, 10% ACKs from receiver)
#	0.12
#	 - make TCP overhead accounting switchable
#	0.13
#	 - fix misaccounting on local configured forwarding via a local relay
#	 - print accounting overhead options
#	0.14
#	 - apply some debug code
#	0.15
#	 - extend message-id based mapping with "to" address
#	 - minor adjustment of debug code
#	0.16
#	 - fix minor bug in message id mapping
#	0.17
#	 - replace all hash references with proper code
#	0.18
#	 - fix problem with <>@host loglines like "from=<<>@uke.uni-hamburg.de>"
#       0.19
#        - make Perl 5.0 compatible
#       0.20
#	 - max width of customer list 79->75 chars
#	 - fix bug on users accouting
#	0.21
#	 - add support for new authentication method "simpleauth"
#	0.22
#	 - add support for option print-max-width
#	0.23
#	 - fix bug in a printf
#	0.24
#	 - add support for accounting discarded messages (at least the header)
#	 - fix bug in reject header accounting (8 bytes too much)
#	0.25
#	 - fix bug with messages longer in queue than analysis time frame
#	 - add counter for "smtp_to_deferred"
#	0.26
#	 - remove extract2ndlevel domain for customer domain file
#	0.27
#	 - more fixes required for 0.18 case
#	0.28
#	 - proper handling of bad e-mail addresses (0.18 case for rejects)
#	0.29
#	 - account also messages blocked by amavis
#	 - minor code optimization
#	0.30
#	 - reorganize hook names
#	0.31
#	 - fix problem if amavis reports 2 destination addresses (take only the first one)
#	 - add support for authenticated users using postfix proxy
#	 - add debug option to print accounting data which doesn't match customers
#	0.32
#	 - fix problem that rejects are no longer accounted since qid=NOQUEUE in log line
#	0.33
#	 - fix accounting bugs for forwarded messages by minor redesign
#	 - add support for fixedformatnumber
#	0.34
#	 - layout fix for longer fixedformatnumber
#	 - computer format now reports also total_rcvd, total_sent
#	0.35
#	 - fix double parsing of smtpd/client lines ('missing return')
#	    causing improper customer domain relation on authenticated users
#	 - fix double printing of result by domain
#	0.36
#        - fix problem with pattern matches and == in if
#	0.37
#        - remove not really needed usage of Net::IP
#	0.38
#        - add support for amavis "blocked clean" because of reaching size limit
#	0.39
#	 - use print_stat for normal statistics to take care of sort option
#	0.40
#	 - fix non working printing of domain statistics in computer format
#	0.41
#	 - [adj] fix format to support more chars in value string
#	0.42
#	 - [adj] regex now supports qid with 12 hexdigits
###


use strict;


## Local constants
my $module_type = "statistics";
my $module_name = $module_type . "-accounting";
my $module_version = "0.42";

package pflogstats::statistics::accounting;

## Export module info
$main::moduleinfo{$module_name}->{'version'} = $module_version;
$main::moduleinfo{$module_name}->{'type'} = $module_type;
$main::moduleinfo{$module_name}->{'name'} = $module_name;

## Global prototyping
#sub print_users_indented();


## Local prototyping
sub print_summary_acc_users_treeview();
sub print_domains_users_indented($;@);


## Register options
$main::options{'acc_virtual'} = \$main::opts{'acc_virtual'};
$main::options{'acc_virtualfile=s'} = \$main::opts{'acc_virtualfile'};
$main::options{'acc_customerfile=s'} = \$main::opts{'acc_customerfile'};
$main::options{'acc_nomemopt'} = \$main::opts{'acc_nomemopt'};
$main::options{'acc_noenvelopes'} = \$main::opts{'acc_noenvelopes'};
$main::options{'acc_norejects'} = \$main::opts{'acc_norejects'};
$main::options{'acc_notcpoverhead'} = \$main::opts{'acc_notcpoverhead'};


## Register calling hooks
$main::hooks{'print_users_indented'}->{$module_name} = \&print_users_indented;
$main::hooks{'checkoptions'}->{$module_name} = \&checkoptions;
$main::hooks{'beforemainloopstarts'}->{$module_name} = \&beforemainloopstarts;
$main::hooks{'print_result'}->{$module_name} = \&print_result;
$main::hooks{'help'}->{$module_name} = \&help;
$main::hooks{'loglineparser'}->{$module_name} = \&loglineparser;


# Define type
$main::types{'acc'} = 0;


## Global variables

## Local variables
my %messageUserStats;
my %messageDomainStats;
my %counters;
my %check_domains;
my %domains_customer;

# Lookup table for postfix proxy authentications
my %clients_authenticated;

my %messagelog; # Message log hash per qid
# $messagelog{$qid}->{0} : master e-mail (first occurance)
# $messagelog{$qid}->{1..x} : clones, created on e-mails with more than one recipient

my %messageid_origto;

my $qid;
my ($client, $smtpauth_username, $smtpauth_method, $smtpauth_sender);
my ($from_domain, $to_domain, $from, $to);

my $mailtarasize;

# Define localhost notation
my %localhost_notations;
$localhost_notations{'::ffff:127.0.0.1'} = 1;
$localhost_notations{'::1'} = 1;
$localhost_notations{'127.0.0.1'} = 1;

my %localrelay_notations;
$localrelay_notations{'avcheck'} = 1; # Kasperski avcheck
$localrelay_notations{'avcheckss'} = 1; # Kasperski avcheck with Spamassassin
$localrelay_notations{'spamassassin'} = 1; # Spamassassin
$localrelay_notations{'local'} = 1; # Local relay
$localrelay_notations{'none'} = 1; # No relay
$localrelay_notations{'spamss'} = 1; # No relay





## Global callable functions

# Help
sub help() {
	my $helpstring = "
    Type: acc
    [--acc_customerfile <file>]  File containing customer domains
                                    (will be preferred for accouting)
    [--acc_virtual]              Use virtual file for match accounting
    [--acc_virtualfile <file>]   Virtual file to use (default: /etc/postfix/virtual)
    [--acc_noenvelopes]          Don't account estimated size of envelope on sent e-mail
    [--acc_noreject]             Don't account estimated size of envelope on rejected connect
    [--acc_notcpoverhead]        Don't account estimated TCP overhead
    [--acc_nomemopt]             Do no memory optimization (only for debug and check purposes recommended)
    [-e]                         Extended logging mode parsing logfile
    [--debug <debug>]            Debug value
                                    | 0x0001 : display matched log line
                                    | 0x0002 : display matched amavis log line
                                    | 0x0008 : display accounting information not matching customers
                                    | 0x0010 : display accounting lines
                                    | 0x0020 : information about IP address handling
                                    | 0x0040 : information about domain name and customer file
                                    | 0x0080 : show IPv6 addresses of clients and relays
                                    | 0x0100 : show garbage collection statistics on memory optimization
                                    | 0x0200 : show information about qidreusage
                                    | 0x0400 : display reject accounting lines
                                    | 0x0800 : display accounted messages

";
	return $helpstring;
}

# Print users indented
sub print_users_indented() {
	print_summary_acc_users_treeview();
};

sub print_message($$;$) {
	my $qid = $_[0];
	my $cloneid = $_[1];

	print "DEBUG(acc)";

	if (defined $_[2]) {
		print " [" . $_[2] . "]";
	};
	print ": ";

	my $time = ::unixtime2string($messagelog{$qid}->{'time'}) || "";
	$qid = $qid || "";
	if (! defined $cloneid) { $cloneid = "<undefined>" };
	my $from = $messagelog{$qid}->{'from'} || "";
	my $to = $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'} || "";
	my $size = $messagelog{$qid}->{'size'} || -1;
	my $client = $messagelog{$qid}->{'client'} || "";
	my $relay = $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay'} || "";
	my $status = $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'status'} || "";
	my $smtpauth_method = $messagelog{$qid}->{'smtpauth_method'} || "";
	my $smtpauth_username = $messagelog{$qid}->{'smtpauth_username'} || "";
	my $smtpauth_sender = $messagelog{$qid}->{'smtpauth_sender'} || "";
	my $client_ip = $messagelog{$qid}->{'client_ip'} || "";
	my $relay_ip = $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay_ip'} || "";

	printf "time='%s' qid=%s cloneid=%s from=%s to=%s size=%d client=%s relay=%s status=%s smtpauth_method=%s smtpauth_username=%s smtpauth_sender=%s client_ip=%s relay_ip=%s\n", $time, $qid, $cloneid, $from, $to, $size, $client, $relay, $status, $smtpauth_method, $smtpauth_username, $smtpauth_sender, $client_ip, $relay_ip;
};

# Print statistics
sub calculatestatistics(;$) {
	# arg1: 1: intermediate run
	my $run_intermediate;
	if (! defined $_[0]) {
		$run_intermediate = 0;
	} else {
		$run_intermediate = $_[0];
	};

	my %accounting;
	my $qid;
	my $time_limit = 0;
	my $skip_ip_client;
	my $skip_ip_relay;
	my $from;

	# Debug: run through messagelog and look for unset times
	if (0) {
		for my $qid ( keys %messagelog ) {
			if (! defined $messagelog{$qid}->{'time'} ) {
				$messagelog{$qid}->{'time'} = 0;	
				print_message($qid, 0, "timeunset");
			};
		};
		exit 1;
	};

	# Run through logged messages
	for $qid ( sort { $messagelog{$a}->{'time'} <=> $messagelog{$b}->{'time'} } keys %messagelog ) {
	    if ($run_intermediate) {
		if ( ! defined $messagelog{$qid}->{'from'} )  {
			# skip still not complete information on intermediate run
			#print_message($qid, 0, "skipnofrom") if ($main::opts{'debug'} & 0x0100 );
			next;
		};
		if ( ! defined $messagelog{$qid}->{'size'} )   {
			#print_message($qid, $cloneid, "skipnosize") if ($main::opts{'debug'} & 0x0100 );
			next;
		};

		if ( ! %{$messagelog{$qid}->{'rcpt'}}) {
			# still no recipients defined, skip
			#print_message($qid, 0, "skipnorcpt") if ($main::opts{'debug'} & 0x0100 );
			next;
		};

		# Look for newest time
		if (defined $messagelog{$qid}->{'time'} && $messagelog{$qid}->{'time'} > $time_limit) {
			$time_limit = $messagelog{$qid}->{'time'};
		};
	    } else {
		# Fill undefined values 
		if ( ! defined $messagelog{$qid}->{'from'} )   { $messagelog{$qid}->{'from'}   = "?" };
		if ( ! defined $messagelog{$qid}->{'size'} )   { $messagelog{$qid}->{'size'}   = "0" }; 
	    };


	    # Get 2nd-Level Domain of "from"
	    $from = $messagelog{$qid}->{'from'};
	    $from_domain = ::extract_2ndleveldomain( $from );

	    # Run through clones (sorry for 4 space indent)
	    for my $cloneid (sort keys %{$messagelog{$qid}->{'rcpt'}}) {
		# Check for valid logentry
		if (! defined $cloneid ) {
		#if (! defined $messagelog{$qid}->{'rcpt'}->{$cloneid} ) {
			# logentry isn't valid
			next;
		};

		if (! defined $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'status'}) {
			# Skip message without a status
			#print_message($qid, $cloneid, "skipstatus") if ($main::opts{'debug'} & 0x0100 );
			next;
		};
		if ( $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'status'} ne 'sent' ) {
			#print_message($qid, $cloneid, "skipnotsent") if ($main::opts{'debug'} & 0x0100 );

			if ( $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'status'} eq 'bounced' ) {
				# Remove bounced message
				# Free some no longer needed information
				delete $messagelog{$qid}->{'rcpt'}->{$cloneid};
				$counters{'skipped_status_bounced'}++;
			};

			# Skip message if not sent
			next;
		};

		#print "Clone ID: " . $cloneid . "\n";

		if ($run_intermediate) {
			# skip still not complete information on intermediate run
			if ( ! defined $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'} )     {
				#print_message($qid, $cloneid, "skipnoto") if ($main::opts{'debug'} & 0x0100 );
				next;
			};
			if ( ! defined $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'status'} ) {
				#print_message($qid, $cloneid, "skipnostatus") if ($main::opts{'debug'} & 0x0100 );
				next;
			};
		} else {
			if ( ! defined $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'} )     { $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'}     = "?" };
			#if ( ! defined $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'status'} ) { $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'status'} = "?" }; 
		};

		if ( ! defined $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay_ip'} )  { $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay_ip'}  = "" };
		if ( ! defined $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay'} )  { $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay'}  = "?" };

		if ( ( $messagelog{$qid}->{'from'} eq '?' || $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'} eq '?' )  ) {
			# Skip messages with invalid from or to
			if ( $messagelog{$qid}->{'from'} eq '?' ) {
				$counters{'skipped_status_invalid_from'}++;
			};
			if ( $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'} eq '?' ) {
				$counters{'skipped_status_invalid_to'}++;
			};
			print_message($qid, $cloneid, "invalid_from_to");
			next;
		};

		$counters{'total'}++;

		## Client checks and counters
		if (! defined $messagelog{$qid}->{'accounted'}) {
			# Check and fill client data with defaults
			if ( ! defined $messagelog{$qid}->{'client'}        ) { $messagelog{$qid}->{'client'} = "?";        }; 
			if ( ! defined $messagelog{$qid}->{'client_ip'}     ) { $messagelog{$qid}->{'client_ip'} = "";      };
			if ( ! defined $messagelog{$qid}->{'smtpauth_method'}   ) { $messagelog{$qid}->{'smtpauth_method'}   = "?"; };
			if ( ! defined $messagelog{$qid}->{'smtpauth_username'} ) { $messagelog{$qid}->{'smtpauth_username'} = "?"; };
			if ( ! defined $messagelog{$qid}->{'smtpauth_sender'}   ) { $messagelog{$qid}->{'smtpauth_sender'} = "?";   };

			# IPv6 counters
			if ( $messagelog{$qid}->{'client_ip'} ne "" ) {
				if ( $messagelog{$qid}->{'client_ip'} =~ /:/ ) {
					$counters{'client_ipv6'}++;
					print STDERR "DEBUG: IPv6 client: " . $messagelog{$qid}->{'client_ip'} . "\n" if ($main::opts{'debug'} & 0x80);
				} else {
					$counters{'client_ipv4'}++;
				};
			};
			# SASL counters
			if ( $messagelog{$qid}->{'smtpauth_method'} eq 'PLAIN'      ) { $counters{'smtpauth_PLAIN'}++;      };
			if ( $messagelog{$qid}->{'smtpauth_method'} eq 'LOGIN'      ) { $counters{'smtpauth_LOGIN'}++;      };
			if ( $messagelog{$qid}->{'smtpauth_method'} eq 'DIGEST-MD5' ) { $counters{'smtpauth_DIGEST-MD5'}++; };
			if ( $messagelog{$qid}->{'smtpauth_method'} eq 'CRAM-MD5'   ) { $counters{'smtpauth_CRAM-MD5'}++;   };
			if ( $messagelog{$qid}->{'smtpauth_method'} ne '!' && $messagelog{$qid}->{'smtpauth_method'} ne '?' ) { $counters{'sasl'}++; };

			$messagelog{$qid}->{'accounted'} = 1;
		};

		## Recipient counters
		# IPv6 counters
		if ( $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay_ip'} ne "" ) {
			print STDERR "DEBUG: relay: " . $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay_ip'} . "\n" if ($main::opts{'debug'} & 0x80);
			if ( $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay_ip'} =~ /:/ ) {
				$counters{'relay_ipv6'}++;
				print STDERR "DEBUG: IPv6 relay: " . $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay_ip'} . "\n" if ($main::opts{'debug'} & 0x80);
			} else {
				$counters{'relay_ipv4'}++;
			};
		};
		# Relays
		if ( $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay'} ne '?' && $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay'} ne '!' ) { $counters{'relayed'}++; };
		if ( $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay'} eq 'avcheck' ) { $counters{'relayed_avchecked'}++; };
		if ( $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay'} eq 'avcheckss' ) { $counters{'relayed_avchecked'}++; };
		if ( $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay'} eq 'spamss' ) { $counters{'relayed_spamassassin'}++; };
		if ( $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay'} eq 'local' ) { $counters{'relayed_local'}++; };

		$counters{'accounted'}++;

		print_message($qid, $cloneid, "opte") if (defined $main::opts{'e'} );

		# Handling of virtual
		if (defined $main::opts{'acc_virtual'} ) {
			# Rewrite recipient for virtual accounting
			if ( defined $check_domains{$messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'}} ) {
				# Map user
				printf  "*MAP: " . $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'} . " => " . $check_domains{$messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'}} . "\n" if ($main::opts{'debug'} & 0x0010 ) ;
				$messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'} = "@" . $check_domains{$messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'}};
			};
		};

		# Get 2nd-Level Domain of "to"
		$to_domain = ::extract_2ndleveldomain( $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'} );

		# Reset flags
		$accounting{'from'}->{'flag'} = 0;
		$accounting{'from'}->{'direction'} = '';
		$accounting{'from'}->{'info'} = "";
		$accounting{'to'}->{'flag'} = 0;
		$accounting{'to'}->{'direction'} = '';
		$accounting{'to'}->{'info'} = "";

		# print_message($qid, $cloneid, "check");


		# Check IP addresses
		$skip_ip_client = 0;
		$skip_ip_relay = 0;

		if ( $messagelog{$qid}->{'client_ip'} ne "" ) {
			# Hook "testipaddress"
			for my $p_hook (keys %{$main::hooks{'testipaddress'}}) {
				if ( &{$main::hooks{'testipaddress'}->{$p_hook}} ($messagelog{$qid}->{'client_ip'}) != 0 ) {
					$skip_ip_client = 1;
					last;
				};
			};
		};
		if ( $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay_ip'} ne "" ) {
			# Hook "testipaddress"
			for my $p_hook (keys %{$main::hooks{'testipaddress'}}) {
				if ( &{$main::hooks{'testipaddress'}->{$p_hook}} ($messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay_ip'}) != 0 ) {
					$skip_ip_relay = 1;
					last;
				};
			};
		};

		## Main accounting selection code starts here
		if ( $messagelog{$qid}->{'client_ip'} ne "" ) {

			#print "DEBUG(client_ip): " . $messagelog{$qid}->{'client_ip'} . "\n";
			#for my $key (keys %localhost_notations) {
			#	print $key;
			#	if ($key eq $messagelog{$qid}->{'client_ip'}) {
			#		print "+";
			#	} else {
			#		print "-";
			#	};
			#	print " ";
			#};
			#print "\n";

			# Client connects via IP
			if ( ! defined $localhost_notations{$messagelog{$qid}->{'client_ip'}} ) {
				#print "DEBUG(client_ip): not localhost\n";
				# Incoming e-mail from external
				if ( defined $localrelay_notations{$messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay'}} || defined $localhost_notations{$messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay_ip'}} ) {
					# Check for client in exclude range
					#print_message($qid, $cloneid, "check1");
					if ( $skip_ip_client != 0 ) {
						# client_ip should be not accounted
						$counters{'notaccounted_client_ip_excluded'}++;
						printf "*ACC: --not accounted: client is excluded--\n" if ($main::opts{'debug'} & 0x0010 ) ;
					} else {
						# Incoming e-mail from external to local
						if ($cloneid > 0 ) {
							# cloned message, one connect, one from, several to's
							printf "*ACC: --not accounted: message is a clone\n" if ($main::opts{'debug'} & 0x0010 ) ;
						} else {
							if ( $messagelog{$qid}->{'smtpauth_username'} ne '!' && $messagelog{$qid}->{'smtpauth_username'} ne '?' ) {
								# Authenticated user, account "from" address
								$accounting{'from'}->{'direction'} .= '*rcvd';
								$accounting{'from'}->{'flag'}++;
								$accounting{'from'}->{'info'} .= "*ACC-auth-rcvd";

								$from = $messagelog{$qid}->{'smtpauth_username'};
	    							$from_domain = ::extract_2ndleveldomain( $from );
							} else {
								# Unauthenticated sender, account "to"
								$accounting{'to'}->{'direction'} .= '*rcvd';
								$accounting{'to'}->{'flag'}++;
								$accounting{'to'}->{'info'} .= "*ACC-4";
							};
						};
					};
				} else {
					# Not a local relay
					#printf "DEBUG(acc/generate) qid=%s\n", $qid;
					#print_message($qid, $cloneid, "NotLocalRelay");

					# Check for client and relay in exclude range
					#print_message($qid, $cloneid, "check2");
					if ( $skip_ip_client != 0 ) {
						$counters{'notaccounted_client_ip_excluded'}++;
						printf "*ACC-6a: --not accounted: client is in exclude net--\n" if ($main::opts{'debug'} & 0x0010 ) ;
					} else {
						printf "*ACC-: check client allowed\n" if ($main::opts{'debug'} & 0x0010 );

						if ($cloneid > 0 ) {
							# cloned message, one connect, one from, several to's
							printf "*ACC: --not accounted: message is a clone\n" if ($main::opts{'debug'} & 0x0010 ) ;
						} else {
							if ( $messagelog{$qid}->{'smtpauth_username'} ne '!' && $messagelog{$qid}->{'smtpauth_username'} ne '?' ) {
								# Authenticated user, account "from" address
								$accounting{'from'}->{'direction'} .= '*rcvd';
								$accounting{'from'}->{'flag'}++;
								$accounting{'from'}->{'info'} .= "*ACC-auth-rcvd";

								# Map from address to ID of authenticated user
								$from = $messagelog{$qid}->{'smtpauth_username'};
	    							$from_domain = ::extract_2ndleveldomain( $from );
							} else {
								# Unauthenticated (by SMTP) sender, but perhaps by SMTP after POP
								# Check for customer
								if ( defined $domains_customer{$from_domain} ) {
									# in list of customer domains 
									printf "*ACC-: from_domain in customer list\n" if ($main::opts{'debug'} & 0x0010 );
									$accounting{'from'}->{'flag'}++;
									$accounting{'from'}->{'info'} .= "*ACC-cd";
									$accounting{'from'}->{'direction'} .= '*rcvd';
								} elsif ( defined $domains_customer{$to_domain} ) {
									# in list of customer domains 
									printf "*ACC-: to_domain in customer list\n" if ($main::opts{'debug'} & 0x0010 );
									$accounting{'to'}->{'flag'}++;
									$accounting{'to'}->{'info'} .= "*ACC-cd";
									$accounting{'to'}->{'direction'} .= '*rcvd';
								} else {
									# really unauthenticated, account "to"
									printf "*ACC-: not in customer list\n" if ($main::opts{'debug'} & 0x0010 );
									$accounting{'to'}->{'flag'}++;
									$accounting{'to'}->{'info'} .= "*ACC-6b";
									$accounting{'to'}->{'direction'} .= '*rcvd';
								};
							};
						};
					};
					#print_message($qid, $cloneid, "check3");
					if ( ($messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay_ip'} ne "") && ( $skip_ip_relay != 0 ) ) {
						# relay should be not accounted
						$counters{'notaccounted_relay_ip_excluded'}++;
						printf "*ACC-6b: --not accounted: relay is in exclude net--\n" if ($main::opts{'debug'} & 0x0010 ) ;
					} else {
						printf "*ACC-: check mailrouting\n" if ($main::opts{'debug'} & 0x0010 );

						if ( $messagelog{$qid}->{'smtpauth_username'} ne '!' && $messagelog{$qid}->{'smtpauth_username'} ne '?' ) {
							# Authenticated user, account "from" address
							$accounting{'from'}->{'direction'} .= '*sent';
							$accounting{'from'}->{'flag'}++;
							$accounting{'from'}->{'info'} .= "*ACC-auth-sent";

							$from = $messagelog{$qid}->{'smtpauth_username'};
    							$from_domain = ::extract_2ndleveldomain( $from );
						} else {
							# Check for mailrouting
							if ( defined $domains_customer{$to_domain} ) {
								# in list of customer domains
								printf "*ACC-: in customer list\n" if ($main::opts{'debug'} & 0x0010 );
								$accounting{'to'}->{'flag'}++;
								$accounting{'to'}->{'info'} .= "*ACC-mr";
								$accounting{'to'}->{'direction'} .= '*sent';
							} else {
								# Hopefully authenticated user, account "from" address
								printf "*ACC-: not in customer list\n" if ($main::opts{'debug'} & 0x0010 );
								$accounting{'from'}->{'flag'}++;
								$accounting{'from'}->{'info'} .= "*ACC-6a";
								$accounting{'from'}->{'direction'} .= '*sent';
							};
						};
					};
					#print_message($qid, $cloneid, "check3a");
				};
			} else {
				# Message send from localhost, outgoing message? perhaps sent by avceck?
				if ( defined $localhost_notations{$messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay_ip'}} ) {
					# Local
					printf "*ACC: --not accounted: relay is local--\n" if ($main::opts{'debug'} & 0x0010 ) ;
				} elsif ( $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay_ip'} eq "" ) {
					# Local
					printf "*ACC: --not accounted: relay is not given--\n" if ($main::opts{'debug'} & 0x0010 ) ;
				} else {
					# Not local, check destination
					#print_message($qid, $cloneid, "check4");
					if ( $skip_ip_relay != 0 ) {
						# relay should be not accounted
						$counters{'notaccounted_relay_ip_excluded'}++;
						printf "*ACC: --not accounted: relay is excluded--\n" if ($main::opts{'debug'} & 0x0010 ) ;
					#} else {
					#	# accouting
					#	$messageUserStats{$messagelog{$qid}->{'to'}}->{'rcvd'}->{'count'}++;
					#	$messageUserStats{$messagelog{$qid}->{'to'}}->{'rcvd'}->{'size'} += $messagelog{$qid}->{'size'};
					#	$messageDomainStats{$to_domain}->{'rcvd'}->{'count'}++;
					#	$messageDomainStats{$to_domain}->{'rcvd'}->{'size'} += $messagelog{$qid}->{'size'};
					#	printf "*ACC: to=%s size=%s\n", $messagelog{$qid}->{'to'}, $messagelog{$qid}->{'size'};
					} else {
						# Account "from"
						$accounting{'from'}->{'flag'}++;
						$accounting{'from'}->{'info'} .= "*ACC-5";
						$accounting{'from'}->{'direction'} .= '*sent';
					};
				};
			};

		} else {
			# client_ip is empty, locally generated or forwarded
			#printf "DEBUG(acc/generate) qid=%s\n", $qid;
			#print_message($qid, $cloneid, "check5");

			if ( defined $localhost_notations{$messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay_ip'}} ) {
				# Local
				printf "*ACC: --not accounted: relay is local--\n" if ($main::opts{'debug'} & 0x0010 ) ;
			} elsif ( $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'relay_ip'} eq "" ) {
				# Local
				$counters{'notaccounted_relay_local'}++;
				printf "*ACC: --not accounted: relay is not given--\n" if ($main::opts{'debug'} & 0x0010 ) ;
			} elsif ( $skip_ip_relay != 0 ) {
				# relay should be not accounted
				$counters{'notaccounted_relay_ip_excluded'}++;
				printf "*ACC: --not accounted: relay is excluded--\n" if ($main::opts{'debug'} & 0x0010 ) ;
			} else {
				if (! defined $messagelog{$qid}->{'mid'}) {
					print "WARN : message with qid probably longer in queue than analysis time frame: $qid\n";
				} elsif (! defined $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'}) {
					print "WARN : message with qid probably longer in queue than analysis time frame: $qid\n";
				} elsif (defined $messageid_origto{$messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'}}->{$messagelog{$qid}->{'mid'}} ) {
					# Outgoing message, replace to with orig_to
					printf  "*MAP orig_to: " . $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'} . " => " . $messageid_origto{$messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'}}->{$messagelog{$qid}->{'mid'}} . "\n" if ($main::opts{'debug'} & 0x0010 ) ;
					$messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'} = $messageid_origto{$messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'}}->{$messagelog{$qid}->{'mid'}};
					# Get 2nd-Level Domain of "to"
					$to_domain = ::extract_2ndleveldomain( $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'} );
				};

				if ( defined $domains_customer{$to_domain} ) {
					# in list of customer domains
					printf "*ACC-: to_domain in customer list\n" if ($main::opts{'debug'} & 0x0010 );
					$accounting{'to'}->{'flag'}++;
					$accounting{'to'}->{'info'} .= "*ACC-7a";
					$accounting{'to'}->{'direction'} .= '*sent';
				} else {
					# really unauthenticated, account "from"
					$accounting{'from'}->{'flag'}++;
					$accounting{'from'}->{'info'} .= "*ACC-7a";
					$accounting{'from'}->{'direction'} .= '*sent';
				};
			};
		};

		# Check accounting
		if ( $accounting{'from'}->{'flag'} < 0 || $accounting{'to'}->{'flag'} < 0 || ($accounting{'from'}->{'flag'} + $accounting{'to'}->{'flag'} > 2) ) {
			die "Accounting trouble, this should never happen";
		};

		## Calculate mail envelope data bytes (estimation)
		#
		# 220 hostname.example.com ESMTP [4+sizeof(localhelostring)+6+2=12+sizeof(localhelostring)]
		# HELO client [5+sizeof(remotehelostring)+2=7+sizeof(remotehelostring)]
		# 250 hostname.example.com [4+sizeof(hostname)+2=6+sizeof(hostname)]
		# MAIL FROM: <sender@example.com> [11+1+sizeof(sender)+1+2=15+sizeof(sender)]
		# 250 Ok [6+2=8]
		# RCPT TO: <recipient@example.com> [9+1+sizeof(rcpt)+1+2=13+sizeof(rcpt)]
		# 250 Ok [6+2=8]
		# DATA [4+2=6]
		# 354 End data with <CR><LF>.<CR><LF> [35+2=37]
		# text (size) [=size]
		# . [1+2=3]
		# 250 Ok: queued as xxxxxxxxxx [18+2+sizeof(qid)+2=22+sizeof(qid)]
		# QUIT [4+2=6]
		# 221 Bye [7+2=9]

		# 3x40 SYN, 4x40 FIN, 12x40 ACK = 760
		# Assume MTU 1500 and 10% ACKs by receiver, uncalculable: TCP options

		if (! defined $main::opts{'acc_noenvelopes'} ) {
			# $mailtarasize = 12 + length($main::opts{'myhostname'}) + 7 + 6 + length($main::opts{'myhostname'}) + 15 + length($messagelog{$qid}->{'from'}) + 8 + 13 + length($messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'}) + 8 + 6 + 37 + 3 + 22 + length($qid) + 6 + 9i + 760 + int($messagelog{$qid}->{'size'} / 1500) * 40;
			$mailtarasize = 158 + 2* length($main::opts{'myhostname'}) + length($messagelog{$qid}->{'from'}) + length($messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'}) + length($qid);
		} else {
			$mailtarasize = 0;
		};

		if ( ! defined $main::opts{'acc_notcpoverhead'} ) {
			$mailtarasize += 760 + int( ($messagelog{$qid}->{'size'} + 1459) / 1460) * 44;
		};

		# Account now
		if ( $accounting{'from'}->{'flag'} + $accounting{'to'}->{'flag'} > 0 ) {
			print_message($qid, $cloneid, "account") if ($main::opts{'debug'} & 0x0010 );
		};

		if ( $accounting{'from'}->{'direction'} =~ /\*sent/ ) {
			$messageUserStats{$from}->{'sent'}->{'count'} ++;
			$messageUserStats{$from}->{'sent'}->{'size'} += $messagelog{$qid}->{'size'} + $mailtarasize;
			$messageDomainStats{$from_domain}->{'sent'}->{'count'} ++;
			$messageDomainStats{$from_domain}->{'sent'}->{'size'} += $messagelog{$qid}->{'size'} + $mailtarasize;

			if ($main::opts{'debug'} & 0x0010 || $main::opts{'debug'} & 0x800 || $main::opts{'debug'} & 0x0008) {
				if ( $main::opts{'debug'} & 0x0008 && (defined $domains_customer{$to_domain} || defined $domains_customer{$from_domain})) {
					# nothing to do
				} else {
					printf "%s: from=%s qid=%s size=%s (sent)\n", $accounting{'from'}->{'info'}, $messagelog{$qid}->{'from'}, $qid, $messagelog{$qid}->{'size'};
				};
			};
		};

		if ( $accounting{'from'}->{'direction'} =~ /\*rcvd/ ) {
			$messageUserStats{$from}->{'rcvd'}->{'count'} ++;
			$messageUserStats{$from}->{'rcvd'}->{'size'} += $messagelog{$qid}->{'size'} + $mailtarasize;
			$messageDomainStats{$from_domain}->{'rcvd'}->{'count'} ++;
			$messageDomainStats{$from_domain}->{'rcvd'}->{'size'} += $messagelog{$qid}->{'size'} + $mailtarasize;

			if ($main::opts{'debug'} & 0x0010 || $main::opts{'debug'} & 0x800 || $main::opts{'debug'} & 0x0008) {
				if ( $main::opts{'debug'} & 0x0008 && (defined $domains_customer{$to_domain} || defined $domains_customer{$from_domain})) {
					# nothing to do
				} else {
					printf "%s: from=%s qid=%s size=%s (rcvd)\n", $accounting{'from'}->{'info'}, $messagelog{$qid}->{'from'}, $qid, $messagelog{$qid}->{'size'};
				};
			};
		};

		if ( $accounting{'to'}->{'direction'} =~ /\*sent/ ) {
			$messageUserStats{$messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'}}->{'sent'}->{'count'} ++;
			$messageUserStats{$messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'}}->{'sent'}->{'size'} += $messagelog{$qid}->{'size'} + $mailtarasize;
			$messageDomainStats{$to_domain}->{'sent'}->{'count'} ++;
			$messageDomainStats{$to_domain}->{'sent'}->{'size'} += $messagelog{$qid}->{'size'} + $mailtarasize;

			if ($main::opts{'debug'} & 0x0010 || $main::opts{'debug'} & 0x800 || $main::opts{'debug'} & 0x0008) {
				if ( $main::opts{'debug'} & 0x0008 && (defined $domains_customer{$to_domain} || defined $domains_customer{$from_domain})) {
					# nothing to do
				} else {
					printf "%s: to=%s qid=%s size=%s + overhead=%d (sent)\n", $accounting{'to'}->{'info'}, $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'}, $qid, $messagelog{$qid}->{'size'}, $mailtarasize;
				};
			};
		};

		if ( $accounting{'to'}->{'direction'} =~ /\*rcvd/ ) {
			$messageUserStats{$messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'}}->{'rcvd'}->{'count'} ++;
			$messageUserStats{$messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'}}->{'rcvd'}->{'size'} += $messagelog{$qid}->{'size'} + $mailtarasize;
			$messageDomainStats{$to_domain}->{'rcvd'}->{'count'} ++;
			$messageDomainStats{$to_domain}->{'rcvd'}->{'size'} += $messagelog{$qid}->{'size'} + $mailtarasize;

			if ($main::opts{'debug'} & 0x0010 || $main::opts{'debug'} & 0x800 || $main::opts{'debug'} & 0x0008) {
				if ( $main::opts{'debug'} & 0x0008 && (defined $domains_customer{$to_domain} || defined $domains_customer{$from_domain})) {
					# nothing to do
				} else {
					printf "%s: to=%s qid=%s size=%s + overhead=%d (rcvd)\n", $accounting{'to'}->{'info'}, $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'to'}, $qid, $messagelog{$qid}->{'size'}, $mailtarasize;
				};
			};
		};

		# Free some no longer needed information
		delete $messagelog{$qid}->{'rcpt'}->{$cloneid};
LABEL_statend:
	    }; # end of cloneid loop

	    if (! $run_intermediate) {
		# Last run, so remove qid
		delete $messagelog{$qid};
	    };

	}; # end of qid loop

	if ($run_intermediate) {
		if ($time_limit == 0) {
			printf "DEBUG(acc): Garbage collection skipped because of missing time limit\n" if ($main::opts{'debug'} & 0x0100 ) ;
			return;
		};

		# offset: (offset is needed to catch clones which appear e.g. on next line after this intermediate run)
		#$time_limit -= 7200; # 2 hours
		$time_limit -= 14400; # 4 hours

		printf "DEBUG(acc): Garbage collection on intermediate run, time limit: %d\n", $time_limit if ($main::opts{'debug'} & 0x0100 ) ;

		# Garbage collection
		my $stat_qids = 0;
		my $stat_qids_removed = 0;
		my $stat_qids_extime = 0;
		my $stat_qids_deferred = 0;
		my $stat_qids_stillrecipients = 0;
		my $stat_qids_stillnorecipients = 0;
		# Remove all qids which are older than limit
		for my $qid ( keys %messagelog ) {
			$stat_qids++;
			#printf "DEBUG(acc): Garbage collection on intermediate run, check: %d\n", $messagelog{$qid}->{'time'} if ($main::opts{'debug'} & 0x0100 ) ;
			if ( $messagelog{$qid}->{'time'} < $time_limit) {
				$stat_qids_extime++;

				if (! %{$messagelog{$qid}->{'rcpt'}}) {
					# still no recipients defined after that delay so delete
					# normally "client rejects"
					#print_message($qid, 0, "skipstillnorecipients");
					$stat_qids_stillnorecipients++;
					delete $messagelog{$qid};
					$stat_qids_removed++;
					next;
				};

				if (scalar (keys %{$messagelog{$qid}->{'rcpt'}}) > 0 ) {
					# Still some recipients defined (mean not accounted)
					#if ($main::opts{'debug'} & 0x0100) {
					#	for my $cloneid (keys %{$messagelog{$qid}->{'rcpt'}}) {
					#		print_message($qid, $cloneid, "skipstillrecipients");
					#	};
					#};
					if ($main::opts{'debug'} & 0x0100) {
						for my $cloneid (keys %{$messagelog{$qid}->{'rcpt'}}) {
							print_message($qid, $cloneid, "skipstillrecipients");
							$stat_qids_stillrecipients++;
							if (defined  $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'status'} && $messagelog{$qid}->{'rcpt'}->{$cloneid}->{'status'} eq "deferred") {
								$stat_qids_deferred++;
							};
						};
					};
					next;
				};

			
				#printf "DEBUG(acc): Garbage collection on intermediate run, remove: %d\n", $messagelog{$qid}->{'time'} if ($main::opts{'debug'} & 0x0100 ) ;
				# old enough, so remove
				delete $messagelog{$qid};
				$stat_qids_removed++;
			};
		};
		printf "DEBUG(acc): Garbage collection on intermediate run: removed=%d (%d %%) extime=%d count=%d deferred=%d stillrecipients=%d stillnorecipients=%d\n", $stat_qids_removed, (($stat_qids_removed * 100) / $stat_qids), $stat_qids_extime, $stat_qids, $stat_qids_deferred, $stat_qids_stillrecipients, $stat_qids_stillnorecipients if ($main::opts{'debug'} & 0x0100 ) ;
	};
};

# Print result
sub print_result() {
	return if ( $main::types{'acc'} == 0);

	calculatestatistics();

	my $format;

	# Fill still undefined fields (to avoid warnings on sum)
	for my $key (keys %messageUserStats) {	
		if ( ! defined $messageUserStats{$key}->{'sent'}->{'count'} ) { $messageUserStats{$key}->{'sent'}->{'count'} = 0; };
		if ( ! defined $messageUserStats{$key}->{'sent'}->{'size'}  ) { $messageUserStats{$key}->{'sent'}->{'size'} = 0;  };
		if ( ! defined $messageUserStats{$key}->{'rcvd'}->{'count'} ) { $messageUserStats{$key}->{'rcvd'}->{'count'} = 0; };
		if ( ! defined $messageUserStats{$key}->{'rcvd'}->{'size'}  ) { $messageUserStats{$key}->{'rcvd'}->{'size'} = 0;  };
	};
	for my $key (keys %messageDomainStats) {	
		if ( ! defined $messageDomainStats{$key}->{'sent'}->{'count'}     ) { $messageDomainStats{$key}->{'sent'}->{'count'} = 0     };
		if ( ! defined $messageDomainStats{$key}->{'sent'}->{'size'}      ) { $messageDomainStats{$key}->{'sent'}->{'size'} = 0      };
		if ( ! defined $messageDomainStats{$key}->{'rcvd'}->{'count'} ) { $messageDomainStats{$key}->{'rcvd'}->{'count'} = 0 };
		if ( ! defined $messageDomainStats{$key}->{'rcvd'}->{'size'}  ) { $messageDomainStats{$key}->{'rcvd'}->{'size'} = 0  };
	};

	print "\n# Accounting data also contains following overheads:\n";
	print "#  + envelope data size (partially estimated)\n" if (! defined $main::opts{'acc_noenvelopes'});
	print "#  + reject data size (partially estimated)\n" if (! defined $main::opts{'acc_norejects'});
	print "#  + TCP overhead (partially estimated)\n" if (! defined $main::opts{'acc_notcpoverhead'});

	# Print statistics
	# Format: treeview
	if (defined $main::format{"treeview"}) {
		$format = "treeview";
		print "\n\nWARNING(acc): Format '" . $format . "' is currently not supported!\n\n";
	};

	# Format: computer
	if (defined $main::format{"computer"}) {
		$format = "computer";

		::print_headline("ACCOUNTING statistics", $format);
		::print_timerange($format);

		print_summary_acc_domains_short();
	};

	# Format: indented
	if (defined $main::format{"indented"}) {
		$format = "indented";

		::print_timerange($format);

		if ( defined $main::opts{'show_users'} ) {
			## Hook 'print_users_indented'
			my $hookhere = 'print_users_indented';
			my $p_hookshere = $main::hooks{$hookhere};
			for my $p_hook (keys %$p_hookshere) {
				# print "Call hook: " . $hookhere . "/" . $p_hook . "\n";
				my $p_sub = $main::hooks{$hookhere}->{$p_hook};
				&$p_sub();
			};
		} else {
			print "WARNING(acc): format 'indented' is currently only supported on using option 'show_users'\n";
		};
	};

	# Format: txttable
	if (defined $main::format{"txttable"}) {
		$format = "txttable";

		::print_headline("ACCOUNTING statistics", $format);
		::print_timerange($format);

		# Print special status
		print '=' x $main::opts{'print-max-width'} . "\n";
		print "Summary:\n";
		print '-' x $main::opts{'print-max-width'} . "\n";
		for my $key (sort keys %counters) {
			printf "%-*s : %d\n", $main::opts{'print-max-width'} - 35, $key, $counters{$key};
		};
		print '=' x $main::opts{'print-max-width'} . "\n";

		# Print status
		print_summary_acc_users() if ( defined $main::opts{'show_users'} );
		print_summary_acc_domains();
		print_summary_acc_domains_short();
	};

	print "\n\n";
};

# Check options
sub checkoptions() {
	# Default value for: acc_virtualfile
	if (! defined $main::opts{'acc_virtualfile'} ) {
		$main::opts{'acc_virtualfile'} = "/etc/postfix/virtual";
	};
};

# Init
sub beforemainloopstarts() {
	# for my $key (keys %localhost_notations) { print $key . "\n"; };

	if (defined $main::opts{'acc_virtual'} ) {
		# Read virtual file
		print STDERR "INFO: read virtual file: " . $main::opts{'acc_virtualfile'} . " \n" if ($main::opts{'debug'} & 0x0040);

		# read in the virtual file and analyse domains
		open(VIRTUAL,"<" . $main::opts{'acc_virtualfile'}) || die "ERROR: cannot open: " . $main::opts{'acc_virtualfile'};
		while(<VIRTUAL>) {
			$_ =~ s/([^#]*)#.*/$1/o; # Remove comments
			$_ =~ s/[[:space:][:cntrl:]]+$//o; # Remove trailing spaces and control chars
			$_ =~ s/^[[:space:][:cntrl:]]+//o; # Remove leading spaces and control chars
			if ( length($_) == 0 ) { next; }; # Skip empty lines

			printf STDERR $_ . "\n" if ($main::opts{'debug'} & 0x0040);
		
			# Split
			my ($src, $dst) = split /[[:space:]]+/, $_, 2;

			print STDERR "DEBUG: src=" . $src . " dst=" . $dst . "\n" if ($main::opts{'debug'} & 0x0040);

			# Skip postfix virtual domain style
			if ( ! ($src =~ /@/o) ) { next; };

			my $domain = ::extract_domain($src);

			# Run through multible destinations
			print STDERR "Dest: $dst\n" if ($main::opts{'debug'} & 0x0040);
			foreach my $d (split /[[:space:],]+/, $dst) {
				print STDERR "Destsplit: " . $d . "\n" if ($main::opts{'debug'} & 0x0040);
				# Check for dst contains a domain
				if ( $d =~ /@/o ) {
				} else {
					$d .= "@" . $main::opts{'mydomainname'};
					print STDERR "DEBUG: append mydomainname: " . $d . "\n" if ($main::opts{'debug'} & 0x0040);
				};

				if (! defined $check_domains{$d}) {
					# Ok, first time
					$check_domains{$d} = $domain;
					print STDERR "DEBUG: put dst=" . $d . " domain=" . $domain . "\n" if ($main::opts{'debug'} & 0x0040);
				} else {
					# More than once, check equal
					if ( $check_domains{$d} ne $domain ) {
						warn "WARN: virtual has a non uniq reverse domain mapping problem:\nAlready mapped: " . $d . " => " . $check_domains{$d} ."\nNow requested but skipped: " . $d . " => " . $domain . "\n";
					};
				};
			};
		};
		close(VIRTUAL);

		print '='x79 . "\n";
		print "Virtual user => domain mapping\n";
		print '-'x79 . "\n";
		for my $key (keys %check_domains ) {
			print $key . " => " . $check_domains{$key} . "\n";
		};
		print '='x79 . "\n";
	};


	if (defined $main::opts{'acc_customerfile'} ) {
		print STDERR "INFO: read customer file: " . $main::opts{'acc_customerfile'} . " \n" if ($main::opts{'debug'} & 0x0040);

		# read in the customers file
		open(CUSTOMERS,"<" . $main::opts{'acc_customerfile'}) || die "ERROR: cannot open: " . $main::opts{'acc_customerfile'};
		while(<CUSTOMERS>) {
			$_ =~ s/([^#]*)#.*/$1/o; # Remove comments
			$_ =~ s/[[:space:][:cntrl:]]+$//o; # Remove trailing spaces and control chars
			$_ =~ s/^[[:space:][:cntrl:]]+//o; # Remove leading spaces and control chars
			if ( length($_) == 0 ) { next; }; # Skip empty lines

			printf STDERR $_ if ($main::opts{'debug'} & 0x0040);
		
			# Split
			if( /^\s*(\S+)\s*[#]*.*$/ ) {
				$domains_customer{$1} = 1;
			};
		};
		close(CUSTOMERS);

		print '=' x $main::opts{'print-max-width'} . "\n";
		print "Customer domains\n";
		print '-' x $main::opts{'print-max-width'} . "\n";
		for my $key (sort keys %domains_customer ) {
			print $key . "\n";
		};
		print '=' x $main::opts{'print-max-width'} . "\n";
	};
	
};

## Special local parsers

sub logline_cmd_smtp(\$\$\$) {
	return if ( $main::types{'acc'} == 0);
	#if (! defined $_[0]) { die "Missing qid pointer (arg1)"; };
	#if (! defined $_[1]) { die "Missing unixtime pointer (arg2)"; };
	#if (! defined $_[2]) { die "Missing logline pointer (arg3)"; };

	# Check whether qid was already used
	if (defined $messagelog{${$_[0]}}->{'time'}) {
		# possible qid reusage (but not probably inbetween 30 min)
 		if ( abs($messagelog{${$_[0]}}->{'time'} - ${$_[1]}) > 1800 ) {
			printf "WARNING(acc/logline_cmd_smtp): qid reusage qid=%s time_old='%s' time_new='%s' delta=%d sec\n", ${$_[0]}, ::unixtime2string($messagelog{${$_[0]}}->{'time'}), ::unixtime2string(${$_[1]}), ${$_[1]} - $messagelog{${$_[0]}}->{'time'}  if ($main::opts{'debug'} & 0x0200 );;

			# Generate a new qid
			my $newqid;
			do {
				$newqid = sprintf "%s%04x", ${$_[0]}, rand(0x10000);
			} until(! defined $messagelog{$newqid});
		
			# Save orig qid	content
			$messagelog{$newqid} = $messagelog{${$_[0]}};
			$counters{'cmd_qidreusage'}++;

			#printf "DEBUG(acc/logline_cmd_smt): qid reusage check time=%s\n", $messagelog{$newqid}->{'time'};

			# Delete orig qid
			delete $messagelog{${$_[0]}};
		};
	};

	# Set time
	$messagelog{${$_[0]}}->{'time'} = ${$_[1]};

	# Auth found flag
	my $flag_auth_extracted = 0;

	## Extract optional SMTP authentication data
	if ((($client, $smtpauth_method, $smtpauth_username) = ${$_[2]} =~ / client=([^,]+), sasl_method=([^,]+), sasl_username=([^,]+)$/o )) {
		$messagelog{${$_[0]}}->{'client'} = $client;
		$messagelog{${$_[0]}}->{'smtpauth_method'} = $smtpauth_method;
		$messagelog{${$_[0]}}->{'smtpauth_username'} = $smtpauth_username;
		$messagelog{${$_[0]}}->{'smtpauth_sender'} = "!";
		$flag_auth_extracted = 1;
	} elsif ((($client, $smtpauth_method, $smtpauth_username) = ${$_[2]} =~ / client=([^,]+), simpleauth_method=([^,]+), simpleauth_username=([^,]+)$/o )) {
		$messagelog{${$_[0]}}->{'client'} = $client;
		$messagelog{${$_[0]}}->{'smtpauth_method'} = $smtpauth_method;
		$messagelog{${$_[0]}}->{'smtpauth_username'} = $smtpauth_username;
		$messagelog{${$_[0]}}->{'smtpauth_sender'} = "!";
		$flag_auth_extracted = 1;
	} elsif ((($client, $smtpauth_sender) = ${$_[2]} =~ / client=([^,]+), sasl_sender=([^,]+)$/o)) {
		# SMTP authenticated sender
		$messagelog{${$_[0]}}->{'client'} = $client;
		$messagelog{${$_[0]}}->{'smtpauth_sender'} = $smtpauth_sender;
		$messagelog{${$_[0]}}->{'smtpauth_method'} = "!";
		$messagelog{${$_[0]}}->{'smtpauth_username'} = "!";
		$flag_auth_extracted = 1;
	} elsif ((($client, $smtpauth_sender) = ${$_[2]} =~ / client=([^,]+), simpleauth_sender=([^,]+)$/o)) {
		# SMTP authenticated sender
		$messagelog{${$_[0]}}->{'client'} = $client;
		$messagelog{${$_[0]}}->{'smtpauth_sender'} = $smtpauth_sender;
		$messagelog{${$_[0]}}->{'smtpauth_method'} = "!";
		$messagelog{${$_[0]}}->{'smtpauth_username'} = "!";
		$flag_auth_extracted = 1;
	} elsif ((($client) = ${$_[2]} =~ / client=([^,]+)$/o )) {
		$messagelog{${$_[0]}}->{'client'} = $client;
		$messagelog{${$_[0]}}->{'smtpauth_method'} = "!";
		$messagelog{${$_[0]}}->{'smtpauth_username'} = "!";
		$messagelog{${$_[0]}}->{'smtpauth_sender'} = "!";
	};
	if (! defined $client) {
		warn "*** Unmatched client log line:\n" . $_ . "\n*** Fix code!\n";
	};

	## Check clients_authenticated lookup table
	if ($flag_auth_extracted == 1) {
		if (defined $clients_authenticated{$client}->{'smtpauth_unixtime'}) {
			# Client authentication extracted here, cleanup outdated entry in lookup table
			undef $clients_authenticated{$client};
		}
	} else {
		if (defined $clients_authenticated{$client}->{'smtpauth_unixtime'}) {
			# Client authentication exists in lookup table

			# Compare times
			if (${$_[1]} - $clients_authenticated{$client}->{'smtpauth_unixtime'} < 600) {
				# Authentication time < 5 min, take information
				$messagelog{${$_[0]}}->{'smtpauth_method'} =  $clients_authenticated{$client}->{'smtpauth_method'};
				$messagelog{${$_[0]}}->{'smtpauth_username'} = $clients_authenticated{$client}->{'smtpauth_username'};
				$messagelog{${$_[0]}}->{'smtpauth_sender'} = $clients_authenticated{$client}->{'smtpauth_sender'};

				print "DEBUG(acc/logline_cmd_smtp): authenticated client: client=" . $client . " authenticated at unixtime=" . $clients_authenticated{$client}->{'smtpauth_unixtime'} . " message further processed at unixtime=" . ${$_[1]} . "\n" if ($main::opts{'debug'} & 0x10);

				# Cleanup no longer required entry
				# undef $clients_authenticated{$client};
			} else {
				print "NOTICE(acc/logline_cmd_smtp): authenticated client too long ago: client=" . $client . " authenticated at unixtime=" . $clients_authenticated{$client}->{'smtpauth_unixtime'} . " message further processed at unixtime=" . ${$_[1]} . "\n";
				undef $clients_authenticated{$client};
			};
		};
	};

	# Extract IP address
	if ( $client =~ /.*\[(.*)\]/o ) {
		$messagelog{${$_[0]}}->{'client_ip'} = $1;
	};

	$counters{'cmd_smtp'}++;
};

sub logline_cmd_cleanup(\$\$\$) {
	return if ( $main::types{'acc'} == 0);
	#if (! defined $_[0]) { die "Missing qid pointer (arg1)"; };
	#if (! defined $_[1]) { die "Missing unixtime pointer (arg2)"; };
	#if (! defined $_[2]) { die "Missing logline pointer (arg3)"; };

	if (! defined $messagelog{${$_[0]}}->{'time'}) {
		$messagelog{${$_[0]}}->{'time'} = ${$_[1]};
	};

	## Extract message id
	if (${$_[2]} =~ / message-id=([^ ]*)$/o ) {
		$messagelog{${$_[0]}}->{'mid'} = $1;
	};
};

sub logline_cmd_pickup(\$\$\$) {
	return if ( $main::types{'acc'} == 0);
	#if (! defined $_[0]) { die "Missing qid pointer (arg1)"; };
	#if (! defined $_[1]) { die "Missing unixtime pointer (arg2)"; };
	#if (! defined $_[2]) { die "Missing logline pointer (arg3)"; };

	# Check whether qid was already used
	if (defined $messagelog{${$_[0]}}->{'time'}) {
		# possible qid reusage (but not probably inbetween 30 min)
 		if ( abs($messagelog{${$_[0]}}->{'time'} - ${$_[1]}) > 1800 ) {
			printf "WARNING(acc/logline_cmd_smtp): qid reusage qid=%s time_old='%s' time_new='%s' delta=%d sec\n", ${$_[0]}, ::unixtime2string($messagelog{${$_[0]}}->{'time'}), ::unixtime2string(${$_[1]}), ${$_[1]} - $messagelog{${$_[0]}}->{'time'}  if ($main::opts{'debug'} & 0x0200 );;

			# Generate a new qid
			my $newqid;
			do {
				$newqid = sprintf "%s%04x", ${$_[0]}, rand(0x10000);
			} until(! defined $messagelog{$newqid});
		
			# Save orig qid	content
			$messagelog{$newqid} = $messagelog{${$_[0]}};
			$counters{'cmd_qidreusage'}++;

			#printf "DEBUG(acc/logline_cmd_smt): qid reusage check time=%s\n", $messagelog{$newqid}->{'time'};

			# Delete orig qid
			delete $messagelog{${$_[0]}};
		};
	};

	# Set time
	$messagelog{${$_[0]}}->{'time'} = ${$_[1]};

	$counters{'cmd_qid'}++;
	
	$counters{'cmd_pickup'}++;
};

sub logline_cmd_from(\$\$\$\$) {
	return if ( $main::types{'acc'} == 0);
	#if (! defined $_[0]) { die "Missing qid pointer (arg1)"; };
	#if (! defined $_[1]) { die "Missing unixtime pointer (arg2)"; };
	#if (! defined $_[2]) { die "Missing addr pointer (arg3)"; };
	#if (! defined $_[3]) { die "Missing size pointer (arg4)"; };

	if (! defined $messagelog{${$_[0]}}->{'time'}) {
		$messagelog{${$_[0]}}->{'time'} = ${$_[1]};
	};

	$messagelog{${$_[0]}}->{'from'} = ${$_[2]};
	$messagelog{${$_[0]}}->{'size'} = ${$_[3]};

	$counters{'cmd_from'}++;
};


sub logline_cmd_to(\$\$\$\$\$) {
	return if ( $main::types{'acc'} == 0);
	#if (! defined $_[0]) { die "Missing qid pointer (arg1)"; };
	#if (! defined $_[1]) { die "Missing unixtime pointer (arg2)"; };
	#if (! defined $_[2]) { die "Missing addr pointer (arg3)"; };
	#if (! defined $_[3]) { die "Missing status pointer (arg4)"; };
	#if (! defined $_[4]) { die "Missing relay pointer (arg5)"; };

	if (! defined $messagelog{${$_[0]}}->{'time'}) {
		$messagelog{${$_[0]}}->{'time'} = ${$_[1]};
	};

	# Initial
	if (! defined $messagelog{${$_[0]}}->{'count'}) {
		$messagelog{${$_[0]}}->{'count'} = 0;
	};


	# Ok, one or more "to" already filled, check for equal and update
	for my $cloneid (keys %{$messagelog{${$_[0]}}->{'rcpt'}}) {
		if ( $messagelog{${$_[0]}}->{'rcpt'}->{$cloneid}->{'to'} eq ${$_[2]} ) {
			# same "to" as already filled, check status
			if ( $messagelog{${$_[0]}}->{'rcpt'}->{$cloneid}->{'status'} ne "sent" ) {
				if (${$_[3]} eq "bounced") {
					# Message bounced
					$counters{'cmd_to_bounced'}++;
					# Remove this clone
					delete $messagelog{${$_[0]}}->{'rcpt'}->{$cloneid};
					goto ("LABEL_logline_cmd_to_end");
				};

				if (${$_[3]} eq "deferred") {
					# Message deferred
					$counters{'cmd_to_deferred'}++;
				};

				# update status and relay
				$messagelog{${$_[0]}}->{'rcpt'}->{$cloneid}->{'status'} = ${$_[3]};
				$messagelog{${$_[0]}}->{'rcpt'}->{$cloneid}->{'relay'} = ${$_[4]};

				if ( ${$_[4]} =~ /.*\[(.*)\]/o ) {
					$messagelog{${$_[0]}}->{'rcpt'}->{$cloneid}->{'relay_ip'} = $1;
					# print STDERR "DEBUG(acc/logline_cmd_to): relay_ip=" . $messagelog{${$_[0]}}->{'rcpt'}->{0}->{'relay_ip'} . "\n";
				};
				goto ("LABEL_logline_cmd_to_end");
			} else {
				# Same "to", but first already sent, so double recipient
				goto ("LABEL_logline_cmd_to_do_clone");
			};
		};
	};

LABEL_logline_cmd_to_do_clone:
	# No entry found
	if (${$_[3]} eq "bounced") {
		# Message bounced
		$counters{'cmd_to_bounced'}++;
		# do not create a new entry
		return;
	};

	printf STDERR "DEBUG(acc): create a new clone from=%s to=%s\n", $messagelog{${$_[0]}}->{'from'}, ${$_[2]} if ($main::opts{'debug'} & 0x0040 ) ;

	# Create a new rcpt entry
	#printf STDERR "INFO: more than one recipient, clone id %s -> %s\n", ${$_[0]}, $newqid if ($main::opts{'debug'} & 0x0040 ) ;

	$messagelog{${$_[0]}}->{'rcpt'}->{$messagelog{${$_[0]}}->{'count'}}->{'to'} = ${$_[2]};
	$messagelog{${$_[0]}}->{'rcpt'}->{$messagelog{${$_[0]}}->{'count'}}->{'status'} = ${$_[3]};
	$messagelog{${$_[0]}}->{'rcpt'}->{$messagelog{${$_[0]}}->{'count'}}->{'relay'} = ${$_[4]};
	if ( ${$_[4]} =~ /.*\[(.*)\]/o ) {
		$messagelog{${$_[0]}}->{'rcpt'}->{$messagelog{${$_[0]}}->{'count'}}->{'relay_ip'} = $1;
		# print STDERR "DEBUG(acc/logline_cmd_to): relay_ip=" . $messagelog{${$_[0]}}->{'rcpt'}->{$messagelog{${$_[0]}}->{'count'}}->{'relay_ip'} . "\n";
	};

	$messagelog{${$_[0]}}->{'count'}++;

LABEL_logline_cmd_to_end:
	$counters{'cmd_to'}++;
	if (! defined $main::opts{'acc_nomemopt'}) {
		#if (($counters{'cmd_to'} % 1000) == 0) {
		if (($counters{'cmd_to'} % 100) == 0) {
			print "DEBUG(acc): intermediate statistics calculation\n" if ($main::opts{'debug'} & 0x100);
			calculatestatistics(1);
		};
	};
};

# Parse logline
sub loglineparser(\$\$) {
	return if ( $main::types{'acc'} == 0);

	if (! defined $_[0]) { die "Missing time pointer (arg1)"; };
	if (! defined $_[1]) { die "Missing logline pointer (arg2)"; };

	my ($cmd, $qid, $rest);
	my ($addr, $orig_to, $relay, $delay, $status, $size);
	my ($client_ip, $message, $from, $to, $helo);

	# Example: Feb 28 13:19:59 host amavis[1296]: (01296-01) Blocked SPAM, [192.167.219.83] [20.200.15.23] <sender@domain.example> -> <account@domain.example>, Message-ID: <4996irh843k16$08566$x21my96@Clementd725utz505e5b>, Hits: 11.322, Size: 62306, 2629 ms
	# Example: Feb 28 14:26:57 host amavis[1088]: (01088-09) Blocked INFECTED (EICAR-Test-File), [IPv6:3ffe::1] [3ffe::1] <sender@domain.example> -> <account@domain.example>, quarantine: virus-20050228-142656-01088-09, Message-ID: <20050228132655.GA7155@host.domain.example>, Hits: -, Size: 1147, 1180 NOTICEif ( ${$_[1]} =~ /^.*\samavis\[.*\]: \(([^\)]+)\) Blocked /io ) {
	# Example: Sep 12 12:47:04 host amavis[2197]: (02197-10) Blocked CLEAN, [192.0.2.1] [192.0.2.2] <sender@domain.example> -> <account@domain.example>, Message-ID: <xxxxxxxxxxxxxx@domain.example>, Hits: -, Size: 72646291, 449519 ms      (size limit exceeded)
	if ( ${$_[1]} =~ /^.*\samavis\[.*\]: \(([^\)]+)\) Blocked /io ) {

		print "DEBUG(acc/loglineparser): matched: '" . ${$_[1]} . "'\n" if ($main::opts{'debug'} & 0x2);

		# Special treatment of amavis blocked messages
		$rest = "";

		if ( ${$_[1]} =~ /^.*\samavis\[.*\]: \(([^\)]+)\) Blocked (SPAM|CLEAN), \[([^]]+)\].* <(.*)> -> <([^,]*)>,.*, Size: ([0-9]+),/io ) {
			$message = $1;
			$qid = $2;
			$client_ip = $3;
			$from = $4;
			# Note that only the first recipient will be used here (usually, a second one has the same domain)
			$to = $5;
			$size = $6;
		} elsif ( ${$_[1]} =~ /^.*\samavis\[.*\]: \(([^\)]+)\) Blocked INFECTED \(([^)]+)\), \[([^]]+)\].* <(.*)> -> <([^,]*)>,.*, Size: ([0-9]+),/io ) {
			$qid = $1;
			$rest = $2;
			$client_ip = $3;
			$from = $4;
			# Note that only the first recipient will be used here (usually, a second one has the same domain)
			$to = $5;
			$size = $6;		
			$message = "INFECTED";
		} elsif ( ${$_[1]} =~ /^.*\samavis\[.*\]: \(([^\)]+)\) Blocked (SPAM|CLEAN), \[([^]]+)\].* <(.*)> -> <([^,]*)>,/io ) {
			$message = $1;
			$qid = $2;
			$client_ip = $3;
			$from = $4;
			$to = $5;
			$size = 0;
			warn "NOTICE: enable logging of 'Size' in amavis: " . ${$_[1]};
		} elsif ( ${$_[1]} =~ /^.*\samavis\[.*\]: \(([^\)]+)\) Blocked INFECTED \(([^)]+)\), \[([^]]+)\].* <(.*)> -> <([^,]*)>,/io ) {
			$qid = $1;
			$rest = $2;
			$client_ip = $3;
			$from = $4;
			$to = $5;
			$size = 0;		
			$message = "INFECTED";
			warn "NOTICE: enable logging of 'Size' in amavis: " . ${$_[1]};
		} else {
			warn "WARN: unsupported log line: " . ${$_[1]};
			return;
		};

		print "DEBUG(acc/loglineparser): id=$qid message=$message rest=$rest client_ip=$client_ip from=$from to=$to size=$size\n" if ($main::opts{'debug'} & 0x2);

		# Check IP addresses
		if ( $client_ip ne "" ) {
			# Hook "testipaddress"
			for my $p_hook (keys %{$main::hooks{'testipaddress'}}) {
				if ( &{$main::hooks{'testipaddress'}->{$p_hook}} ($client_ip) != 0 ) {
					$counters{'notaccounted_client_ip_excluded'}++;
					return;
				};
			};
		};

		# Adjust addresses
		if ($from eq "") { $from = "from=<>" };
		if ($from eq "#@[]") { $from = "from=<#@[]>"; };

		$counters{'amavis_blocked'}++;

		$from = lc ($from);
		$to   = lc ($to);

		# Hook "modifyaddress"
		for my $p_hook (keys %{$main::hooks{'modifyaddress'}}) {
			$from = &{$main::hooks{'modifyaddress'}->{$p_hook}} ($from);
			$to   = &{$main::hooks{'modifyaddress'}->{$p_hook}} ($to);
		};

		$to_domain = ::extract_domain($to);
		$from_domain = ::extract_domain($from);

		## Calculate mail envelope data bytes (estimation)
		#
		# 220 server.example.com ESMTP [4+sizeof(localhelostring)+6+2=12+sizeof(localhelostring)]
		# HELO test [5+sizeof(remotehelostring)+2=7+sizeof(remotehelostring)] -> note: helostring unknown!
		# 250 server.example.com [4+sizeof(hostname)+2=6+sizeof(hostname)]
		# MAIL FROM: <sender@example.com> [11+1+sizeof(sender)+1+2=15+sizeof(sender)]
		# 250 Ok [6+2=8]
		# RCPT TO: <rcpt@example.com> [9+1+sizeof(rcpt)+1+2=13+sizeof(rcpt)]
		# DATA [4+2=6]
		# 354 End data with <CR><LF>.<CR><LF> [35+2=37]
		# text (size) [=size]
		# . [1+2=3]
		# 550 5.7.1 Message content rejected, id=01088-09 - VIRUS: EICAR-Test-File [44+sizeof(qid)+sizeof(rest)+sizeof(type($message))
		# 221 Bye [7+2=9]

		# 3x40 SYN, 4x40 FIN, 12x40 ACK = 760
		# Assume MTU 1500 and 10% ACKs by receiver, uncalculable: TCP options


		# Account blocked message now
		if (! defined $main::opts{'acc_noenvelopes'} ) {
			$mailtarasize = 160 + 2* length($main::opts{'myhostname'}) + length($from) + length($to) + length($qid);
			if ($message eq "INFECTED") {
				$mailtarasize += 5 + length($rest); # VIRUS + virus name
			} elsif ($message eq "SPAM") {
				$mailtarasize += 3; # UBE
			};
		} else {
			$mailtarasize = 0;
		};

		if ( ! defined $main::opts{'acc_notcpoverhead'} ) {
			$mailtarasize += 760 + int(($size + 1459) / 1460) * 44;
		};

		$messageUserStats{$to}->{'rcvd'}->{'count'} ++;
		$messageUserStats{$to}->{'rcvd'}->{'size'} += $mailtarasize + $size;
		$messageDomainStats{$to_domain}->{'rcvd'}->{'count'} ++;
		$messageDomainStats{$to_domain}->{'rcvd'}->{'size'} += $mailtarasize + $size;
		printf "*amavisblockedAcc: to=%s tara=%d size=%d\n", $to, $mailtarasize, $size if ($main::opts{'debug'} & 0x2 );	# orig: 0x0400

		return;
	};


	# Catch Postfix Proxy SMTP auth lines without unique QID
	# Example. May  2 11:23:11 host postfix/smtpd[24062]: NOQUEUE: client=client.domain.example[1.2.3.4], sasl_method=PLAIN, sasl_username=user@domain.example
	if (${$_[1]} =~ /^.*\spostfix\/smtpd\[[0-9]+\]: NOQUEUE: client=.*$/o ) {
		print "DEBUG(acc/loglineparser): matched: '" . ${$_[1]} . "'\n" if ($main::opts{'debug'} & 0x1);

		## Extract optional SMTP authentication data
		if ((${$_[1]} =~ /.* client=([^,]+), sasl_method=([^,]+), sasl_username=([^,]+)$/o ) ) {
			$client = $1;
			$clients_authenticated{$client}->{'smtpauth_method'} = $2;
			$clients_authenticated{$client}->{'smtpauth_username'} = $3;
			$clients_authenticated{$client}->{'smtpauth_sender'} = "!";
			#print "DEBUG(acc/clients_authenticated): match A\n" if ($main::opts{'debug'} & 0x10);
		} elsif ((${$_[1]} =~ /.* client=([^,]+), simpleauth_method=([^,]+), simpleauth_username=([^,]+)$/o )) {
			$client = $1;
			$clients_authenticated{$client}->{'smtpauth_method'} = $2;
			$clients_authenticated{$client}->{'smtpauth_username'} = $3;
			$clients_authenticated{$client}->{'smtpauth_sender'} = "!";
			#print "DEBUG(acc/clients_authenticated): match B\n" if ($main::opts{'debug'} & 0x10);
		} elsif ((${$_[1]} =~ /.* client=([^,]+), sasl_sender=([^,]+)$/o)) {
			# SMTP authenticated sender
			$client = $1;
			$clients_authenticated{$client}->{'smtpauth_sender'} = $2;
			$clients_authenticated{$client}->{'smtpauth_method'} = "!";
			$clients_authenticated{$client}->{'smtpauth_username'} = "!";
			#print "DEBUG(acc/clients_authenticated): match C\n" if ($main::opts{'debug'} & 0x10);
		} elsif ((${$_[1]} =~ /.* client=([^,]+), simpleauth_sender=([^,]+)$/o)) {
			# SMTP authenticated sender
			$client = $1;
			$clients_authenticated{$client}->{'smtpauth_sender'} = $smtpauth_sender;
			$clients_authenticated{$client}->{'smtpauth_method'} = "!";
			$clients_authenticated{$client}->{'smtpauth_username'} = "!";
			#print "DEBUG(acc/clients_authenticated): match D\n" if ($main::opts{'debug'} & 0x10);
		} elsif ((($client) = ${$_[1]} =~ /.* client=([^,]+)$/o)) {
			# no SMTP authenticated sender
			if (defined $clients_authenticated{$client}) {
				print "DEBUG(acc/clients_authenticated): got: client=" . $client . " with no authentication information, reset\n" if ($main::opts{'debug'} & 0x10);
			};	
			undef $clients_authenticated{$client};
			return;
		};
		if (! defined $client) {
			warn "*** Unmatched client log line:\n" . $_ . "\n*** Fix code!\n";
		};

		if (defined $client) {
			# Set timestamp
			$clients_authenticated{$client}->{'smtpauth_unixtime'} = ${$_[0]};

			print "DEBUG(acc/clients_authenticated): got: unixtime=" . $clients_authenticated{$client}->{'smtpauth_unixtime'} . " client=" . $client . " smtpauth_sender=" . $clients_authenticated{$client}->{'smtpauth_sender'} . " smtpauth_method=" . $clients_authenticated{$client}->{'smtpauth_method'}  . " smtpauth_username=" . $clients_authenticated{$client}->{'smtpauth_username'} ."\n" if ($main::opts{'debug'} & 0x10);
		};

		return;
	};



	# Example: Feb  7 16:10:17 host postfix/smtpd[31956]: (CA9461386E|NOQUEUE):...
	if (! ( ${$_[1]} =~ /^.*\spostfix\/([^\[:]+).*?: ([A-F0-9]{8,12}|NOQUEUE): (.*)$/o ) ) {
		# Unmatched logline
		# E.g.: unmatched qid
		#print "DEBUG(acc/loglineparser): skipped: '" . ${$_[1]} . "'\n";
		return;
	};

	print "DEBUG(acc/loglineparser): matched: '" . ${$_[1]} . "'\n" if ($main::opts{'debug'} & 0x1);

	$cmd = $1;
	$qid = $2;
	$rest = $3;

	if ( $cmd eq "smtpd" ) {
		# Example: Feb  7 16:10:17 host postfix/smtpd[31956]: CA9461386E: client=clientname[ipaddress]

		if ( $rest =~ /^reject: /o ) {
			# Example: Jan  1 01:35:54 host postfix/smtpd[12546]: D126F13866: reject: ...
			if ($qid ne "NOQUEUE" && ! defined $messagelog{$qid} ) {
				# for older postfix version where qid is given in reject
				# Rejected but qid not in log, skip
				# Happens e.g. one e-mail should be delivered to 2 or more recipients but client is rejected
				return;
			};

			# Rejected
			$counters{'cmd_smtpd_rejected'}++;

			# Account envelope of rejected mail with "RCPT from"
			if ( (! $main::opts{'acc_norejects'} ) && ( $rest =~ /^reject: RCPT from /o ) ) {
				#printf "*rejectAcc: line=%s\n", $rest if ($main::opts{'debug'} & 0x0400 );	

				# Example: RCPT from adsl-63-206-123-11.dsl.snfc21.pacbell.net[63.206.123.11]: 554 <adsl-63-206-123-11.dsl.snfc21.pacbell.net[63.206.123.11]>: Client host rejected: Please use SMTP relay of your e-mail provider; from=<paulhpom@aol.com> to=<recipient@example.com> proto=SMTP helo=<aol.com>

				($client_ip, $message, $from, $to, $helo) = $rest =~ /^reject: RCPT from .*\[([0-9A-Fa-f\.:]+)\]: ([0-9]{3} .*); from=<(.*)> to=<(.*)> proto=[^ ]* helo=<(.*)>$/o;
				printf "*rejectAcc: client_ip=%s message=%s from=%s to=%s helo=%s\n", $client_ip, $message, $from, $to, $helo if ($main::opts{'debug'} & 0x0400 );	

				# Check IP address of client
				if ( $client_ip ne "" ) {
					# Hook "testipaddress"
					for my $p_hook (keys %{$main::hooks{'testipaddress'}}) {
						if ( &{$main::hooks{'testipaddress'}->{$p_hook}} ($client_ip) != 0 ) {
							$counters{'notaccounted_client_ip_excluded'}++;
							return;
						};
					};
				};

				# Modify addresses
				if ($from eq "") { $from = "from=<>" };
				if ($from eq "#@[]") { $from = "from=<#@[]>"; };
				$from = lc ($from);
				$to   = lc ($to);

				# Hook "modifyaddress"
				for my $p_hook (keys %{$main::hooks{'modifyaddress'}}) {
					$from = &{$main::hooks{'modifyaddress'}->{$p_hook}} ($from);
					$to   = &{$main::hooks{'modifyaddress'}->{$p_hook}} ($to);
				};

				$to_domain = ::extract_domain($to);
				$from_domain = ::extract_domain($from);

				## Calculate mail envelope data bytes (estimation)
				#
				# 220 server.example.com ESMTP [4+sizeof(localhelostring)+6+2=12+sizeof(localhelostring)]
				# HELO test [5+sizeof(remotehelostring)+2=7+sizeof(remotehelostring)]
				# 250 server.example.com [4+sizeof(hostname)+2=6+sizeof(hostname)]
				# MAIL FROM: <sender@example.com> [11+1+sizeof(sender)+1+2=15+sizeof(sender)]
				# 250 Ok [6+2=8]
				# RCPT TO: <rcpt@example.com> [9+1+sizeof(rcpt)+1+2=13+sizeof(rcpt)]
				# 554 Service unavailable; Client host [217.232.177.23] blocked using relays.osirusoft.com [=sizeof(message)+2]
				# QUIT [=6]
				# 221 Bye [=9]

				# 3x40 SYN, 4x40 FIN, 9x40 ACK = 640
				# Missing, but uncalculable: TCP options

				# $mailtarasize = 12 + length($main::opts{'myhostname'}) + 7 + length($helo) + 6 + length($main::opts{'myhostname'}) + 15 + length($from) + 8 + 13 + length($to) + length($message) + 2 + 6 + 9+ 640;

				$mailtarasize = 76 + 2*length($main::opts{'myhostname'}) + length($helo) + length($from) + length($to) + length($message);

				if ( ! defined $main::opts{'acc_notcpoverhead'} ) {
					$mailtarasize += 640;
				};
				
				$messageUserStats{$to}->{'rcvd'}->{'count'} ++;
				$messageUserStats{$to}->{'rcvd'}->{'size'} += $mailtarasize;
				$messageDomainStats{$to_domain}->{'rcvd'}->{'count'} ++;
				$messageDomainStats{$to_domain}->{'rcvd'}->{'size'} += $mailtarasize;
				printf "*rejectAcc: to=%s tara=%d\n", $to, $mailtarasize if ($main::opts{'debug'} & 0x0400 );	
			};


			if ($qid ne "NOQUEUE" && defined $messagelog{$qid}->{'time'} ) {
 				if ( abs($messagelog{$qid}->{'time'} - ${$_[0]}) < 1800 ) {
					# Remove qid if client was already set (avoid logfile timeline troubles)
					# and time distance is short enough (avoid deleting wrong qid)
					delete $messagelog{$qid};
					#print "DEBUG(acc/loglineparser/" . $cmd . "): rejected/deleted qid=" . $qid . "\n";
					return;
				};
			};
			return;
			# end of reject
		} elsif ( $rest =~ /^discard: /o ) {
			# Example: Feb 18 13:02:00 server postfix/smtpd[22323]: 16875BB40: discard: RCPT from client[1.2.3.4]: <sender@domain.example>: Sender address Delivery notification; from=<sender@domain.example> to=<recipient@domain.example> proto=SMTP helo=<test>
			if (! defined $messagelog{$qid} ) {
				# Discarded but qid not in log, skip
				# Happens e.g. one e-mail should be delivered to 2 or more recipients but client is rejected
				return;
			};

			# Discarded
			$counters{'cmd_smtpd_discarded'}++;

			# Account envelope of discarded mail with "RCPT from"
			if ( (! $main::opts{'acc_norejects'} ) && ( $rest =~ /^discard: RCPT from /o ) ) {
				#printf "*rejectAcc: line=%s\n", $rest if ($main::opts{'debug'} & 0x0400 );	

				# Example: RCPT from client[1.2.3.4]: <sender@domain.example>: Sender address Delivery notification; from=<sender@domain.example> to=<recipient@domain.example> proto=SMTP helo=<test>

				my ($client_ip, $message, $from, $to, $helo) = $rest =~ /^discard: RCPT from .*\[([0-9A-Fa-f\.:]+)\]: (.*); from=<(.*)> to=<(.*)> proto=[^ ]* helo=<(.*)>$/o;
				# printf "*discardAcc: client_ip=%s message=%s from=%s to=%s helo=%s\n", $client_ip, $message, $from, $to, $helo if ($main::opts{'debug'} & 0x0400 );	

				# Check IP address of client
				if ( $client_ip ne "" ) {
					# Hook "testipaddress"
					for my $p_hook (keys %{$main::hooks{'testipaddress'}}) {
						if ( &{$main::hooks{'testipaddress'}->{$p_hook}} ($client_ip) != 0 ) {
							$counters{'notaccounted_client_ip_excluded'}++;
							return;
						};
					};
				};

				# Modify addresses
				if ($from eq "") { $from = "from=<>" };
				if ($from eq "#@[]") { $from = "from=<#@[]>"; };
				$from = lc ($from);
				$to   = lc ($to);

				# Hook "modifyaddress"
				for my $p_hook (keys %{$main::hooks{'modifyaddress'}}) {
					$from = &{$main::hooks{'modifyaddress'}->{$p_hook}} ($from);
					$to   = &{$main::hooks{'modifyaddress'}->{$p_hook}} ($to);
				};

				$to_domain = ::extract_domain($to);
				$from_domain = ::extract_domain($from);

				## Calculate mail envelope data bytes (estimation)
				#
				# 220 server.example.com ESMTP [4+sizeof(localhelostring)+6+2=12+sizeof(localhelostring)]
				# HELO test [5+sizeof(remotehelostring)+2=7+sizeof(remotehelostring)]
				# 250 server.example.com [4+sizeof(hostname)+2=6+sizeof(hostname)]
				# MAIL FROM: <sender@example.com> [11+1+sizeof(sender)+1+2=15+sizeof(sender)]
				# 250 Ok [6+2=8]
				# RCPT TO: <rcpt@example.com> [9+1+sizeof(rcpt)+1+2=13+sizeof(rcpt)]
				# 250 Ok [6+2=8]
				# DATA [4+2=6]
				# 354 End data with <CR><LF>.<CR><LF> [35+2=37]
				# +++discarded data, size unknown+++ [?+2=2]
				# . [1+2=3]
				# 250 Ok: queued as BC389BB40 [27+2=29]
				# QUIT [=6]
				# 221 Bye [=9]

				# 3x40 SYN, 4x40 FIN, 14x40 ACK = 840
				# Missing, but uncalculable: TCP options and size of body

				$mailtarasize = 167 + 2*length($main::opts{'myhostname'}) + length($helo) + length($from) + length($to);

				if ( ! defined $main::opts{'acc_notcpoverhead'} ) {
					$mailtarasize += 840;
				};
				
				$messageUserStats{$to}->{'rcvd'}->{'count'} ++;
				$messageUserStats{$to}->{'rcvd'}->{'size'} += $mailtarasize;
				$messageDomainStats{$to_domain}->{'rcvd'}->{'count'} ++;
				$messageDomainStats{$to_domain}->{'rcvd'}->{'size'} += $mailtarasize;
				printf "*rejectAcc: to=%s tara=%d\n", $to, $mailtarasize if ($main::opts{'debug'} & 0x0400 );	
			};


			if (defined $messagelog{$qid}->{'time'} ) {
 				if ( abs($messagelog{$qid}->{'time'} - ${$_[0]}) < 1800 ) {
					# Remove qid if client was already set (avoid logfile timeline troubles)
					# and time distance is short enough (avoid deleting wrong qid)
					delete $messagelog{$qid};
					#print "DEBUG(acc/loglineparser/" . $cmd . "): rejected/deleted qid=" . $qid . "\n";
					return;
				};
			};
			return;
			# end of discard
		} elsif ( $rest =~ /^client=/o ) {
			&logline_cmd_smtp(\$qid, \${$_[0]}, \${$_[1]});
			return;
		} else {
			# not interesting here
			die "ERROR(acc/loglineparser/" . $cmd . "): Line contains unrecognized values: qid=" . $qid . " '" . $rest . "' !FIXCODE!";
			return;

		};
		return;
	} elsif ($cmd eq 'pickup') {
		if (! ( $rest =~ /^(sender|uid)=/o ) ) {
			# not interesting here
			return;
		};
		&logline_cmd_pickup(\$qid, \${$_[0]}, \${$_[1]});
		return;
	} elsif ($cmd eq 'cleanup') {
		&logline_cmd_cleanup(\$qid, \${$_[0]}, \${$_[1]});
		return;
	} elsif ($cmd eq 'pipe' || $cmd eq 'local' || $cmd eq "smtp") {
		if ( $rest =~ /^to=<(.*)>, orig_to=<(.*)>, relay=([^,]+), delay=[\-0-9]+, status=([^ ]+)/o ) {
			# Example: to=<account@server.example.com>, orig_to=<account@example.com>, relay=avcheck, delay=1, status=sent ...additional text
			$addr = lc($1); # force lower case
			$orig_to = $2;
			$relay = $3;
			$status = $4;

			# replace address with orig_to address (if origto contains an @)
			if ( $orig_to =~ /@/o ) {
				# fill in special hash for proper accounting of forwarding via local relay
				if (defined $messagelog{$qid}->{'mid'} ) {
					$messageid_origto{$addr}->{$messagelog{$qid}->{'mid'}} = $orig_to;
					#print "DEBUG: fill mid\n";
				};

                        	$addr = lc($orig_to); # force lower case
			};
			#printf "DEBUG(acc/loglineparser/M1): qid=%s to=%s relay=%s status=%s\n", $qid, $addr, $relay, $status;
		} elsif ( $rest =~ /^to=<(.*)>, relay=([^,]+), delay=[\-0-9]+, status=([^ ]+)/o ) {
			# Example: to=<account@example.com>, relay=avcheck, delay=1, status=sent ...additional text
			$addr = lc($1); # force lower case
			$relay = $2;
			$status = $3;
			#printf "DEBUG(acc/loglineparser/M2): qid=%s to=%s relay=%s status=%s\n", $qid, $addr, $relay, $status;
		} elsif ( $rest =~ /^to=<([^>]*)>/o ) {
			die "ERROR(acc/loglineparser/" . $cmd . "): Line contains unrecognized values: qid=" . $qid . " '" . $rest . "' !FIXCODE!";
		} else {
			# not interesting here
			return;
		};

		# Hook "modifyaddress"
		for my $p_hook (keys %{$main::hooks{'modifyaddress'}}) {
			$addr = &{$main::hooks{'modifyaddress'}->{$p_hook}} ($addr);
		};

		&logline_cmd_to(\$qid, \${$_[0]}, \$addr, \$status, \$relay);
		return;
	} elsif ($cmd eq 'nqmgr' || $cmd eq 'qmgr') {
		if ( $rest =~ /^from=<(.*)>, size=([0-9]+)/o ) {
			# Example: from=<account@example.com>, size=1352, nrcpt=1 ...additional txt
			# Catch also (not so valid): from=<<>@uke.uni-hamburg.de>, size= 
			$addr = lc($1);
			$size = $2;
		} elsif ( $rest =~ /^from=<(.*)>, status=([^ ]+)/o ) { 
			# Example: from=<account@example.com>, status=expired, returned to sender
			# TODO: remove this qid from accounting
			# Return for now
# Todo
			return;
		} elsif ( $rest =~ /^to=<(.*)>, relay=([^,]+), delay=[\-0-9]+, status=([^ ]+)/o ) {
			# Example: to=<xxx@xxx.xx>, relay=none, delay=0, status=deferred ....
			# Only occur on older postfix versions (qmgr)
			$addr = lc($1); # force lower case
			$relay = $2;
			$status = $3;
			# Update status
			&logline_cmd_to(\$qid, \${$_[0]}, \$addr, \$status, \$relay);
			return;
		} elsif ( $rest =~ /^to=<(.*)>, orig_to=<(.*)>, relay=([^,]+), delay=[\-0-9]+, status=([^ ]+)/o ) {
			# Example: to=<account@example.com>, orig_to=<account@example.com>, relay=none, delay=1, status=bounced ...
			$addr = lc($1); # force lower case
			$orig_to = $2;
			$relay = $3;
			$status = $4;
			# replace address with orig_to address (if origto contains an @)
			if ( $orig_to =~ /@/o ) {
				# fill in special hash for proper accounting of forwarding via local relay
				$messageid_origto{$addr}->{$messagelog{$qid}->{'mid'}} = $orig_to;

                        	$addr = lc($orig_to); # force lower case
			};
			# Update status
			&logline_cmd_to(\$qid, \${$_[0]}, \$addr, \$status, \$relay);
			return;
		} elsif ( $rest =~ /^to=<([^>]*)>/o ) {
			die "ERROR(acc/loglineparser/" . $cmd . "): Line contains unrecognized values: qid=" . $qid . " '" . $rest . "' !FIXCODE!";
		} elsif ( $rest =~ /^from=<([^>]*)>/o ) {
			die "ERROR(acc/loglineparser/" . $cmd . "): Line contains unrecognized values: qid=" . $qid . " '" . $rest . "' !FIXCODE!";
		} else {
			# not interesting here
			return;
		};

		if ($addr) {
			# Check for bounce addresses
			if ($addr eq "#@[]") {
				$addr = "from=<#@[]>";
			};
		} else {
			$addr = "from=<>";
		};

		# Hook "modifyaddress"
		for my $p_hook (keys %{$main::hooks{'modifyaddress'}}) {
			$addr = &{$main::hooks{'modifyaddress'}->{$p_hook}} ($addr);
		};

		&logline_cmd_from(\$qid, \${$_[0]}, \$addr, \$size);
		return;
	};


};

## Local functions

sub print_summary_acc_users_treeview() {
	my %tree_acc_users;

	# print "DEBUG/" . $module_name . "/print_summary_acc_users_treeview: called\n";

	# Create tree
	my $secondleveldomain;
	my $size;
	for my $user (keys %messageUserStats) {
		$secondleveldomain = ::extract_2ndleveldomain($user);
		$size = $messageUserStats{$user}->{'sent'}->{'size'} + $messageUserStats{$user}->{'rcvd'}->{'size'};
		$tree_acc_users{$secondleveldomain}->{$user} = $size;
		$tree_acc_users{$secondleveldomain}->{'TOTAL'} += $size;
	};

	# print "DEBUG/" . $module_name . "/print_summary_acc_users_treeview: tree generated\n";

	#for my $key (keys %tree_acc_users) {
	#	print $key . "\n";
	#};

	print_domains_users_indent(\%tree_acc_users);
};

# Print users/domains in an indented format
sub print_users_indent($) {
        my $p = $_[0] || die "missing hash pointer";

	# Sorted by size (biggest first)
        foreach my $k0 ( sort { $$p{$b} <=> $$p{$a} } keys %$p ) {
		next if ($k0 eq 'TOTAL'); # do not display "total" value here
		next if ($$p{$k0} == 0); # do not display entries without any traffic
		printf "    %-60s  %9s\n", substr($k0, 0, 60),
			$main::numberformat{$main::opts{'numberformat'}}->format_bytes($$p{$k0});
	};
};

sub print_domains_users_indent($;@) {
        my $p = $_[0] || die "missing hash pointer";
        my $list = $_[1]; # optional list of keys
        my $p0;
	my $startflag = 0;

        if (! defined $p) { die "hash pointer is undefined"; };
        if (! %$p) { print "WARNING: no data"; };
        if (! defined $list) { $list = ""; };

	print '=' x $main::opts{'print-max-width'} . "\n";
	print "Domains/Users accounting statistics indented\n";
	::print_timerange_normal();
	print '-' x $main::opts{'print-max-width'} . "\n";
	printf "%-*s      %9s%9s\n", $main::opts{'print-max-width'} - 24, "Domain/User", "Total", "Single";
	print '-' x $main::opts{'print-max-width'} . "\n";
        if ($list eq "" ) {
		# Sorted by size (biggest first)
                for my $k ( sort { $$p{$b}->{'TOTAL'} <=> $$p{$a}->{'TOTAL'} } keys %$p ) {
                        $p0 = $$p{$k};
			next if ($$p{$k}->{'TOTAL'} == 0); # do not display entries without any traffic
			if ($startflag == 0) {
				$startflag = 1;
			} else {
				print "\n";
			};
			printf "%-55s  %9s\n", substr($k, 0, 55),
				$main::numberformat{$main::opts{'numberformat'}}->format_bytes($$p{$k}->{'TOTAL'});
                        print_users_indent( \%$p0 );
                };
        } else {
                foreach my $k (split " ", $list) {
                        if (! defined $$p{$k} ) {
				# print " !  no data !\n";
                                next;
                        };
                        $p0 = $$p{$k};
			if ($startflag == 0) {
				$startflag = 1;
			} else {
				print "\n";
			};
			printf "%-55s  %9s\n", substr($k, 0, 55),
				$main::numberformat{$main::opts{'numberformat'}}->format_bytes($$p{$k}->{'TOTAL'});
                        print_users_indent( \%$p0 );
                };
	};
	print '=' x $main::opts{'print-max-width'} . "\n";
};



# Print per user statistics
sub print_summary_acc_users() {
	my %sum;

	print "\n";
	print '='x104 . "\n";
	printf "%-40s: %8s %11s|%8s %11s|%8s %11s\n", "User", "NumSent", "BytesSent", "NumRec", "BytesRec", "NumSum", "BytesSum"; 
	print '-'x104 . "\n";
	for my $user (sort keys %messageUserStats) {
		$sum{'sent'}->{'count'} += $messageUserStats{$user}->{'sent'}->{'count'};
		$sum{'sent'}->{'size'}  += $messageUserStats{$user}->{'sent'}->{'size'};
		$sum{'rcvd'}->{'count'} += $messageUserStats{$user}->{'rcvd'}->{'count'};
		$sum{'rcvd'}->{'size'}  += $messageUserStats{$user}->{'rcvd'}->{'size'};

		printf "%-40s: %8d %11s|%8d %11s|%8d %11s\n",
			$user,
			$messageUserStats{$user}->{'sent'}->{'count'},
			::format_number($messageUserStats{$user}->{'sent'}->{'size'}),
			$messageUserStats{$user}->{'rcvd'}->{'count'},
			::format_number($messageUserStats{$user}->{'rcvd'}->{'size'}),
			$messageUserStats{$user}->{'sent'}->{'count'}
			 + $messageUserStats{$user}->{'rcvd'}->{'count'},
			::format_number($messageUserStats{$user}->{'sent'}->{'size'}
			 + $messageUserStats{$user}->{'rcvd'}->{'size'});
	};
	print '-'x104 . "\n";
	printf "%-40s: %8d %11s|%8d %11s|%8d %11s\n", "Total",
		$sum{'sent'}->{'count'},
		::format_number($sum{'sent'}->{'size'}),
		$sum{'rcvd'}->{'count'},
		::format_number($sum{'rcvd'}->{'size'}),
		$sum{'sent'}->{'count'} + $sum{'rcvd'}->{'count'},
		::format_number($sum{'sent'}->{'size'} + $sum{'rcvd'}->{'size'});
	print '='x104 . "\n";
};

# Print per domain statistics, customers will be separated from others
sub print_summary_acc_domains() {
	my %sum;
	$sum{'sent'}->{'count'}     = 0;
	$sum{'sent'}->{'size'}      = 0;
	$sum{'rcvd'}->{'count'} = 0;
	$sum{'rcvd'}->{'size'}  = 0;

	print "\n";
	print '=' x $main::opts{'print-max-width'} . "\n";
	printf "%-*s:%6s %10s|%6s %10s|%6s %10s\n", $main::opts{'print-max-width'} - 55, "Domain", "NumSent", "BytesSent", "NumRec", "BytesRec", "NumSum", "BytesSum"; 
	print '-' x $main::opts{'print-max-width'} . "\n";
	for my $domain (sort keys %messageDomainStats) {
		$sum{'sent'}->{'count'} += $messageDomainStats{$domain}->{'sent'}->{'count'};
		$sum{'sent'}->{'size'}  += $messageDomainStats{$domain}->{'sent'}->{'size'};
		$sum{'rcvd'}->{'count'} += $messageDomainStats{$domain}->{'rcvd'}->{'count'};
		$sum{'rcvd'}->{'size'}  += $messageDomainStats{$domain}->{'rcvd'}->{'size'};

		printf "%-20s: %6d %10s|%6d %10s|%6d %10s\n",
			substr ($domain, 0, 20),
			$messageDomainStats{$domain}->{'sent'}->{'count'},
			::format_number($messageDomainStats{$domain}->{'sent'}->{'size'}),
			$messageDomainStats{$domain}->{'rcvd'}->{'count'},
			::format_number($messageDomainStats{$domain}->{'rcvd'}->{'size'}),
			$messageDomainStats{$domain}->{'sent'}->{'count'} + $messageDomainStats{$domain}->{'rcvd'}->{'count'},
			::format_number($messageDomainStats{$domain}->{'sent'}->{'size'} + $messageDomainStats{$domain}->{'rcvd'}->{'size'});
	};
	print '-' x $main::opts{'print-max-width'} . "\n";
	printf "%-*s: %6d %10s|%6d %10s|%6d %10s\n", $main::opts{'print-max-width'} - 55, "Total",
		$sum{'sent'}->{'count'},
		::format_number($sum{'sent'}->{'size'}),
		$sum{'rcvd'}->{'count'},
		::format_number($sum{'rcvd'}->{'size'}),
		$sum{'sent'}->{'count'} + $sum{'rcvd'}->{'count'},
		::format_number($sum{'sent'}->{'size'} + $sum{'rcvd'}->{'size'});
	print '=' x $main::opts{'print-max-width'} . "\n";
};

sub print_summary_acc_domains_short() {
	# Print per domain statistics
	my %sum;
	my %sum_others;
	my $format;
	$sum{'sent'}->{'count'}     = 0;
	$sum{'sent'}->{'size'}      = 0;
	$sum{'rcvd'}->{'count'} = 0;
	$sum{'rcvd'}->{'size'}  = 0;
	$sum_others{'sent'}->{'count'}     = 0;
	$sum_others{'sent'}->{'size'}      = 0;
	$sum_others{'rcvd'}->{'count'} = 0;
	$sum_others{'rcvd'}->{'size'}  = 0;

	# Calculate sum
	for my $domain (sort keys %messageDomainStats) {
		if ( %domains_customer ) {
			if ( defined $domains_customer{$domain} ) {
				$sum{'sent'}->{'count'} += $messageDomainStats{$domain}->{'sent'}->{'count'};
				$sum{'sent'}->{'size'}  += $messageDomainStats{$domain}->{'sent'}->{'size'};
				$sum{'rcvd'}->{'count'} += $messageDomainStats{$domain}->{'rcvd'}->{'count'};
				$sum{'rcvd'}->{'size'}  += $messageDomainStats{$domain}->{'rcvd'}->{'size'};
			} else {
				$sum_others{'sent'}->{'count'} += $messageDomainStats{$domain}->{'sent'}->{'count'};
				$sum_others{'sent'}->{'size'}  += $messageDomainStats{$domain}->{'sent'}->{'size'};
				$sum_others{'rcvd'}->{'count'} += $messageDomainStats{$domain}->{'rcvd'}->{'count'};
				$sum_others{'rcvd'}->{'size'}  += $messageDomainStats{$domain}->{'rcvd'}->{'size'};
			};
		} else {
			$sum{'sent'}->{'count'} += $messageDomainStats{$domain}->{'sent'}->{'count'};
			$sum{'sent'}->{'size'}  += $messageDomainStats{$domain}->{'sent'}->{'size'};
			$sum{'rcvd'}->{'count'} += $messageDomainStats{$domain}->{'rcvd'}->{'count'};
			$sum{'rcvd'}->{'size'}  += $messageDomainStats{$domain}->{'rcvd'}->{'size'};
		};
	};



	# Format: treeview
	if (defined $main::format{"treeview"}) {
		$format = "treeview";
		print "\n\nWARNING(acc): Format '" . $format . "' is currently not supported!\n\n";
	};

	# Format: computer
	if (defined $main::format{"computer"}) {
		$format = "computer";

		if ( %domains_customer ) {
			printf "# <Domain (filtered by customers domain list)> = <BytesTotal>\n";
		} else {
			printf "# <Domain> = <BytesTotal>\n";
		};

		for my $domain (sort keys %messageDomainStats) {
			if ( %domains_customer ) {
				if ( defined $domains_customer{$domain} ) {
					print "_domain_" . $domain . "=" . ($messageDomainStats{$domain}->{'sent'}->{'size'} + $messageDomainStats{$domain}->{'rcvd'}->{'size'}) . "\n";
				};
			} else {
				print "_domain_" . $domain . "=" . ($messageDomainStats{$domain}->{'sent'}->{'size'} + $messageDomainStats{$domain}->{'rcvd'}->{'size'}) . "\n";
			};
		};
		if ( %domains_customer ) {
			print "_customers=" . ($sum{'sent'}->{'size'} + $sum{'rcvd'}->{'size'}) . "\n";
			print "_others=" . ($sum_others{'sent'}->{'size'} + $sum_others{'rcvd'}->{'size'}) . "\n";
			print "_total_sent=" . ($sum{'sent'}->{'size'} + $sum_others{'sent'}->{'size'}) . "\n";
			print "_total_rcvd=" . ($sum{'rcvd'}->{'size'} + $sum_others{'rcvd'}->{'size'}) . "\n";
			print "_total=" . ($sum{'sent'}->{'size'} + $sum{'rcvd'}->{'size'} + $sum_others{'sent'}->{'size'} + $sum_others{'rcvd'}->{'size'}) . "\n";
		} else {
			print "_total_sent=" . ($sum{'sent'}->{'size'}) . "\n";
			print "_total_rcvd=" . ($sum{'rcvd'}->{'size'}) . "\n";
			print "_total=" . ($sum{'sent'}->{'size'} + $sum{'rcvd'}->{'size'}) . "\n";
		};
	};

	# Format: indented
	if (defined $main::format{"indented"}) {
		$format = "indented";
		print "\n\nWARNING(acc): Format '" . $format . "' is currently not supported!\n\n";
	};

	# Format: txttable
	if (defined $main::format{"txttable"}) {
		$format = "txttable";

		if ( %domains_customer ) {
			print '=' x $main::opts{'print-max-width'} . "\n";

			printf "%-*s: %12s\n", $main::opts{'print-max-width'} - 14, "Domain (filtered by customers domain list)", "BytesTotal";
			print '-' x $main::opts{'print-max-width'} . "\n";

			for my $domain (sort keys %messageDomainStats) {
				if ( defined $domains_customer{$domain} ) {
					printf "%-*s: %12s\n",
						$main::opts{'print-max-width'} - 14,
						$domain,
						 ::format_number($messageDomainStats{$domain}->{'sent'}->{'size'}
						 + $messageDomainStats{$domain}->{'rcvd'}->{'size'});
				};
			};

			print '-' x $main::opts{'print-max-width'} . "\n";

			printf "%-*s: %12s\n", $main::opts{'print-max-width'} - 14, "Customers",
				::format_number($sum{'sent'}->{'size'} + $sum{'rcvd'}->{'size'});
			printf "%-*s: %12s\n", $main::opts{'print-max-width'} - 14, "Others",
				::format_number($sum_others{'sent'}->{'size'} + $sum_others{'rcvd'}->{'size'});
			print '-' x $main::opts{'print-max-width'} . "\n";
			printf "%-*s: %12s\n", $main::opts{'print-max-width'} - 14, "Total",
				::format_number($sum{'sent'}->{'size'} + $sum{'rcvd'}->{'size'} + $sum_others{'sent'}->{'size'} + $sum_others{'rcvd'}->{'size'} );

			print '=' x $main::opts{'print-max-width'} . "\n";
		} else {
			# Create hash for generic print_stat function
			my %stat;
			for my $domain (sort keys %messageDomainStats) {
				$stat{$domain} = $messageDomainStats{$domain}->{'sent'}->{'size'} + $messageDomainStats{$domain}->{'rcvd'}->{'size'};
			};

			::print_stat ("Domain", \%stat, "format");
		};
	};
};


## End of module
return 1;
