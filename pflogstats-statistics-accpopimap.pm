#!/usr/bin/perl -w

###
# Project:     pflogstats
# Module:      pflogstats-statistics-accpopimap.pm
# Type:        statistics
# Description: Statistics module for accounting
# Copyright:   Dr. Peter Bieringer <pbieringer at aerasec dot de>
#               AERAsec GmbH <http://www.aerasec.de/> 
# License:     GNU GPL v2
# CVS:         $Id: pflogstats-statistics-accpopimap.pm,v 1.20 2006/09/01 09:03:14 peter Exp $
###

## ChangeLog
#	0.01
#	 - initial split-off
#	0.02
#	 - support new format code style
#	0.03
#	 - adjust loglineparser arguments, fix some not well transferred code
#	0.04
#	 - tag some match patterns with "o"
#	0.05
#	 - adjustments for external network check module
#	0.06
#	 - account TCP overhead also
#	0.07
#	 - convert IPv4 compatible IPv6 addresses into IPv4 ones
#	0.08
#	 - replace all hash references with proper code
#       0.09
#        - make Perl 5.0 compatible
#	0.10
#	 - add support of option print-max-width
#	0.11
#	 - reorganize hook names
#	0.12
#	 - fix check for exisiting data
#	0.13
#	 - add fallback/compatibility code for counting header and body values if present and sent=0 or missing
#	0.14
#	 - display warning about bug in accounting code only, if sent=0 && !(header==0 && body==0)
#	0.15
#	 - [adj] fix format to support more chars in value string
#	0.16
#	 - [fix] use now also format_number function to support --fixednumberformat
##

use strict;


## Local constants
my $module_type = "statistics";
my $module_name = $module_type . "-accpopimap";
my $module_version = "0.16";

package pflogstats::statistics::accpopimap;

## Export module info
$main::moduleinfo{$module_name}->{'version'} = $module_version;
$main::moduleinfo{$module_name}->{'type'} = $module_type;
$main::moduleinfo{$module_name}->{'name'} = $module_name;

# Global prototyping


## Local prototyping


## Register options
$main::options{'acc_notcpoverhead'} = \$main::opts{'acc_notcpoverhead'};

## Register calling hooks
$main::hooks{'loglineparser'}->{$module_name} = \&loglineparser;
$main::hooks{'print_result'}->{$module_name} = \&print_result;
$main::hooks{'checkoptions'}->{$module_name} = \&checkoptions;
$main::hooks{'help'}->{$module_name} = \&help;

# Define type
$main::types{'accpopimap'} = 0;

## Global variables

## Local variables
my %accounting_pop_imap;
my ($user, $ip, $rcvd, $sent, $headers, $body);
my $tcpoverhead;

## Global callable functions

# Help
sub help() {
	my $helpstring = "
    Type: accpopimap
    [--acc_notcpoverhead]        Don't account estimated TCP overhead
    [--debug <debug>]            Debug value
                                  | 0x0001 : display imap/pop lines
                                  | 0x0002 : display imap/pop accounting data lines
                                  | 0x0010 : display accounting information
";
	return $helpstring;
};


# Check options
sub checkoptions() {
};


# Parse logline
sub loglineparser(\$\$) {
	return if ( $main::types{'accpopimap'} == 0);

	if (! defined $_[0]) { die "Missing time pointer (arg1)"; };
	if (! defined $_[1]) { die "Missing logline pointer (arg2)"; };

	# Looking for pop3/imapd lines, nothing else
	return unless (${$_[1]} =~ /^.*\s+(pop3d|pop3d-ssl|imapd|imapd-ssl):\s+.*$/o);


	# Looking for accounting lines only
	printf STDERR "DEBUG: ACC_POP_IMAP: %s\n", ${$_[1]} if ($main::opts{'debug'} & 0x0001 ) ;
	return unless (/^.*\s+(rcvd|sent)=\d+.*$/o) ;

	printf STDERR "DEBUG: ACC_POP_IMAP: %s\n", ${$_[1]} if ($main::opts{'debug'} & 0x0002 ) ;

	undef $user; undef $ip; undef $rcvd; undef $sent; undef $headers; undef $body;

	# Get user
	if (${$_[1]} =~ /\s+user=([^\s,]+).*/o ) {
		$user = lc($1);
	};
	if (${$_[1]} =~ /\s+ip=\[([^\s,]+)\].*$/o ) {
		$ip = lc($1);
		# Convert IPv4 compatible IPv6 addresses into IPv4 ones
		$ip =~ s/^::ffff:([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$/$1/o;
	};
	if (${$_[1]} =~ /\s+rcvd=([^\s,]+).*$/o ) {
		$rcvd = $1;
	};
	if (${$_[1]} =~ /\s+sent=([^\s,]+).*$/o ) {
		$sent = $1;
	};
	if (${$_[1]} =~ /\s+headers=([^\s,]+).*$/o ) {
		$headers = $1;
	};
	if (${$_[1]} =~ /\s+body=([^\s,]+).*$/o ) {
		$body = $1;
	};

	if ( ! (defined $user && defined $ip) ) {
		# not a proper accounting line
		return;
	};

	if ( defined $rcvd && defined $sent ) {
		if (defined $headers && defined $body) {
			if ($sent == 0 && ! ($headers == 0 && $body == 0 ) ) {
				# Fallback for buggy patch
				printf STDERR "WARN : ACC_POP_IMAP: sent=" . $sent . " but headers=" . $headers . " / body=" . $body . " - bug in accounting code?\n";
				$sent += $headers;
				$sent += $body;
			};
		};
	} elsif (defined $headers && defined $body) {
		# Accounting courier-imap <= 4.0.6 without accouting patch
		$sent += $headers;
		$sent += $body;
	};

	# Append domain to user
	if (! ( $user =~ /@/o ) ) {
		$user .= "@" . $main::opts{'mydomainname'};
	};

	printf STDERR "DEBUG: ACC_POP_IMAP: user=%s ip=[%s] rcvd=%s sent=%s\n", $user, $ip, $rcvd, $sent if ($main::opts{'debug'} & 0x0010 ) ;
 
	# Hook "testipaddress"
	for my $p_hook (keys %{$main::hooks{'testipaddress'}}) {
		if ( &{$main::hooks{'testipaddress'}->{$p_hook}} ($ip) != 0 ) {
			# excluded
		printf STDERR "DEBUG: ACC_POP_IMAP: excluded from accounting\n" if ($main::opts{'debug'} & 0x0010 ) ;
			return;
		};
	};

	if ( ! defined $main::opts{'acc_notcpoverhead'} ) {
		# 3x40 SYN, 4x40 FIN = 7x40 = 280
		# Assume MTU 1500 and 10% ACKs by receiver, uncalculable: TCP options

		$tcpoverhead = 280 + ( int(($sent + 1459) / 1460) + int(($rcvd + 1459) / 1460) ) * 44;
	} else {
		$tcpoverhead = 0;
	};

	$accounting_pop_imap{'user'}->{$user} += $rcvd + $sent + $tcpoverhead;
	$accounting_pop_imap{'domain'}->{::extract_domain($user)} += $rcvd + $sent + $tcpoverhead;

	return;
};

# print result
sub print_result() {
	return if ( $main::types{'accpopimap'} == 0);

	my $sum;
	my %accounting;
	my $p_hash;
	my $format;

	print "\n# Accounting data also contains following overheads:\n";
	print "#  + TCP overhead (partially estimated)\n" if (! defined $main::opts{'acc_notcpoverhead'});

	# Format: treeview
	if (defined $main::format{"treeview"}) {
		$format = "treeview";
		print "\n\nWARNING(accpopimap): Format '" . $format . "' is currently not supported!\n\n";
	};

	# Format: computer
	if (defined $main::format{"computer"}) {
		$format = "computer";
		print "\n\nWARNING(accpopimap): Format '" . $format . "' is currently not supported!\n\n";
	};

	# Format: indented
	if (defined $main::format{"indented"}) {
		$format = "indented";
		print "\n\nWARNING(accpopimap): Format '" . $format . "' is currently not supported!\n\n";
	};

	# Format: txttable
	if (defined $main::format{"txttable"}) {
		$format = "txttable";

		::print_headline("Accounting statistics for POP & IMAP", $format);
		::print_timerange($format);

		if (defined $main::opts{'show_users'}) {
			$p_hash = $accounting_pop_imap{'user'};
			%accounting = %$p_hash;

			if (%accounting) {
				$sum = 0;

				print '=' x $main::opts{'print-max-width'} . "\n";
				printf "%-*s: %6s\n", $main::opts{'print-max-width'} - 25, "User", "BytesTraffic"; 
				print '-' x $main::opts{'print-max-width'} . "\n";
				for my $user (sort keys %accounting) {
					if ( ! defined $accounting{$user} ) { $accounting{$user} = 0; };
					
					$sum += $accounting{$user};

					printf "%-*s: %9d  %12s\n",
						$main::opts{'print-max-width'} - 25,
						substr ($user, 0, $main::opts{'print-max-width'} - 25),
						$accounting{$user},
						::format_number($accounting{$user});
				};
				print '-' x $main::opts{'print-max-width'} . "\n";
				printf "%-*s: %9d  %12s\n", $main::opts{'print-max-width'} - 25, "Total",
					$sum,
					::format_number($sum);
				print '=' x $main::opts{'print-max-width'} . "\n";

			} else {
				print "!! NO DATA !!\n";
			};

			print "\n";
		};

		$p_hash = $accounting_pop_imap{'domain'};

		if (defined $p_hash) {
			%accounting = %$p_hash;

			$sum = 0;
			print '=' x $main::opts{'print-max-width'} . "\n";
			printf "%-*s: %6s\n", $main::opts{'print-max-width'} - 25, "Domain", "BytesTraffic"; 
			print '-' x $main::opts{'print-max-width'} . "\n";
			for my $domain (sort keys %accounting) {
				if ( ! defined $accounting{$domain} ) { $accounting{$domain} = 0; };
				
				$sum += $accounting{$domain};

				printf "%-*s: %9d  %12s\n",
					$main::opts{'print-max-width'} - 25,
					substr ($domain, 0, $main::opts{'print-max-width'} - 25),
					$accounting{$domain},
					::format_number($accounting{$domain});
			};
			print '-' x $main::opts{'print-max-width'} . "\n";
			printf "%-*s: %9d  %12s\n", $main::opts{'print-max-width'} - 25, "Total",
				$sum,
				::format_number($sum);
			print '=' x $main::opts{'print-max-width'} . "\n";

		} else {
			print "!! NO DATA !!\n";
		};

		print "\n";
	};
};



## Local functions




## End of module
return 1;
