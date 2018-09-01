#!/usr/bin/perl -w

###
# Project:     pflogstats
# Module:      pflogstats-common-support.pm
# Description: Support functions
# Copyright:   Dr. Peter Bieringer <pbieringer at aerasec dot de>
#               AERAsec GmbH <http://www.aerasec.de/> 
# License:     GNU GPL v2
# CVS:         $Id: pflogstats-common-support.pm,v 1.48 2006/08/11 13:54:47 peter Exp $
###

###
# ChangeLog:
#	0.01
#	 - initial creation
#	0.02
#	 - add option "numberformat"
#	0.03
#	 - minor code movement
#	0.04
#	 - add statistics
#	0.05
#	 - move statistics to separate module
#	0.06
#	 - move networking code to separate module
#	0.07
#	 - check debug value string for numeric value
#	0.08
#	 - hash reference cosmetics
#	0.09
#	 - replace all hash references with proper code
#       0.10
#        - make Perl 5.0 compatible
#	0.11
#	 - add new switch "verbose"
#	0.12
#	 - add new function print_treeview2 with parameter maxdepth
#	 - print sum numbers on tree entries
#	0.13
#	 - add option "--skip_subtree_pattern"
#	0.14
#	 - set debug value to 0 on early begin to avoid problems on checkoption calls on other modules
#	0.15
#	 - add support for optional subkey list in treeview
#	 - accept format "none"
#	0.16
#	 - add print-max_width option
#	 - migrate show_domain_list and show_user_list
#	0.17
#	 - add a missing print-max-width match
#	0.18
#	 - add caching for domain extraction
#	 - add function 'modify_address' with cache
#	0.19
#	 - add new option "fixednumberformat"
#	 - add new number format function
#	 - add new option "printstatistics"
#	0.20
#	 - take care of .(co|ac).tld on extract 2nd level domains
#	0.21
#	 - take care of .(net).(ar) on extract 2nd level domains
#	0.22
#	 - move option check to hook "early_checkoptions" to fix converting debug option before used by other modules
#	0.23
#	 - extend print_stat for use with accounting module
#	0.24
#	 - [enh] assume unixtime=0 if timmin/max is not defined (happen on empty input)
#	 - [enh] improve handling of format_bytes to handle large numbers proper
#	0.25
#	 - [ajd] require Number::Format >= 1.51, older versions have problems like
#	          'Argument "precision" isn't numeric in exponentiation (**) at'
#	 - [enh] add support for option "fixednumberprecision" (default: 3)
#	 - [enh] add support for 2 additional number formats: {de_DE,en_US}-nosep (suppressing thousand separator)
###

## Todo:
# - correct module function export
##

use strict;

use Sys::Hostname;
use Number::Format (1.51);
use Time::Local;
use POSIX qw(strftime);
use locale;

#package pflogstats::common::support;
#package pflogstats_common_support;


## Local constants
my $module_type = "common";
my $module_name = $module_type . "-support";
my $module_version = "0.25";

## Export module info
$main::moduleinfo{$module_name}->{'version'} = $module_version;
$main::moduleinfo{$module_name}->{'type'} = $module_type;
$main::moduleinfo{$module_name}->{'name'} = $module_name;

## Global prototyping


## Global variables


## Local prototyping


## Local variables
my @opt_skip_subtree_pattern;

my %cache_extract_domain;
my %cache_extract_2ndleveldomain;
my %cache_modify_address;


# Number format
my $numberformat_de_DE = new Number::Format(-thousands_sep   => '.', -decimal_point   => ',', -int_curr_symbol => 'EUR', -KILO_SUFFIX => ' KiB', -MEGA_SUFFIX => ' MiB', -GIGA_SUFFIX => ' GiB');
my $numberformat_en_US = new Number::Format(-thousands_sep   => ',', -decimal_point   => '.', -int_curr_symbol => '$', , -KILO_SUFFIX => ' KiB', -MEGA_SUFFIX => ' MiB', -GIGA_SUFFIX => ' GiB');
my $numberformat_de_DE_nosep = new Number::Format(-thousands_sep   => '', -decimal_point   => ',', -int_curr_symbol => 'EUR', -KILO_SUFFIX => ' KiB', -MEGA_SUFFIX => ' MiB', -GIGA_SUFFIX => ' GiB');
my $numberformat_en_US_nosep = new Number::Format(-thousands_sep   => '', -decimal_point   => '.', -int_curr_symbol => '$', , -KILO_SUFFIX => ' KiB', -MEGA_SUFFIX => ' MiB', -GIGA_SUFFIX => ' GiB');

$main::numberformat{'de_DE'} = $numberformat_de_DE;
$main::numberformat{'en_US'} = $numberformat_en_US;
$main::numberformat{'en_US-nosep'} = $numberformat_en_US_nosep;
$main::numberformat{'en_US-nosep'} = $numberformat_en_US_nosep;

## Register options
$main::options{'mydomainname=s'}         = \$main::opts{'mydomainname'};
$main::options{"numberformat=s"}         = \$main::opts{'numberformat'};
$main::options{"debug|d=s"}              = \$main::opts{'debug'};
$main::options{'format=s'}               = \@main::opt_format;
$main::options{'print-max-width=i'}      = \$main::opts{'print-max-width'};
$main::options{'verbose'}                = \$main::opts{'verbose'};
$main::options{'show_user_list=s'}       = \$main::opts{'show_user_list'};
$main::options{'show_domain_list=s'}     = \$main::opts{'show_domain_list'},
$main::options{'skip_subtree_pattern=s'} = \@opt_skip_subtree_pattern;
$main::options{'fixednumberformat=s'}    = \$main::opts{'fixednumberformat'};
$main::options{'fixednumberprecision=i'} = \$main::opts{'fixednumberprecision'};
$main::options{'printstatistics'}        = \$main::opts{'printstatistics'};


## Register calling hooks
$main::hooks{'beforemainloopstarts'}->{$module_name} = \&beforemainloopstarts1;
$main::hooks{'help'}->{$module_name} = \&help1;
$main::hooks{'early_checkoptions'}->{$module_name} = \&checkoptions;
$main::hooks{'early_begin'}->{$module_name} = \&setearlybegin;


## Global callable functions
sub help1() {
	my $temp;
	my $helpstring = "
    General:
    [--mydomainname <domain>]    My domain (default: domain of hostname)
";

	# Number format
	$temp = "    [--numberformat <format>]  Number format\n                               Default: 'de_DE'\n                               Available support:";
	foreach my $format (keys %main::numberformat ) {
	        $temp .= " '" . $format . "'";
	};
	$helpstring .= $temp . "\n";

	# Fixed Number format
	$temp = "    [--fixednumberformat <fixedformat>]  Fixed number format\n                               Default: none'\n                               Available support: {K,M,G}[i]B";
	$helpstring .= $temp . "\n";

	# Fixed Number format precision
	$temp = "    [--fixednumberprecision <value>]  Fixed number format precision\n                               Default: 3'\n                               Available support: 0-9";
	$helpstring .= $temp . "\n";


	# Debug value
	$temp = "    [--debug|-d <debugvalue>]  Display some debug information";
	$helpstring .= $temp . "\n";

	# Verbose option
	$temp = "    [--verbose]  Be more verbose";
	$helpstring .= $temp . "\n";

	# statistics
	$temp = "    [--printstatistics]  Print some statistical data";
	$helpstring .= $temp . "\n";

	# Format options
	$temp = "    [--format <formatvalue>]  Format option for displaying information (can be used more than once)\n             Default: 'txttable'\n                         Available formats: 'txttable' 'computer' 'treeview' 'indented' 'none'\n               (not all formats are supported on each type)";
	$helpstring .= $temp . "\n";

	# Skip subtree entries
	$temp = "    [--skip_subtree_pattern <pattern>]  Regexp pattern on which subtree displaying is skipped in format 'treeview'\
           Can be used more than once\n";
	$helpstring .= $temp . "\n";

	# max width printing
	$temp = "    [--print-max-width <value>]  Maximum width of output (currently not always supported)\
        (default: 75)\n";
	$helpstring .= $temp . "\n";


	# User/domain lists
	$temp = "    [--show_domain_list <domain-list>] Show statistics only for domain in list\
     <domain-list> is a comma separated list of e-mail domains\ 
    [--show_user_list <user-list>]     Show statistics only for user in list\
     <user-list> is a comma separated list of e-mail addresses\
      currently supported by format: treeview";
	$helpstring .= $temp . "\n";

	return $helpstring;
};

# Set some values on early begin
sub setearlybegin() {
	$main::opts{'debug'} = 0;
};

# Check options
sub checkoptions() {
	##  Check debug value
	if (! defined $main::opts{'debug'}) {
		$main::opts{'debug'} = 0;
	};

	# hex to dec
	if ( $main::opts{'debug'} =~ /^0x[0-9A-Fa-f]+$/i ) {
		$main::opts{'debug'} = hex ($main::opts{'debug'});
	};

	# check dec
	if ( ! ( $main::opts{'debug'} =~ /^[0-9]+$/i ) ) {
		print STDERR "ERROR: Debug value not decimal: " . $main::opts{'debug'} . "\n";
		exit 1;
	};

	if ( $main::opts{'debug'} != 0 ) {
		printf STDERR "DEBUG: Debug mode: %x\n", $main::opts{'debug'};
	};


	## Set domainname
	if (! defined $main::opts{'mydomainname'} ) {
		# Set default
		my $myhostname = hostname;
		if ( $myhostname =~ /^[^\.]+\.(\S+)/ ) {
			$main::opts{'mydomainname'} = $1;
		};
	};
	print STDERR "INFO : Domainname: " . $main::opts{'mydomainname'} .  "\n" if ($main::opts{'debug'} & 0x0040);


	## Set hostname
	if (! defined $main::opts{'myhostname'} ) {
		# Set default
		$main::opts{'myhostname'} = hostname;
	};
	print STDERR "INFO : Hostname: " . $main::opts{'myhostname'} .  "\n" if ($main::opts{'debug'} & 0x0040);


	##  Check number format
	if (! defined $main::opts{'numberformat'}) {
		# Default
		$main::opts{'numberformat'} = "de_DE";
	};
	if (! defined $main::numberformat{$main::opts{'numberformat'}}) {
		print "ERROR: Unsupported number format: " . $main::opts{'numberformat'} . "\n";
		exit 1;
	};

	##  Check fixed format
	if (defined $main::opts{'fixednumberformat'}) {
                my $unit = substr($main::opts{'fixednumberformat'},0,1);
                my $base_string = substr($main::opts{'fixednumberformat'},1);

		if ($base_string ne "B" && $base_string ne "iB") {
			print "ERROR: Unsupported fixed format: " . $main::opts{'fixednumberformat'} . "\n";
			exit 1;
		};
	};

	##  Check fixed format precision
	if (defined $main::opts{'fixednumberprecision'}) {
                my $unit = substr($main::opts{'fixednumberformat'},0,1);
                my $base_string = substr($main::opts{'fixednumberformat'},1);

		if ($main::opts{'fixednumberprecision'} !~ /^[0-9]$/) {
			print "ERROR: Unsupported fixed format: " . $main::opts{'fixednumberprecision'} . "\n";
			exit 1;
		};
	} else {
		# Default
		$main::opts{'fixednumberprecision'} = 3;
	};

	## Check format options
	if (scalar (@main::opt_format) == 0) {
		# Default
		push @main::opt_format, 'txttable';
	};
	for my $key (@main::opt_format) {
		# check key
		if ($key ne "computer" && $key ne "treeview" && $key ne "indented" && $key ne "txttable" && $key ne "none") {
			print STDERR "ERROR: Unsupported format: " . $key . "\n";
			exit 1;
		} else {
			$main::format{$key} = 1;
		};
	};


	# Adjust skip_subtree_pattern
	if (scalar(@opt_skip_subtree_pattern) > 0) {
		# Print for debugging
		foreach my $pattern (@opt_skip_subtree_pattern) {
			print STDERR "INFO : skip subtree pattern: " . $pattern . "\n" if ($main::opts{'debug'} & 0x0040);
		};
	};

	
	# max_width
	if (defined $main::opts{'print-max-width'}) {
		# 0 is currently not supported
		#if ($main::opts{'print-max-width'} == 0) {
		#	# ok
		#} elsif ($main::opts{'print-max-width'} < 60) {
		#	print STDERR "ERROR: value of option 'print-max-width' is too low, use '60' or up\n";
		#	exit 1;
		#};
		if ($main::opts{'print-max-width'} < 60) {
			print STDERR "ERROR: value of option 'print-max-width' is too low, use '60' or up\n";
			exit 1;
		};
	} else {
	# Default
		$main::opts{'print-max-width'} = 75;
	};
};

sub beforemainloopstarts1() {
};


# Unixtime2string
sub unixtime2string($) {
	return POSIX::strftime "%a %b %e %H:%M:%S %Y", localtime($_[0]);
};

# Print time range
sub print_timerange_normal() {
	my $time_min = $main::timemin;
	my $time_max = $main::timemax;
	if (! defined $time_min) {
		$time_min = 0;
	};
	if (! defined $time_max) {
		$time_max = 0;
	};
	my $timeminstr = POSIX::strftime "%a %b %e %H:%M:%S %Y", localtime($time_min);
	my $timemaxstr = POSIX::strftime "%a %b %e %H:%M:%S %Y", localtime($time_max);
	printf " Begin: %s (localtime)\n", $timeminstr;
	printf " End  : %s (localtime)\n", $timemaxstr;
};


# Print statistics
sub print_line($$$) {
	my $key = shift;
	my $value = shift;
	my $type = shift;

	if ($type eq "format") {
		printf "%-*s : %10s\n", $main::opts{'print-max-width'} - 13, $key, ::format_number($value);
	} else {
		printf "%-*s : %10s\n", $main::opts{'print-max-width'} - 13, $key, $value;
	};
};

sub print_stat($$;$) {
	my $title = shift;
	my $p_stat = shift;
	my $type = shift;
	my %stat = %$p_stat;
	my $sum = 0;

	if (defined $type) {
		if ($type eq "format") {
			#ok
		} else {
			die "ERROR(bug-in-code): unsupported type";
		};
	} else {
		$type = "";
	};

	print '=' x $main::opts{'print-max-width'} . "\n";
	print "$title\n";
	print_timerange_normal();
	print '-' x $main::opts{'print-max-width'} . "\n";

	if ($main::opts{'sort_type'} eq "alpha") {
		for my $key (sort keys %stat) {
			print_line($key, $stat{$key}, $type);
			$sum += $stat{$key};
		};
	} elsif ($main::opts{'sort_type'} eq "maxmin") {
		for my $key (sort { $stat{$b} <=> $stat{$a} } keys %stat) {
			print_line($key, $stat{$key}, $type);
			$sum += $stat{$key};
		};
	} elsif ($main::opts{'sort_type'} eq "minmax") {
		for my $key (sort { $stat{$a} <=> $stat{$b} } keys %stat) {
			print_line($key, $stat{$key}, $type);
			$sum += $stat{$key};
		};
	} else {
		die "ERROR(missing-code): Unsupported sort type";
	};

	print '-' x $main::opts{'print-max-width'} . "\n";
	print_line("Total", $sum, $type);
	print '=' x $main::opts{'print-max-width'} . "\n\n";
};


# Print time range
sub print_timerange($) {
	my $format = shift || die "Missing format (arg1)";

	if (! defined $main::timemin || ! defined $main::timemax) {
		warn "No timerange data!\n";
		return;
	};

	if ( $format eq "computer" ) {
		printf "__timemin=%d\n", $main::timemin;
		printf "__timemax=%d\n", $main::timemax;
	} else {
		print '+' x $main::opts{'print-max-width'} . "\n";
		if (defined $main::timemin && defined $main::timemax) {
			my $timeminstr = POSIX::strftime "%a %b %e %H:%M:%S %Y", localtime($main::timemin); 
			my $timemaxstr = POSIX::strftime "%a %b %e %H:%M:%S %Y", localtime($main::timemax); 
			printf "Timerange:  %s  -  %s\n", $timeminstr, $timemaxstr;
		} else {
			printf "Timerange:  NO DATA!\n";
		};
		print '+' x $main::opts{'print-max-width'} . "\n";
		printf "\n";
	};
};


# Print headline
sub print_headline($$) {
	my $text = shift || die "Missing text (arg1)";
	my $format = shift || die "Missing format (arg2)";

	if ( $format eq "computer" ) {
		printf "\n";
		printf "__headline=\"%s\"\n", $text;
	} else {
		printf "\n\n";
		print '#' x $main::opts{'print-max-width'} . "\n";
		printf "%s\n", $text;
		print '#' x $main::opts{'print-max-width'} . "\n";
		printf "\n";
	};
};


## Print a subtreeview
# $1: pointer to subtreehash
# $2 (optional): max depth
# $3 (optional): list of subkeys
sub print_subtreeview($;$$) {
	my $p0 = $_[0] || die "Missing hash pointer";

	my $maxdepth = $_[1];
	if (! defined $maxdepth) { $maxdepth = -1; };
	#print "Maxdepth: $maxdepth\n";

	# if (! defined $p) { die "hash pointer is undefined"; };
	# if (! defined %$p) { die "hash of pointer is undefined"; };

	my $sublist = $_[2]; # optional list of subkeys
	if (! defined $sublist) { $sublist = "" };

	# count only
	if ($maxdepth == -2) {
		# Count level 2
		my $counter2 = 0;
		if ($sublist eq "" ) {
			foreach my $k0 ( sort keys %$p0 ) { 
				my $p1 = $$p0{$k0};
				foreach my $k1 ( sort keys %$p1 ) {
					my $p2 = $$p1{$k1};
					foreach my $k2 ( sort keys %$p2 ) {
						$counter2 += $$p2{$k2};
					};
				};
			};
		} else {
			foreach my $k0 (split " ", $sublist) {
				if (defined $$p0{$k0} ) {
					my $p1 = $$p0{$k0};
					foreach my $k1 ( sort keys %$p1 ) {
						my $p2 = $$p1{$k1};
						foreach my $k2 ( sort keys %$p2 ) {
							$counter2 += $$p2{$k2};
						};
					};
				};
			};
		};
		return ($counter2)
	};

	my $c0;
	my %subkeyfilter;
	my $string;
	if ($sublist eq "" ) {
		$c0 = scalar( keys %$p0 );
	} else {
		# split array into hash
		foreach my $k0 (split " ", $sublist) {
			if (defined $$p0{$k0} ) {
				$subkeyfilter{$k0} = 1;
			};
		};
		$c0 = scalar( keys %subkeyfilter );
	};

	if ($c0 == 0) {
		return 0;
	};

	foreach my $k0 ( sort keys %$p0 ) { 
		if ($sublist ne "" ) {
			# check filter
			if (! defined  $subkeyfilter{$k0}) {
				next;
			};
		};

		$c0--;
		if ( $c0 > 0 ) {
			print "+- ";
		} else {
			print "`- ";
		};
		my $p1 = $$p0{$k0};
		my $c1 = scalar( keys %$p1 );
		#print $k0 . " [" . $c1 . "]\n";

		# Count level 3
		my $counter3 = 0;
		foreach my $k1 ( sort keys %$p1 ) {
			my $p2 = $$p1{$k1};
			foreach my $k2 ( sort keys %$p2 ) {
				if (! defined  $$p2{$k2} ) {
					warn "key has no value: $k2\n";
				} else {
					$counter3 += $$p2{$k2};
				};
			};
		};
		print $k0 . " [" . $counter3 . "]\n";

		foreach my $k1 ( sort keys %$p1 ) {
			$c1--;
			if ( $c0 > 0 ) {
				print "|";
			} else {
				print " ";
			};
			my $p2 = $$p1{$k1};
			if ( $c1 > 0 ) {
				print "  +- ";
			} else {
				print "  `- ";
			};
			my $c2 = scalar( keys %$p2 );
			#print $k1 . " [" . $c2 . "]\n";

			# Count level 4
			my $counter4 = 0;
			foreach my $k2 ( sort keys %$p2 ) {
				$counter4 += $$p2{$k2};
			};
			$string = $k1;

			if (defined $main::opts{'print-max-width'} && $main::opts{'print-max-width'} > 0) {
				# max_width - 2 
				my $delta = (length($k1) + length($counter4) + 3 + 6) - $main::opts{'print-max-width'} + 2;
				if ( $delta > 0 ) {
					if (length($string) > ($delta + 3)) {
						$string = substr($string, 0, length($string) - $delta - 3) . "...";
					};
				} else {
					# Append some spaces for right alignment
					$string .= ' ' x (- $delta);
				};
			}
			print $string . " [" . $counter4 . "]\n";

			my $skip = 0;
			if (scalar(@opt_skip_subtree_pattern) > 0) {
				# Check for skip_subtree_pattern
				foreach my $pattern (@opt_skip_subtree_pattern) {
					if ($k1 =~ /$pattern/) {
						$skip = 1;
						last;
					};
				};
			};

			if ((($maxdepth >= 4) || ($maxdepth == -1)) && ($skip == 0)) {
				foreach my $k2 ( sort keys %$p2 ) {
					$c2--;
					if ( $c0 > 0 ) {
						print "|";
					} else {
						print " ";
					};
					if ( $c1 > 0 ) {
						print "  |";
					} else {
						print "   ";
					};
					if ( $c2 > 0 ) {
						print "  +- ";
					} else {
						print "  `- ";
					};
					$string = $k2;

					if (defined $main::opts{'print-max-width'} && $main::opts{'print-max-width'} > 0) {					
						my $delta = (length($k2) + length($$p2{$k2}) + 3 + 9) - $main::opts{'print-max-width'};
						if ( $delta > 0 ) {
							# longer than max width, have to shorten now
							# try to be intelligent
							my ($t1, $t2, $t3, $t4);
							my ($l1, $l2, $l3, $l4);
							if (($t1, $t2, $t3, $t4) = $string =~ /^([^@]*)@(.*)\s\((.+)\[(.+)\]\)$/o ) {
								# yrddfucambd@yahoo.com (66-123-123-123.lb-cres.charterpipeline.net[123.123.123.123])
								# svq@[filename /home/admin/domains.txt] (d66-123-123-123.bchsia.telus.net[66.123.123.123])   <-  more funny one
								$l1 = length($t1);
								$l2 = length($t2);
								$l3 = length($t3);
								$l4 = length($t4);

								# Short first t3
								if (($delta > 0) && ($l3 > 6)) {
									if ($l3 - 6 > $delta) {
										$t3 = substr($t3, 0, $l3 - 3 - $delta) . "...";
										$delta = 0;
									} else {
										$t3 = substr($t3, 0, 3) . "...";
										$delta -= $l3 - 6;
									};
								};

								# Short now t2 if required
								if (($delta > 0) && ($l2 > 6)) {
									if ($l2 - 6 > $delta) {
										$t2 = substr($t2, 0, $l2 - 3 - $delta) . "...";
										$delta = 0;
									} else {
										$t2 = substr($t2, 0, 3) . "...";
										$delta -= $l2 - 6;
									}
								};

								# Short now t1 if required
								if (($delta > 0) && ($l1 > 6)) {
									if ($l1 - 6 > $delta) {
										$t1 = substr($t1, 0, $l1 - 3 - $delta) . "...";
										$delta = 0;
									} else {
										$t1 = substr($t1, 0, 3) . "...";
										$delta -= $l1 - 6;
									}
								};
								# Short now t4 if required
								if (($delta > 0) && ($l4 > 6)) {
									if ($l4 - 6 > $delta) {
										$t4 = substr($t4, 0, $l1 - $delta - 3) . "...";
										$delta = 0;
									} else {
										$t4= substr($t4, 0, 3) . "...";
										$delta -= $l4 - 6;
									};
								};

								if ($delta > 0) {
									#warn "Problem with print-max-width: " . $string . "\n";
								};

								$string = $t1 . "@" . $t2 . " (" . $t3 . "[" . $t4 . "])";

							 } elsif (($t1, $t3, $t4) = $string =~ /^([^@]+)\s\((.+)\[(.+)\]\)$/o ) {
								# from=<> (server.domain.example[1.2.3.4])

								$l1 = length($t1);
								$l3 = length($t3);
								$l4 = length($t4);

								# Short first t3
								if (($delta > 0) && ($l3 > 6)) {
									if ($l3 - 6 > $delta) {
										$t3 = substr($t3, 0, $l3 - 3 - $delta) . "...";
										$delta = 0;
									} else {
										$t3 = substr($t3, 0, 3) . "...";
										$delta -= $l3 - 6;
									};
								};

								# Short now t1 if required
								if (($delta > 0) && ($l1 > 6)) {
									if ($l1 - 6 > $delta) {
										$t1 = substr($t1, 0, $l1 - 3 - $delta) . "...";
										$delta = 0;
									} else {
										$t1 = substr($t1, 0, 3) . "...";
										$delta -= $l1 - 6;
									}
								};
								# Short now t4 if required
								if (($delta > 0) && ($l4 > 6)) {
									if ($l4 - 6 > $delta) {
										$t4 = substr($t4, 0, $l1 - $delta - 3) . "...";
										$delta = 0;
									} else {
										$t4= substr($t4, 0, 3) . "...";
										$delta -= $l4 - 6;
									};
								};

								if ($delta > 0) {
									#warn "Problem with print-max-width: " . $string . "\n";
								};

								$string = $t1 . " (" . $t3 . "[" . $t4 . "])";

							} elsif (($t1, $t2) = $string =~ /^([^@]*)@([^\s]*)$/o ) {
								# great_camera@srv04189.e-bizinformationcenter.com
								$l1 = length($t1);
								$l2 = length($t2);

								# Short first t2
								if (($delta > 0) && ($l2 > 6)) {
									if ($l2 - 6 > $delta) {
										$t2 = substr($t2, 0, $l2 - 3 - $delta) . "...";
										$delta = 0;
									} else {
										$t2 = substr($t2, 0, 3) . "...";
										$delta -= $l2 - 6;
									};
								};

								# Short now t1 if required
								if (($delta > 0) && ($l1 > 6)) {
									if ($l1 - 6 > $delta) {
										$t1 = substr($t1, 0, $l1 - 3 - $delta) . "...";
										$delta = 0;
									} else {
										$t1 = substr($t1, 0, 3) . "...";
										$delta -= $l2 - 6;
									}
								};

								if ($delta > 0) {
									#warn "Problem with print-max-width: " . $string . "\n";
								};

								$string = $t1 . "@" . $t2;
							} else {
								warn "No match for print-max-width: " . $string . "\n";
							}
						} else {
							# Append some spaces for right alignment
							$string .= ' ' x (- $delta);
						};
					};
					print $string . " [" . $$p2{$k2} . "]\n";
				};
			} else {
				if (! (($maxdepth >= 4) || ($maxdepth == -1))) {
					print "   `- #### Subtree entries skipped by maxdepth mechanism\n" if ($main::opts{'debug'} & 0x0040);
				} elsif ($skip == 1) {
					print "   `- #### Subtree entries skipped by option '--skip_subtree_pattern'\n" if ($main::opts{'debug'} & 0x0040);
				};
			};
		};
	};
};

## Print a treeview
# $1: pointer to treehash
# $2 (optional): list of keys
# $3 (optional): list of subkeys
sub print_treeview($;$$) {
	my $p = $_[0] || die "Missing hash pointer";
	my $list = $_[1]; # optional list of keys
	my $sublist = $_[2]; # optional list of subkeys
	my $p0;

	#print "List: " . $list . "\n";
	# print "DEBUG/main/print_treeview: called\n";
	
	if (! defined $p) { die "hash pointer is undefined"; };
	if (! %$p) {
		print "\n";
		print " !  no data !\n";
		return 1;
	};
	if (! defined $list) { $list = "" };
	if (! defined $sublist) { $sublist = "" };

	if ($list eq "" ) {
		# print "DEBUG/main/print_treeview: without list\n";
		for my $k ( sort keys %$p ) {
			# print "DEBUG/main/print_treeview: " . $k . "\n";
			$p0 = $$p{$k};
			#print "\n" . $k . " [" . scalar(keys %$p0)  . "]\n";
			print "\n" . $k . "\n";
			print_subtreeview(\%$p0, -1, $sublist);
		};
	} else {
		foreach my $k (split " ", $list) {
			print "\n" . $k . "\n";
			if (! defined $$p{$k} ) {
				print " !  no data !\n";
				next;
			};
			#print "\n" . $k . " [" . scalar(keys %$p0)  . "]\n";
			print "\n" . $k . "\n";
			$p0 = $$p{$k};
			print_subtreeview(\%$p0, -1, $sublist);
		};
	};
};

## Print a treeview
# $1: pointer to treehash
# $2 (optional): max depth
# $3 (optional): list of keys
sub print_treeview2($;$@) {
	my $p = $_[0] || die "Missing hash pointer";
	my $maxdepth = $_[1]; # optional max depth
	my $list = $_[2]; # optional list of keys
	my $p0;

	#print "Maxdepth: $maxdepth\n";
	#print "List: " . $list . "\n";
	# print "DEBUG/main/print_treeview: called\n";
	
	if (! defined $p) { die "hash pointer is undefined"; };
	if (! %$p) { die "hash of pointer is undefined"; };
	if (! defined $list) { $list = "" };

	if ($list eq "" ) {
		# print "DEBUG/main/print_treeview: without list\n";
		for my $k ( sort keys %$p ) {
			# print "DEBUG/main/print_treeview: " . $k . "\n";
			$p0 = $$p{$k};
			#print "\n" . $k . "\n";

			my $c = print_subtreeview( \%$p0, -2 );
			print "\n" . $k . " [" . $c  . "]\n";
			print_subtreeview( \%$p0, $maxdepth );
		};
	} else {
		foreach my $k (split " ", $list) {
			print "\n" . $k . "\n";
			if (! defined $$p{$k} ) {
				print " !  no data !\n";
				next;
			};
			#print "\n" . $k . " [" . scalar(keys %$p0)  . "]\n";
			#print "\n" . $k . "\n";
			$p0 = $$p{$k};
			my $c = print_subtreeview( \%$p0, -2 );
			print "\n" . $k . " [" . $c  . "]\n";
			print_subtreeview( \%$p0, $maxdepth );
		};
	};
};


## Extract domain
sub extract_domain ($) {
	my $email = shift || return "";
	#die "Missing argument";
	my $domain;

	# Cache lookup
	if (defined $cache_extract_domain{$email}) {
		return ($cache_extract_domain{$email});
	};

	if ( $email eq "from=<>" || $email eq "from=<#@[]>" ) {
		# unspecified sender, nothing to strip
		$domain = $email;
	} elsif ( $email =~ /^.*@([^@]+)$/ ) {
		$domain = $1;

		if (! defined $domain ) {
			$domain = "ADDRESS_WITH_INVALID_DOMAIN";
		};
	} else {
		# email address contains no domain
		$domain = "ADDRESS_WITHOUT_DOMAIN";
	};

	$cache_extract_domain{$email} = $domain;
	return ($domain);
};


## Extract 2nd level domain
sub extract_2ndleveldomain ($) {
	my $email = shift || die "Missing argument";
	my $domain;

	# Cache lookup
	if (defined $cache_extract_2ndleveldomain{$email}) {
		return ($cache_extract_2ndleveldomain{$email});
	};

	if ( $email eq "from=<>" || $email eq "from=<#@[]>" ) {
		# unspecified sender, nothing to strip
		$domain = $email;
		goto("END_extract_2ndleveldomain");
	};

	# Check for e-mail address
	if ( $email =~ /@/o ) {
		# Is a e-mail address	
		if ( $email =~ /^.*@([^@]+)$/o ) {
			$domain = $1;
		} else {
			$domain = "ADDRESS_WITHOUT_DOMAIN";
			goto("END_extract_2ndleveldomain");
		};

		if (! defined $domain ) {
			$domain = "ADDRESS_WITH_INVALID_DOMAIN";
			goto("END_extract_2ndleveldomain");
		};
	} else {
		# domain only
		$domain = $email;
	};

	# Strip trailing "."
	$domain =~ s/\.+$//og;

	if ( $domain =~ /^[^.]+\.(co|ac)\.[^.]+$/o || $domain =~ /^[^.]+\.(net)\.(ar)$/o || $domain =~ /^[^.]+\.[^.]+$/o ) {
		# Nothing to do anymore
	} elsif ( $domain =~ /^.*\.([^.]+(\.(co|ac))\.[^.]+)$/o || $domain =~ /^.*\.([^.]+(\.(net))\.(ar))$/o || $domain =~ /^.*\.([^.]+\.[^.]+)$/o ) {
		$domain = $1;
		if (! defined $domain ) {
			$domain = "ADDRESS_WITHOUT_SECONDLEVEL_DOMAIN";
		};
	} else {
		$domain = "ADDRESS_WITHOUT_SECONDLEVEL_DOMAIN";
	};

END_extract_2ndleveldomain:
	$cache_extract_2ndleveldomain{$email} = $domain;
	return ($domain);
};


## Modify address according to hooks
sub modify_address ($) {
	my $input = $_[0] || die "Missing argument";
	my $output;
	
	# Cache lookup
	if (defined $cache_modify_address{$input}) {
		return ($cache_modify_address{$input});
	};

	# Hook "modifyaddress"
	for my $p_hook (keys %{$main::hooks{'modifyaddress'}}) {
		$output= &{$main::hooks{'modifyaddress'}->{$p_hook}} ($input);
	};

	$cache_modify_address{$input} = $output;
	return ($output);
};


## Format number
sub format_number ($) {
	my $input = $_[0];

	if (! defined $input) {
		die "Missing argument";
	};

	my $output;

	if (! defined $opts{'fixednumberformat'}) {
		$output = $numberformat{$opts{'numberformat'}}->format_bytes($input);
	} else {
		my $unit = substr($opts{'fixednumberformat'},0,1);
		my $base_string = substr($opts{'fixednumberformat'},1);
		my $base;
		if ($base_string eq "B") {
			$base = 1000;
		} elsif ($base_string eq "iB") {
			$base = 1024;
		} else {
			warn ("unsupported base in numberformat (take 1024 as default): " . $opts{'numberformat'});
			$base = 1024;
		};

		$output = $numberformat{$opts{'numberformat'}}->format_bytes($input, ( precision => $main::opts{'fixednumberprecision'},  unit => $unit, base => $base));

		if ($base_string eq "B") {
			$output =~ s/iB$/B/;
		};

		if ($output eq "0") {
		} else {
			# Add trailing zeros
			$output =~ /^([0-9]+)([,.])([0-9]+)$/;
			my $a = $1;
			my $b = $2;
			my $c = $3;

			if (defined $b) {
				if (! defined $c) {
					$c = "000";
				};
				if (length($c) == 1) {
					$c .= "00";
				} elsif (length($c) == 2) {
					$c .= "0";
				};
				$output = $a . $b . $c;
			};
		};
	};

	return ($output);
};


## End of module
return 1;
