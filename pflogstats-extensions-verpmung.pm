#!/usr/bin/perl -w

###
# Project:     pflogstats
# Module:      pflogstats-extensions-verpmung.pm
# Type:        extensions
# Description: Verp Mung extenstion for address rewriting
# Copyright:   Dr. Peter Bieringer <pbieringer at aerasec dot de>
#               AERAsec GmbH <http://www.aerasec.de/> 
# License:     GNU GPL v2
# CVS:         $Id: pflogstats-extensions-verpmung.pm,v 1.4 2003/05/22 14:02:23 rootadm Exp $
###

## ChangeLog
#	0.01
#	 - initial split-off
#	0.02
#	 - add support for linux-kernel-owner+emailddr=40user.do.main@vger.kernel.org
#       0.03
#        - make Perl 5.0 compatible
##


use strict;


## Local constants
my $module_type = "extensions";
my $module_name = $module_type . "verpmung";
my $module_version = "0.03";

package pflogstats::extensions::verpmung;

## Export module info
$main::moduleinfo{$module_name}->{'version'} = $module_version;
$main::moduleinfo{$module_name}->{'type'} = $module_type;
$main::moduleinfo{$module_name}->{'name'} = $module_name;


# Global prototyping
sub help();


## Local prototyping


## Register options
$main::options{'verp_mung:i'} = \$main::opts{'verpMung'};


## Register calling hooks
$main::hooks{'modifyaddress'}->{$module_name} = \&modifyaddress;
$main::hooks{'help'}->{$module_name} = \&help;


## Global variables


## Local variables


## Global callable functions

# Help
sub help() {
	my $helpstring = "
     [--verp_mung[=<n>]] do 'VERP' generated address munging (n=2: more munging)
";
	#    --verp_mung=2  sender addresses of the form
	#                   "list-return-NN-someuser=some.dom@host.sender.dom"
	#                    to
	#                      "list-return-ID-someuser=some.dom@host.sender.dom"
	#
	#                    In other words: replace the numeric value with "ID".
	#
	#                   By specifying the optional "=2" (second form), the
	#                   munging is more "aggressive", converting the address
	#                   to something like:
	#
	#                        "list-return@host.sender.dom"
	#
	#                   (Actually: specifying anything less than 2 does the
	#                   "simple" munging and anything greater than 1 results
	#                   in the more "aggressive" hack being applied.)
	#
	return $helpstring;
};


# Modify address
sub modifyaddress($) {
	my $address = $_[0] || die "ERROR: arg1 (address) missing";

        # Return address
        return &do_verp_mung($address);
};



## Local functions

## verp mung
sub do_verp_mung($) {
	my $addr = $_[0] || die "Missing address (arg1)";

	if (! defined $main::opts{'verpMung'} ) { 
		return $addr;
	};

	my $info = "";

	# Hack for VERP (?) - convert address from somthing like
	# "list-return-36-someuser=someplace.com@lists.domain.com"
	# to "list-return-ID-someuser=someplace.com@lists.domain.com"
	# to prevent per-user listing "pollution."  More aggressive
	# munging converts to something like
	# "list-return@lists.domain.com"  (Instead of "return," there
	# may be numeric list name/id, "warn", "error", etc.?)

	# Catch: 0_00000_00000000-0000-0000-0000-000000000000_us@newsletters.microsoft.com
	# -> TOKEN@newsletters.microsoft.com
	if ( $addr =~ s/^[0-9A-Za-z_\-]+_([^\@]+)\@(newsletters.microsoft.com)$/$1-TOKEN\@$2/o ) {
		$info = "M1"; goto "LABEL_end"; };

	# Catch: ems+HDV.....LBZ9AQ@bounces.amazon.com
	# -> ems-TOKEN@bounces.amazon.com
	if ( $addr =~ s/^(ems)\+[^\@]+\@(bounces.amazon.com)$/$1-TOKEN\@$2/o ) {
		$info = "M2";  goto "LABEL_end"; };

	# Catch: token-00000-00000-00asas@*
	# -> *-TOKEN@*
	if ( $addr =~ s/^([^\@]+)-[0-9]+-[0-9]+-[0-9A-Za-z]+\@([^\@]+)$/$1-TOKEN\@$2/o ) {
		$info = "M3";  goto "LABEL_end"; };

	# Catch: accinv-18027710-317489000000hf1j100d39lkepgkcn@*
	# -> *-TOKEN@*
	if ( $addr =~ s/^([^\@]+)-[0-9]+-[0-9A-Za-z]+\@([^\@]+)$/$1-TOKEN\@$2/o ) {
		$info = "M3a";  goto "LABEL_end"; };

	# Catch: 000000000000000000008gsnzlfvbougomu-@reply.yahoo.com
	# -> TOKEN@*
	if ( $addr =~ s/^[0-9A-Za-z]+-\@([^\@]+)$/TOKEN\@$1/o ) {
		$info = "M4";  goto "LABEL_end"; };

	# Catch: pgsql-jdbc-owner+00000@postgresql.org
	# -> bounce-TOKEN@*
	if ( $addr =~ s/^([0-9A-Za-z\-]*owner)\+[0-9A-Za-z]+\@([^\@]+)$/$1-TOKEN\@$2/o ) {
		$info = "M5";  goto "LABEL_end"; };

	## Catch: bounce*+-53000073-109@*
	## -> bounce-TOKEN@*
	#if ( $addr =~ s/^([0-9A-Za-z\-]*([u]bounce|errors|owner)(-[0-9A-Za-z_]+))?\+[0-9A-Za-z\-^\@]+\@([^\@]+)$/$1-TOKEN\@$2/o ) {
	#	$info = "M5b";  goto "LABEL_end"; };

	# Catch: bounce*+-53000073-109@*
	# -> bounce-TOKEN@*
	if ( $addr =~ s/^([0-9A-Za-z\-]*errors)\+[0-9A-Za-z\-^\@]+\@([^\@]+)$/$1-TOKEN\@$2/o ) {
		$info = "M5c";  goto "LABEL_end"; };

	if ( $addr =~ s/^([0-9A-Za-z\-]*bounce)\+[0-9A-Za-z\-^\@]+\@([^\@]+)$/$1-TOKEN\@$2/o ) {
		$info = "M5c";  goto "LABEL_end"; };

	if ( $addr =~ s/^([0-9A-Za-z\-]*bounce[0-9A-Za-z_-]*)-[0-9\-]+\@([^\@]+)$/$1-TOKEN\@$2/o ) {
		$info = "M5d";  goto "LABEL_end"; };

	# Catch: *-return-00-40000080@*
	# -> *-return-TOKEN@*
	if ( $addr =~ s/^([^\@]+-return)-[0-9]\-]+\@([^\@]+)$/$1-TOKEN\@$2/o ) {
		$info = "M6";  goto "LABEL_end"; };

	# Catch: d-5-000009-6000002-2-00000-de1-c8000003@xmr3.com
	# -> TOKEN@*
	if ( $addr =~ s/^([^\@]+)\@(xmr3.com)$/TOKEN\@$2/o ) {
		$info = "M7";  goto "LABEL_end"; };

	# Catch: computercorner-text-00000edh@rtn.emazing.com
	# -> *-TOKEN@*
	if ( $addr =~ s/^([^\@]+)-[A-Za-z0-9]+\@(rtn.emazing.com)$/$1-TOKEN\@$2/o ) {
		$info = "M8";  goto "LABEL_end"; };

	# Catch: bmn-e2-0000070@bmn-alerts.com
	# -> *-return-TOKEN@*
	if ( $addr =~ s/^([^\@]+)-[A-Za-z0-9]+-[0-9]+\@([^\@]+)$/$1-TOKEN\@$2/o ) {
		$info = "M9";  goto "LABEL_end"; };

	# Catch: 00000fuqyh50eufuqwz-dn00000yis5fuqmv7c@bounce.etracks.com
	# -> TOKEN@*
	if ( $addr =~ s/^[0-9A-Za-z]+-?[0-9A-Za-z]*\@(bounce.etracks.com)$/TOKEN\@$1/o ) {
		$info = "M10";  goto "LABEL_end"; };

	# Catch: mz_0000000000b467dfd61dfb7bc54d1efd@yodel.mountainzone.com
	# -> TOKEN@*
	if ( $addr =~ s/^([A-Za-z]+)_[0-9A-Za-z]+\@([A-Za-z]+\.mountainzone\.com)$/$1-TOKEN\@$2/o ) {
		$info = "M11";  goto "LABEL_end"; };

	# Catch: online#1.2252.0d-00000dd00000crrr.1.b@xidserv.com
	# -> TOKEN@*
	if ( $addr =~ s/^(online|realage)#[0-9A-Za-z\.]+-?[0-9A-Za-z\.]+\@([^\@]+)$/$1-TOKEN\@$2/o ) {
		$info = "M12";  goto "LABEL_end"; };

	# Catch: anaesthesiologyhtml.um.a.00.0000@email.docguide.com
	# -> TOKEN@*
	if ( $addr =~ s/^([0-9A-Za-z]+)\.um\.[0-9A-Za-z\.]+\@([^\@]+)$/$1-TOKEN\@$2/o ) {
		$info = "M13";  goto "LABEL_end"; };


	# Catch: reports.7g7.....urX6v76OUxAPwJR7474YWJz.e3@mail.internetseer.com
	# -> reports-TOKEN@mail.internetseer.com
	if ( $addr =~ s/^(reports)\.[^\@]+\@(mail.internetseer.com)$/$1-TOKEN\@$2/o ) {
		$info = "M14";  goto "LABEL_end"; };


	# Catch: list-errors.1000008872.90074.1000035839.007.0.4@*
	# -> list-errors-TOKEN@*
	if ( $addr =~ s/^(list-errors)\.[0-9.^\@]+\@([^\@]+)$/$1-ID\@$2/o ) {
		$info = "M15";  goto "LABEL_end"; };


	# Catch: linux-kernel-owner+emailddr=40user.do.main@vger.kernel.org
	# -> bounce-TOKEN@*
	if ( $addr =~ s/^([0-9A-Za-z\-]*owner)\+[0-9A-Za-z=\-]+[^\@]+\@([^\@]+)$/$1-TOKEN\@$2/o ) {
		$info = "M16";  goto "LABEL_end"; };


	# Catch: 20-2231-domain?user@*
	if($main::opts{'verpMung'} > 1) {
		# -> ID@*
		if ( $addr =~ s/^[0-9]+-[0-9]+-[^\@]+\?[^\@]+\@([^\@]+)$/ID\@$1/o ) {
			$info = "MID1"; goto "LABEL_end"; };
	} else {
		# -> domain?user@*
		if ( $addr =~ s/^[0-9]+-[0-9]+-([^\@]+)\?([^\@]+)\@([^\@]+)$/$2=$1\@$3/o ) {
			$info = "MID1"; goto "LABEL_end"; };
	};

	# Catch: b.bestoffers.a-000007-0000.domain.tld*user@m1.baccart.com
	if($main::opts{'verpMung'} > 1) {
		# -> *-ID@*
		if ( $addr =~ s/^([A-Za-z0-9\.]+)-[A-Za-z0-9]+-[A-Za-z0-9]+\.[^\@]+\*[^\@]+\@([^\@]+)$/$1-ID\@$2/o ) {
			$info = "MID2"; goto "LABEL_end"; };
	} else {
		# -> *-user=domain@*
		if ( $addr =~ s/^([A-Za-z0-9\.]+)-[A-Za-z0-9]+-[A-Za-z0-9]+\.([^\@]+)\*([^\@]+)+\@([^\@]+)$/$1-$3=$2\@$4/o ) {
			$info = "MID2"; goto "LABEL_end"; };
	};

	# Catch: *-return-000-user=domain@*
	if($main::opts{'verpMung'} > 1) {
		# -> *-return-user=domain@*
		if ( $addr =~ s/^([^\@]+-return)-?[0-9]*-[^\@^=]+=[^\@^=]+\@([^\@]+)$/$1-ID\@$2/o ) {
			$info = "MID3"; goto "LABEL_end"; };
	} else {
		# -> *-return-ID@*
		if ( $addr =~ s/^([^\@]+-return)-?[0-9]*-([^\@^=]+)=([^\@^=]+)\@([^\@]+)$/$1-$2=$3\@$4/o ) {
			$info = "MID3"; goto "LABEL_end"; };
	};

	# Catch: bounce-debian-alpha=user=domain@lists.debian.org
	if($main::opts{'verpMung'} > 1) {
		# -> *-ID@*
		if ( $addr =~ s/^([^\@]+)=[^\@]+=[^\@]+\@([^\@]+)$/$1-ID\@$2/o ) {
			$info = "MID4"; goto "LABEL_end"; };
	} else {
		# -> *-user=domain@*
		if ( $addr =~ s/^([^\@]+)=([^\@]+)=([^\@]+)\@([^\@]+)$/$1-$2=$3\@$4/o ) {
			$info = "MID4"; goto "LABEL_end"; };
	};

	# Catch: sentto-12456-6789-12345-user=domain.test@*
	if($main::opts{'verpMung'} > 1) {
		# -> sentto@returns.groups.yahoo.com
		if ( $addr =~ s/^(sentto|probe)-[^-]+-?[^-]*-[^-]+-[^\@^=]+=[^\@^=]+\@([^\@]+)$/$1-ID\@$2/o ) {
			$info = "MID5"; goto "LABEL_end"; };
	} else {
		# -> sentto-user=domain.test@returns.groups.yahoo.com
		if ( $addr =~ s/^(sentto|probe)-[^-]+-?[^-]*-[^-]+-([^\@^=]+)=([^\@^=]+)\@([^\@]+)$/$1-$2=$3\@$4/o ) {
			$info = "MID5"; goto "LABEL_end"; };
	};

	# Catch: listname-user=domain.test@*
	if($main::opts{'verpMung'} > 1) {
		if ( $addr =~ s/^([^@^\.]+)-[^\@^=]+=[^\@^=]+\@([^\@]+)$/$1-ID\@$2/o ) {
			$info = "MID6"; goto "LABEL_end"; };
	} else {
		if ( $addr =~ s/^([^@^\.]+)-([^\@^=]+)=([^\@^=]+)\@([^\@]+)$/$1-$2=$3\@$4/o ) {
			$info = "MID6"; goto "LABEL_end"; };
	};

	# Catch: ft44-errors+000001+user+domain@bounce.ft.com
	if($main::opts{'verpMung'} > 1) {
		if ( $addr =~ s/^([^@^\.]+)\+[0-9]+\+[^\@^+]+\+[^\@^+]+\@([^\@]+)$/$1-ID\@$2/o ) {
			$info = "MID7"; goto "LABEL_end"; };
	} else {
		if ( $addr =~ s/^([^@^\.]+)\+[0-9]+\+([^\@^+]+)\+([^\@^+]+)\@([^\@]+)$/$1-$2=$3\@$4/o ) {
			$info = "MID7"; goto "LABEL_end"; };
	};

	# Catch: nolist-000003458-0000-user*name**domain*tld@mail1.savingsengine.com
	if($main::opts{'verpMung'} > 1) {
		if ( $addr =~ s/^([0-9A-Za-z]+)-[0-9]+-[0-9]*-?[^\@]+\*\*[^\@]+\@([^\@]+)$/$1-ID\@$2/o ) {
			$info = "MID8"; goto "LABEL_end"; };
	} else {
		if ( $addr =~ s/^([0-9A-Za-z]+)-[0-9]+-[0-9]*-?([^\@]+)\*\*([^\@]+)\@([^\@]+)$/$1-$2=$3\@$4/o ) {
			$addr =~ s/\*/\./g;
			$info = "MID8"; goto "LABEL_end"; };
	};

	# Catch: owner-nolist-hps-000000c*user*-name**domain*-tld@lsv-003.apcxp.com
	if($main::opts{'verpMung'} > 1) {
		if ( $addr =~ s/^([0-9A-Za-z\-]+)-[0-9A-Fa-f]+\*[^\@]+\*\*[^\@]+\@([^\@]+)$/$1-ID\@$2/o ) {
			$info = "MID9"; goto "LABEL_end"; };
	} else {
		if ( $addr =~ s/^([0-9A-Za-z\-]+)-[0-9A-Fa-f]+\*([^\@]+)\*\*([^\@]+)\@([^\@]+)$/$1-$2=$3\@$4/o ) {
			$addr =~ s/\*-/\./g;
			$info = "MID9"; goto "LABEL_end"; };
	};

	# Catch ezmlm sc/uc cookies: maillist-uc.1234567.dcgpdkfimohjejclelg-user=domain.test@maillist.test
	if($main::opts{'verpMung'} > 1) {
		# -> maillist-uc@maillist.test
		if (  $addr =~ s/^(.+-[su]c)\.[^\@]+\@([^\@]+)$/$1-ID\@$2/o ){
			$info = "MID10"; goto "LABEL_end"; };
	} else {
		# -> maillist-uc-user=domain.test@maillist.test
		if ( $addr =~ s/^(.+-[su]c)\.[^\-]+-([^\@]+)\@([^\@]+)$/$1-$2\@$3/o ) {
			$info = "MID10"; goto "LABEL_end"; };
	};
			



	#if($opts{'verpMung'} > 1) {
	#	# $addr =~ s/^(.+)-return-\d+-[^\@]+(\@.+)$/$1$2/o;
	#	#$addr =~ s/-(\d+-)?[^=-]+=[^\@]+\@/\@/o;
	#
	#} else {
	#	# $addr =~ s/-return-\d+-/-return-ID-/o;
	#	#$addr =~ s/-(return|\d+)-\d+-/-$1-ID-/o; # Currently disabled
	#
	#};

LABEL_end:
	print $info if ( defined($main::opts{'type'}) && $main::opts{'type'} eq "test_verp_mung" );
	if ( ( ($main::opts{'debug'} & 0x1000) ) && ( $info ne "" ) ) {
		return($info . "-" . $addr);
	} else {
		return($addr);
	};
};


## End of module
return 1;
