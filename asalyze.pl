#!/usr/bin/perl -w
# ex: ./asalyze.pl --log=/var/log/fwsm.log

use strict;
no warnings;
use Getopt::Long;
use Time::Local;

## Global variables
my ($o_verb, $o_help, $o_log);

## Funtions
sub check_options {
	Getopt::Long::Configure ("bundling");
	GetOptions(
		'l:s'     => \$o_log,            'log:s'	=> \$o_log,
		'v'     => \$o_verb,            'verbose'	=> \$o_verb,
		'h'     => \$o_help,            'help'	=> \$o_help,
	);

	if(defined ($o_help)){
		help();
		exit 1;
	}

	if(!defined($o_log)){
		print "--log missing\n";
		exit 1;
	}
}

sub help() {
	print "$0\n";
        print <<EOT;
-v, --verbose
        print extra debugging information
-h, --help
	print this help message
-l, --log
	logfile to read
EOT
}

sub print_usage() {
        print "Usage: $0 [-v] ]\n";
}

sub ProcessHost($){
	my ($host) = @_;

	my $ip_port;
	my $name;
	if($host =~ ":"){
		($name, $ip_port) = split(":", $host);
	} else {
		$ip_port = $host;
	}

	my($ip, $port) = split("/", $ip_port);

	return ($ip, $port, $name);
}

sub ProcessLine(@){
	my (@vals) = @_;

	my $month = $vals[0];
	my $day = $vals[1];
	my $time = $vals[2];
	my $device = $vals[3];
	my $msg = $vals[4];
	my $action = $vals[5];

	my($proto, $conn_id, $src, $dst, $duration, $bytes);

	if($msg eq "%fwsm-6-302013:"){
		$proto = $vals[7];
		$conn_id = $vals[9];
		$src = $vals[11];
		$dst = $vals[14];
	} elsif($msg eq "%fwsm-6-302016:"){
		$proto = $vals[6];
		$conn_id = $vals[8];
		$src = $vals[10];
		$dst = $vals[12];
		$duration = $vals[14];
		$bytes = $vals[16];
	} elsif($msg eq "%fwsm-6-106028:"){
		$proto = $vals[6];
		$src = $vals[12];
		$dst = $vals[14];
	} elsif($msg eq "%fwsm-6-106015:"){
		$proto = $vals[6];
		$src = $vals[10];
		$dst = $vals[12];
	} elsif($msg eq " %fwsm-4-106023"){
		$proto = $vals[6];
		$src = $vals[8];
		$dst = $vals[10];
	} elsif($msg eq "%fwsm-2-106007:"){
		$proto = $vals[7];
		$src = $vals[9];
		$dst = $vals[11];
	} else {
		return 0;
	}

	return ($device, $action, $proto, $conn_id, $src, $dst);
}

sub header($){
	my ($header) = @_;
format HEAD =
@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$header
===============================================================================
.
local $~ ="HEAD";
write;

}

sub Summary($){
  	my %hash = %{shift()};

	my $i=0;
	foreach my $key (sort {$hash{$b}<=>$hash{$a}} keys %hash) {
		$i++;
		my $entries = $hash{$key};

	format out = 	
@<<<<     @<<<<<<<<<<<<<<<<<<<<<     @<<<<<<<<      
$i, $key, $entries
.
local $~ ="out";
write;

		if($i > 9){
			return;
		}
	}
}

sub ProcessLog($){
	my ($log) = @_;

	my $max=0;
	my $i=0;
	open(L, "$log");

	my $g_records=0;
	my $g_sec_total=0;

	my $p_sec=0; # Keep previous sec
	my $g_sec=0;

	my $r_per_sec=0;

	my $g_time_start = time();
	my %collect_src;
	my %collect_dst;
	my %collect_dst_port;
	while(<L>){
		chomp($_);
		
		my @vals = split(" ", lc($_));
		my $month = $vals[0];
		my $day = $vals[1];
		my $time = $vals[2];
		my $device = $vals[3];
		my $msg = $vals[4];

		if($max && $i > $max){
			last;
		}

		# Process the line and get important data
		my ($device, $action, $proto, $conn_id, $src, $dst);
		($device, $action, $proto, $conn_id, $src, $dst) = ProcessLine(@vals);

		if($src){
			my ($src_i, $src_p) = ProcessHost($src);
			my ($dst_i, $dst_p) = ProcessHost($dst);

			if($action eq "deny"){
				# Collect and count data

				# src ip address
				$collect_src{$src_i} = $collect_src{$src_i}+1;
				# dst ip address
				$collect_dst{$dst_i} = $collect_dst{$dst_i}+1;

				# dst port
				$collect_dst_port{$dst_p} = $collect_dst_port{$dst_p}+1;
			}
		}

		# General stats
		my ($hour, $min, $sec) = split(":", $time);

		if($p_sec ne $sec){
			# New sec
			$g_sec_total++;
		} 

		# Count records
		$g_records++;

		# Keep current sec
		$p_sec=$sec;

		$i++;
	}
	close(L);

	my $g_time_end = time();
	my $g_time_total = $g_time_end - $g_time_start;

	my $rps = int($g_records / $g_sec_total);
	print "### Summary\n";
	print "# General\n";
	print "Summary generated in: $g_time_total secs\n"; 
	print "Time covered: $g_sec_total secs\n";
	print "\n";

	print "# Connections\n";
	print "Total connections: $g_records\n";
	print "Connections per sec: $rps\n";

	print "\n";
	print "### Denied connections\n\n";
	print "# Top source address\n";
	header("Nr        Source address             # entries");
	Summary(\%collect_src);

	print "\n\n";

	print "# Top destination address\n";
	header("Nr        Destination address        # entries");
	Summary(\%collect_dst);

	print "\n\n";

	print "# Top destination ports\n";
	header("Nr        Port #                     # entries");
	Summary(\%collect_dst_port);
}


## Main
check_options();

ProcessLog($o_log);
