#!/usr/bin/perl

# Copyright (c) F5, Inc.
#
# This source code is licensed under the Apache License, Version 2.0 license
# found in the LICENSE file in the root directory of this source tree.

# tls-perf benchmark for ACME module.

###############################################################################

use warnings;
use strict;

use Test::More;

use IPC::Open3;
use POSIX qw/ waitpid /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::ACME;
use Test::Nginx::DNS;

###############################################################################

my $CERTS	= 50;
my $ROUNDS	= 8;
my $DURATION	= 16;
my $WORKERS	= 1;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'long test') unless $ENV{TEST_NGINX_UNSAFE};

my $t = Test::Nginx->new()->has(qw/http socket_ssl/)
	->has_daemon('openssl')
	->has_daemon('tls-perf')
	->has_daemon('ministat');

$t->plan(1);

$t->write_file_expand('nginx.conf', <<EOF);

%%TEST_GLOBALS%%

daemon off;

worker_processes      $WORKERS;
worker_cpu_affinity   auto;
worker_rlimit_nofile  65535;

env RUST_BACKTRACE;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver 127.0.0.1:%%PORT_8980_UDP%%;

    access_log off;
    error_log %%TESTDIR%%/error.log error;

    acme_issuer default {
        uri https://acme.test:%%PORT_9000%%/dir;
        ssl_trusted_certificate acme.test.crt;
        state_path %%TESTDIR%%/acme_default;
        accept_terms_of_service;
    }

    geo \$var_cert_name {
        default example.test;
    }

    server {
        listen       127.0.0.1:8443 ssl;
        server_name  example.test;

        ssl_certificate        example.test.crt;
        ssl_certificate_key    example.test.key;

        location / {
            return 200;
        }
    }

    server {
        listen       127.0.0.1:8444 ssl;
        server_name  example.test;

        ssl_certificate        \$var_cert_name.crt;
        ssl_certificate_key    \$var_cert_name.key;
        ssl_certificate_cache  max=4;

        location / {
            return 200;
        }
    }

    server {
        listen       127.0.0.1:8445 ssl;
        server_name  example.test;

        acme_certificate       default;
        ssl_certificate        \$acme_certificate;
        ssl_certificate_key    \$acme_certificate_key;
        ssl_certificate_cache  max=4;

        location / {
            return 200;
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  example.test;
    }

    include generated-servers.inc;
}

EOF

my $generated = 'acme_shared_zone zone=ngx_acme_shared:'
	. (64 + 6 * $CERTS) . "k;\n";

# TODO: update server_names_hash_max_size

for (my $i = 0; $i < $CERTS; $i++) {
	my $server_name = sprintf "cert%03i.example.test", $i;

	$generated .= <<EOF;
server {
    listen               127.0.0.1:8440 ssl;
    server_name          $server_name;
    acme_certificate     default;
    ssl_certificate      \$acme_certificate;
    ssl_certificate_key  \$acme_certificate_key;
}
EOF
}

$t->write_file_expand('generated-servers.inc', $generated);

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('acme.test', 'example.test') {
	system("openssl ecparam -genkey -out $d/$name.key -name prime256v1 "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create private key for $name: $!\n";

	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -key $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

my $dp = port(8980, udp=>1);
my @dc = (
	{ name => 'acme.test', A => '127.0.0.1', ttl => 360 },
	{ match => qr/^(\w+\.)?example.test$/, A => '127.0.0.1' }
);

my $acme = Test::Nginx::ACME->new($t, port(9000), port(9001),
	$t->testdir . '/acme.test.crt',
	$t->testdir . '/acme.test.key',
	http_port => port(8080),
	dns_port => $dp,
	nosleep => 1,
	state => $d . "/acme_default",
);

$t->run_daemon(\&Test::Nginx::DNS::dns_test_daemon, $t, $dp, \@dc);
$t->waitforfile($t->testdir . '/' . $dp);

$t->run_daemon(\&Test::Nginx::ACME::acme_test_daemon, $t, $acme);
$t->waitforsocket('127.0.0.1:' . $acme->port());
$t->write_file('acme-root.crt', $acme->trusted_ca());

$t->write_file('index.html', 'SUCCESS');
$t->run();

###############################################################################

$acme->wait_certificate('example.test', timeout => 5 * $CERTS)
	or die "no certificate";

tlsperf(8443, 16);

my @files;

foreach my $port (8443, 8444, 8445) {
	for (my $i = 0; $i < $ROUNDS; $i++) {
		select undef, undef, undef, 4.0 if $i;

		my $out = tlsperf($port, $DURATION);
		append_file($t, "tls-perf-${port}.out", $out);

		my @values = parse_tlsperf($out);
		append_file($t, "tls-perf-${port}.txt", (join "\t", @values));
		# print STDERR ".";
	}

	push @files, "$d/tls-perf-${port}.txt";
	# print STDERR "\n";
}

print STDERR run('ministat', '-C', 1, @files) . "\n";

pass();

###############################################################################

sub parse_tlsperf {
	my ($out) = @_;
	my @rv;

	# total,duration,max,avg,min

	push @rv, $2, $1 if $out =~ /SECONDS\s+(\d+);\s+HANDSHAKES\s+(\d+)/im;
	push @rv, $1 if $out =~ /^\s*HANDSHAKES.*MAX\s+(\d+)/im;
	push @rv, $1 if $out =~ /^\s*HANDSHAKES.*AVG\s+(\d+)/im;
	push @rv, $1 if $out =~ /^\s*HANDSHAKES.*MIN\s+(\d+)/im;

	die "Can't parse tls-perf output: $out" unless scalar(@rv) >= 5;

	return @rv;
}

sub tlsperf {
	my ($port, $duration) = @_;

	return run('tls-perf', '--quiet', '--tls', '1.2',
		'--sni', 'example.test',
		'-t', 2 * $WORKERS, '-T', $duration, '-l', 100,
		'127.0.0.1', port($port));
}

sub run {
    my $pid = open3( undef, my $fh, '>&STDERR', @_ );
    waitpid( $pid, 0 );
    die "$_[0] failed: $! $?\n" unless $? == 0;

    $fh->read( my $out, 32768 );
    chomp($out);
    return $out;
}

sub append_file {
	my ($t, $name, $content) = @_;

	open F, '>>', $t->testdir . '/' . $name
		or die "Can't open $name: $!\n";
	binmode F;
	print F $content . "\n";
	close F;
}

###############################################################################
