#!perl

use strict;
use warnings;

use Carp 'carp';
use Test::More tests => 4;

use lib '../lib';
use Fuzz;

my $thr;

SKIP: {
	skip( 'Perl version is less then then 5.6.0', 4 ) if $] < 5.006;

	eval { use threads 1.63 };
	skip( 'No threads support or threads version is less than 1.63', 4 ) if $@;

	eval { $thr = threads->create( \&EmulateFTP )->detach };
	skip( 'Failed to start FTP emulator thread', 4 ) if $@;

	my $obj = Fuzz->new(
		RemoteAddr => 'localhost',
		RemotePort => 21,
		FuzzLevel  => ['Letters']
	);
	ok( defined $obj && ref $obj eq 'Fuzz', 'Full constructor works properly' );

	$obj->LoadProtocolPreset( 'FTP', 'test', 'test' );    
	ok( $obj->LoadProtocolPreset eq 'FTP', 'Protocol presets works properly' );

	eval { use Data::Generate };
	skip('Data::Generate not installed', 1) if $@;
	
	$obj->AddFuzzCategory( 'Test', 'VC(2) [a-b]', qr/(\w{2})/ );
	ok( ref $obj->Test eq 'HASH', 'Custom data categories works properly' );

	ok( $obj->StartFuzzing, 'Fuzzing works properly' );
}

END { $thr->exit if ref $thr eq 'threads' && $thr->is_running }

sub EmulateFTP {
	my $serv = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => 21,
		Listen    => 1
	  )
	  || carp $! && return;

	my ( $in, @b0f );

	while (1) {
		next unless my $conn = $serv->accept;

		goto LOST unless $conn->recv( $in, 100000 );

		@b0f = split( "\r\n", $in );
		scalar @b0f == 2 || goto LOST;
		chomp @b0f;

		goto LOST if $b0f[0] eq 'QUIT';

		if ( $b0f[0] eq 'USER test' && $b0f[1] eq 'PASS test' ) {
			$conn->send("220 Logged in\r\n");
		}
		else {
			$conn->send("530 Login incorrect\r\n");

			goto LOST;
		}

		while ( $conn->recv( $in, 65536 ) ) {
			chomp $in;

			@b0f = split( ' ', $in );
			next unless defined $b0f[0] && defined $b0f[1];

			print "[~] $b0f[0] [" . length( $b0f[1] ) . " bytes]\n";

			if ( $b0f[0] eq 'CWD' && length $b0f[1] >= 512 ) {

				exit 1;
			}
			else { $conn->send("502 Command not is not supported\r\n") }
		}

	  LOST:
		$conn->close;
		next;
	}
}
