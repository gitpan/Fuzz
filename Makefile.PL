#!perl

use ExtUtils::MakeMaker;

WriteMakefile(
	ABSTRACT     => 'Network services fuzzing interface',    
	NAME         => 'Fuzz',
	AUTHOR => 'Aleksey Surikov',
	VERSION_FROM => 'lib/Fuzz.pm',
	PREREQ_PM    => {
		'IO::Socket'            => 1.30,
		'Class::Accessor::Fast' => 0.31,
		'Carp'                  => 1.0701
	},
	PREREQ_FATAL => 1
);
