#!perl

use strict;
use warnings;

use Test::Simple tests => 3;

use lib '../lib';
use Fuzz;

ok(Fuzz->VERSION > 0, 'VERSION set properly');

my $obj = Fuzz->new('ya.ru:80');
ok(defined $obj && ref $obj eq 'Fuzz', 'Short constructor works properly');

$obj->AuthTemplate('TesT');
ok($obj->AuthTemplate eq 'TesT', 'Acessors/mutators works properly');