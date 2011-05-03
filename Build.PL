#!/usr/bin/perl

use Module::Build;

my $build = Module::Build->new(
    auto_configure_requires => 1,
    module_name => 'Digest::Oplop',
    license     => 'perl',
    create_license => 1,
    build_requires    => {
	'Module::Build' => 0,
    },
    requires    => {
	'Digest::MD5' => 0,
	'Encode' => 0,
    },
);
$build->create_build_script;
