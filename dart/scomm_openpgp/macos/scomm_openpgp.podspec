Pod::Spec.new do |s|
  s.name             = 'scomm_openpgp'
  s.version          = '0.1.0'
  s.summary          = 'Scomm OpenPGP FFI plugin'
  s.description      = 'Loads the scomm_openpgp cdylib. Sequoia is an implementation detail.'
  s.homepage         = 'https://github.com/scomm-ai/scomm-openpgp'
  s.license          = { :type => 'LGPL-2.0-or-later', :file => '../../../LICENSE' }
  s.author           = { 'Scomm.AI' => 'hello@scomm.ai' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'FlutterMacOS'
  s.platform = :osx, '10.15'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version = '5.0'
end
