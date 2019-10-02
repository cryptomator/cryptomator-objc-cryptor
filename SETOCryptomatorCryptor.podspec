Pod::Spec.new do |s|
  s.name     = 'SETOCryptomatorCryptor'
  s.version  = '1.5.0'
  s.license  = 'AGPLv3'
  s.summary  = 'SETOCryptomatorCryptor is an iOS crypto library to access Cryptomator vaults.'
  s.homepage = 'https://github.com/cryptomator/cryptomator-objc-cryptor'
  s.social_media_url = 'https://twitter.com/Cryptomator'
  s.authors  = { 'Tobias Hagemann'   => 'tobias.hagemann@skymatic.de',
                 'Sebastian Stenzel' => 'sebastian.stenzel@skymatic.de' }
  s.source   = { :git => 'https://github.com/cryptomator/cryptomator-objc-cryptor.git', :tag => s.version.to_s }
  s.requires_arc = true

  s.public_header_files = "SETOCryptomatorCryptor/Core/{SETOCryptorProvider,SETOCryptor,SETOAsyncCryptor,SETOMasterKey}.h"
  s.source_files = 'SETOCryptomatorCryptor/**/*.{h,m,c}'

  s.platform = :ios, '8.0'

  s.frameworks = 'Security'
  s.dependency 'Base32', '~> 1.1.0'
  s.dependency 'KZPropertyMapper', '~> 2.9.0'
  s.dependency 'OpenSSL-Universal', '~> 1.0.0'

  s.subspec 'e_aeswrap' do |ss|
    ss.source_files = 'e_aeswrap/*.{h,c}'
    ss.dependency 'OpenSSL-Universal', '~> 1.0.0'
  end

  s.subspec 'scrypt' do |ss|
    ss.source_files = 'scrypt/*.{h,c}'
  end
end
