# frozen_string_literal: true

Gem::Specification.new do |s|
  s.name        = 'app-store-server-library'
  s.version     = '0.0.2'
  s.summary     = 'App Store Server Library'
  s.description = 'Server library for the App Store Server API and App Store Server Notifications'
  s.authors     = ['Illia Kasianenko']
  s.email       = 'i.kasianenko@gmail.com'
  s.files       = ['lib/app_store_server_library.rb']
  s.homepage    = 'https://github.com/got2be/app-store-server-library'

  s.add_dependency 'jwt', '~> 2.8'

  s.required_ruby_version = '>= 2.7.0'
  s.metadata['rubygems_mfa_required'] = 'true'
end
