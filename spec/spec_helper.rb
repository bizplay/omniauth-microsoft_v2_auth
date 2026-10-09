require 'omniauth'
require 'omniauth/microsoft_v2_auth'
require 'webmock/rspec'

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.order = :random

  config.before do
    OmniAuth::Strategies::MicrosoftV2Auth.jwks_cache.clear
  end
end
