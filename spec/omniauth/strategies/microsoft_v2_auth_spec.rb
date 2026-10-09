require 'spec_helper'

describe OmniAuth::Strategies::MicrosoftV2Auth do
  let(:tenant_id) { 'aaaaaaaa-bbbb-cccc-dddd-000000000001' }
  let(:signing_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:other_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:jwk) { JWT::JWK.new(signing_key) }

  let(:claims) do
    {
      'iss' => "https://login.microsoftonline.com/#{tenant_id}/v2.0",
      'aud' => 'client-id',
      'exp' => Time.now.to_i + 3600,
      'iat' => Time.now.to_i,
      'tid' => tenant_id,
      'oid' => '11111111-2222-3333-4444-555555555555',
      'preferred_username' => 'someone@acme.com',
      'roles' => %w[Bizplay.Admin]
    }
  end

  def token_for(payload, key: signing_key)
    JWT.encode(payload, key, 'RS256', { kid: jwk.export[:kid] })
  end

  def strategy_for(token, options = {})
    strategy = described_class.new(nil, 'client-id', 'secret', options)
    allow(strategy).to receive(:access_token).and_return(double(params: { 'id_token' => token }))
    strategy
  end

  before do
    stub_request(:get, "https://login.microsoftonline.com/#{tenant_id}/discovery/v2.0/keys")
      .to_return(status: 200, body: { keys: [jwk.export] }.to_json, headers: { 'Content-Type' => 'application/json' })
  end

  describe '#tenant' do
    it 'signs in users from any directory by default' do
      expect(described_class.new(nil, 'client-id', 'secret').tenant).to eq('common')
    end

    it 'uses the configured directory' do
      expect(described_class.new(nil, 'client-id', 'secret', tenant: tenant_id).tenant).to eq(tenant_id)
    end

    it 'falls back to the default when the configured directory is blank' do
      expect(described_class.new(nil, 'client-id', 'secret', tenant: '  ').tenant).to eq('common')
    end
  end

  describe '#client' do
    it 'can be built without a request, so tokens can be refreshed outside the sign in flow' do
      client = described_class.new(nil, 'client-id', 'secret').client

      expect(client.token_url).to eq('https://login.microsoftonline.com/common/oauth2/v2.0/token')
      expect(client.authorize_url).to eq('https://login.microsoftonline.com/common/oauth2/v2.0/authorize')
    end

    it 'addresses a single directory when a tenant is configured' do
      client = described_class.new(nil, 'client-id', 'secret', tenant: tenant_id).client

      expect(client.authorize_url).to eq("https://login.microsoftonline.com/#{tenant_id}/oauth2/v2.0/authorize")
      expect(client.token_url).to eq("https://login.microsoftonline.com/#{tenant_id}/oauth2/v2.0/token")
    end

    it 'lets an explicitly configured endpoint win over the tenant' do
      strategy = described_class.new(nil, 'client-id', 'secret',
                                     tenant: tenant_id,
                                     client_options: { token_url: '/custom/token' })

      expect(strategy.client.token_url).to eq('https://login.microsoftonline.com/custom/token')
    end
  end

  describe '#id_token_claims' do
    it 'returns the claims of a correctly signed token' do
      claims_found = strategy_for(token_for(claims)).id_token_claims

      expect(claims_found['tid']).to eq(tenant_id)
      expect(claims_found['oid']).to eq('11111111-2222-3333-4444-555555555555')
      expect(claims_found['roles']).to eq(%w[Bizplay.Admin])
    end

    it 'retrieves the signing keys of the directory the token claims to come from' do
      strategy_for(token_for(claims)).id_token_claims

      expect(a_request(:get, "https://login.microsoftonline.com/#{tenant_id}/discovery/v2.0/keys")).to have_been_made
    end

    it 'retrieves the signing keys only once for repeated verifications' do
      strategy_for(token_for(claims)).id_token_claims
      strategy_for(token_for(claims)).id_token_claims

      expect(a_request(:get, "https://login.microsoftonline.com/#{tenant_id}/discovery/v2.0/keys")).to have_been_made.once
    end

    it 'rejects a token signed by someone else' do
      expect { strategy_for(token_for(claims, key: other_key)).id_token_claims }
        .to raise_error(described_class::IdTokenError)
    end

    it 'rejects a token issued for another application' do
      expect { strategy_for(token_for(claims.merge('aud' => 'someone-else'))).id_token_claims }
        .to raise_error(described_class::IdTokenError)
    end

    it 'rejects a token whose issuer disagrees with its tid' do
      forged = claims.merge('iss' => 'https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0')

      expect { strategy_for(token_for(forged)).id_token_claims }
        .to raise_error(described_class::IdTokenError)
    end

    it 'rejects a token that has expired' do
      expect { strategy_for(token_for(claims.merge('exp' => Time.now.to_i - 3600))).id_token_claims }
        .to raise_error(described_class::IdTokenError)
    end

    it 'rejects a token without a tid, since the directory cannot be established' do
      expect { strategy_for(token_for(claims.reject { |k, _| k == 'tid' })).id_token_claims }
        .to raise_error(described_class::IdTokenError, /no tid claim/)
    end

    it 'rejects a token response that contains no id_token' do
      strategy = described_class.new(nil, 'client-id', 'secret')
      allow(strategy).to receive(:access_token).and_return(double(params: {}))

      expect { strategy.id_token_claims }.to raise_error(described_class::IdTokenError, /no id_token/)
    end
  end
end
