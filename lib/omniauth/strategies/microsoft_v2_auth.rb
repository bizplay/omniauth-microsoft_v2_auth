require 'json'
require 'net/http'
require 'jwt'
require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class MicrosoftV2Auth < OmniAuth::Strategies::OAuth2
      # Raised when an id_token is missing or cannot be trusted. Never rescue this
      # into a successful sign in: it means we do not know who authenticated.
      class IdTokenError < StandardError; end

      option :name, :microsoft_v2_auth

      DEFAULT_SCOPE = "openid email profile https://graph.microsoft.com/User.Read"
      SITE = 'https://login.microsoftonline.com'.freeze
      # Signs in users from any directory as well as personal Microsoft accounts
      DEFAULT_TENANT = 'common'.freeze
      JWKS_CACHE_LIFETIME = 3600
      SIGNING_ALGORITHMS = %w[RS256].freeze
      # Tolerated clock difference between us and Microsoft, in seconds
      EXPIRY_LEEWAY = 60

      option :client_options, { site: SITE }
      option :tenant, DEFAULT_TENANT

      option :authorize_options, %i[scope prompt domain_hint login_hint]

      # Taken from the Graph response rather than from the oid claim so that
      # accounts created before id_token verification keep matching
      uid { raw_info['id'] || id_token_claims['oid'] }

      extra do
        extra_hash = {}
        extra_hash['raw_info'] = raw_info unless skip_info?
        extra_hash['id_token_claims'] = id_token_claims unless id_token.nil?
        extra_hash
      end

      def raw_info
        @raw_info ||= access_token.get('https://graph.microsoft.com/v1.0/me').parsed
      end

      # The directory to authenticate against. Resolved from the options only, so
      # that this strategy can be instantiated without a request to obtain an
      # OAuth client for refreshing tokens.
      def tenant
        configured = options.tenant.to_s.strip
        configured.empty? ? DEFAULT_TENANT : configured
      end

      def client
        ::OAuth2::Client.new(options.client_id, options.client_secret, tenanted_client_options)
      end

      # Microsoft returns the id_token alongside the access token, so it arrives
      # over the back channel and needs no nonce to tie it to this browser.
      def id_token
        @id_token ||= access_token && access_token.params['id_token']
      end

      # Verified claims of the id_token. The tid claim is the only trustworthy
      # statement about which directory the user signed in from.
      def id_token_claims
        @id_token_claims ||= verified_id_token_claims
      end

      def authorize_params
        super.tap do |params|
          %w[display score auth_type prompt domain_hint login_hint].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end

          params[:scope] ||= DEFAULT_SCOPE
        end
      end

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      class << self
        def jwks(directory, force: false)
          jwks_mutex.synchronize do
            cached = jwks_cache[directory]
            if force || cached.nil? || cached[:fetched_at] + JWKS_CACHE_LIFETIME < Time.now.to_i
              cached = { keys: fetch_jwks(directory), fetched_at: Time.now.to_i }
              jwks_cache[directory] = cached
            end
            cached[:keys]
          end
        end

        def fetch_jwks(directory)
          response = Net::HTTP.get_response(URI("#{SITE}/#{directory}/discovery/v2.0/keys"))
          unless response.is_a?(Net::HTTPSuccess)
            raise IdTokenError, "could not retrieve the signing keys of directory #{directory}: #{response.code}"
          end

          JSON.parse(response.body)
        rescue JSON::ParserError => e
          raise IdTokenError, "could not retrieve the signing keys of directory #{directory}: #{e.message}"
        end

        def jwks_cache
          @jwks_cache ||= {}
        end

        def jwks_mutex
          @jwks_mutex ||= Mutex.new
        end
      end

      private

      def tenanted_client_options
        defaults = {
          site: SITE,
          authorize_url: "/#{tenant}/oauth2/v2.0/authorize",
          token_url: "/#{tenant}/oauth2/v2.0/token"
        }
        defaults.merge(deep_symbolize(options.client_options || {}))
      end

      def verified_id_token_claims
        raise IdTokenError, 'the token response contained no id_token' if id_token.nil?

        directory = unverified_tenant
        claims, = JWT.decode(
          id_token,
          nil,
          true,
          algorithms: SIGNING_ALGORITHMS,
          jwks: jwks_loader(directory),
          # A multitenant token is issued by the directory it came from, so the
          # issuer has to agree with the tid before the tid can be relied upon
          iss: "#{SITE}/#{directory}/v2.0",
          verify_iss: true,
          aud: options.client_id,
          verify_aud: true,
          verify_expiration: true,
          exp_leeway: EXPIRY_LEEWAY
        )
        claims
      rescue JWT::DecodeError => e
        raise IdTokenError, "the id_token could not be verified: #{e.message}"
      end

      def unverified_tenant
        unverified, = JWT.decode(id_token, nil, false)
        directory = unverified['tid'].to_s.strip
        raise IdTokenError, 'the id_token contains no tid claim' if directory.empty?

        directory
      rescue JWT::DecodeError => e
        raise IdTokenError, "the id_token could not be read: #{e.message}"
      end

      def jwks_loader(directory)
        lambda do |loader_options|
          self.class.jwks(directory, force: loader_options[:invalidate])
        end
      end
    end
  end
end
