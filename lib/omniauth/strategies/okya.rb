require 'omniauth-oauth2'
require 'omniauth/okya/jwt_validator'
require 'omniauth/okya/errors'

module OmniAuth
  module Strategies
    class Okya < OmniAuth::Strategies::OAuth2
      option :name, 'okya'

      # Setup client URLs used during authentication
      def client
        options.client_options.site = options.domain
        options.client_options.authorize_url = '/oauth/authorize'
        options.client_options.token_url = '/oauth/token'
        options.client_options.userinfo_url = '/oauth/userinfo'
        super
      end

      # Use the "sub" key of the userinfo returned
      # as the uid (globally unique string identifier).
      uid { raw_info['sub'] }

      # Build the API credentials hash with returned auth data.
      credentials do
        credentials = {
          'token' => access_token.token,
          'expires' => true
        }

        if access_token.params
          credentials.merge!(
            'id_token' => access_token.params['id_token'],
            'token_type' => access_token.params['token_type'],
            'refresh_token' => access_token.refresh_token
          )
        end

        # Retrieve and remove authorization params from the session
        session_authorize_params = session[:authorize_params] || {}
        session.delete(:authorize_params)

        auth_scope = session_authorize_params['scope'].split
        if auth_scope.respond_to?(:include?) && auth_scope.include?('openid')
          # Make sure the ID token can be verified and decoded.
          jwt_validator.verify(credentials['id_token'], session_authorize_params)
        end

        credentials
      end

      info do
        {
          given_name: raw_info['given_name'],
          family_name: raw_info['family_name'],
          email: raw_info['email'],
          created_at: raw_info['created_at'],
          updated_at: raw_info['updated_at'],
          role: raw_info['role']
        }
      end

      extra do
        { raw_info: raw_info }
      end

      # Define the parameters used for the /authorize endpoint
      def authorize_params
        params = super
        %w[connection connection_scope prompt screen_hint login_hint organization invitation ui_locales].each do |key|
          params[key] = request.params[key] if request.params.key?(key)
        end

        # Generate nonce
        params[:nonce] = SecureRandom.hex
        # Generate leeway if none exists
        params[:leeway] = 60 unless params[:leeway]

        # Store authorize params in the session for token verification
        session[:authorize_params] = params.to_hash

        params
      end

      # Declarative override for the request phase of authentication
      def request_phase
        if no_client_id?
          # Do we have a client_id for this Application?
          fail!(:missing_client_id)
        elsif no_client_secret?
          # Do we have a client_secret for this Application?
          fail!(:missing_client_secret)
        elsif no_domain?
          # Do we have a domain for this Application?
          fail!(:missing_domain)
        else
          # All checks pass, run the Oauth2 request_phase method.
          super
        end
      end

      def callback_phase
        super
      rescue OmniAuth::Okya::TokenValidationError => e
        fail!(:token_validation_error, e)
      end

      private

      def jwt_validator
        @jwt_validator ||= OmniAuth::Okya::JWTValidator.new(options)
      end

      # Parse the raw user info.
      def raw_info
        return @raw_info if @raw_info

        if access_token['id_token']
          claims, = jwt_validator.decode(access_token['id_token'])
          @raw_info = claims
        else
          userinfo_url = options.client_options.userinfo_url
          @raw_info = access_token.get(userinfo_url).parsed
        end

        @raw_info
      end

      # Check if the options include a client_id
      def no_client_id?
        ['', nil].include?(options.client_id)
      end

      # Check if the options include a client_secret
      def no_client_secret?
        ['', nil].include?(options.client_secret)
      end

      # Check if the options include a domain
      def no_domain?
        ['', nil].include?(options.domain)
      end

    end
  end
end
