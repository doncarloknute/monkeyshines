require 'net/http'
require 'oauth'
Net::HTTP.version_1_2
module Monkeyshines
  module Fetcher

    #
    class AuthedHttpFetcher < HttpFetcher
      attr_accessor :auth_params, :oauth_token, :oauth_secret, :consumer_key, :consumer_secret, :site, :authorize_path
      # 
      # All the stuff below was copied from http://github.com/moomerman/twitter_oauth in the client.rb file
      # 
      # def initialize(options = {})
      #   @consumer_key = options[:consumer_key]
      #   @consumer_secret = options[:consumer_secret]
      #   @token = options[:token]
      #   @secret = options[:secret]
      # end
      # 
      # def authorize(token, secret, options = {})
      #   request_token = OAuth::RequestToken.new(
      #     consumer, token, secret
      #   )
      #   @access_token = request_token.get_access_token(options)
      #   @token = @access_token.token
      #   @secret = @access_token.secret
      #   @access_token
      # end
      # 
      # def show(username)
      #   get("/users/show/#{username}.json")
      # end
      # 
      # # Returns the string "ok" in the requested format with a 200 OK HTTP status code.
      # def test
      #   get("/help/test.json")
      # end
      # 
      # def request_token(options={})
      #   consumer.get_request_token(options)
      # end
      # 
      # def authentication_request_token(options={})
      #   consumer.options[:authorize_path] = '/oauth/authenticate'
      #   request_token(options)
      # end
      # 
      # private
      # 
      #   def consumer
      #     @consumer ||= OAuth::Consumer.new(
      #       @consumer_key,
      #       @consumer_secret,
      #       { :site => "http://api.twitter.com" }
      #     )
      #   end
      # 
      #   def access_token
      #     @access_token ||= OAuth::AccessToken.new(consumer, @token, @secret)
      #   end
      # 
      #   def get(path, headers={})
      #     headers.merge!("User-Agent" => "twitter_oauth gem v#{TwitterOAuth::VERSION}")
      #     oauth_response = access_token.get("/1#{path}", headers)
      #     JSON.parse(oauth_response.body)
      #   end
      # 
      #   def post(path, body='', headers={})
      #     headers.merge!("User-Agent" => "twitter_oauth gem v#{TwitterOAuth::VERSION}")
      #     oauth_response = access_token.post("/1#{path}", body, headers)
      #     JSON.parse(oauth_response.body)
      #   end
      # 
      #   def delete(path, headers={})
      #     headers.merge!("User-Agent" => "twitter_oauth gem v#{TwitterOAuth::VERSION}")
      #     oauth_response = access_token.delete("/1#{path}", headers)
      #     JSON.parse(oauth_response.body)
      #   end


      def initialize _options={}
        super _options
        # These should get called by calling super, right?
        # self.username = options[:username]
        # self.password = options[:password]
        # self.http_req_options = {}
        # self.http_req_options["User-Agent"] = options[:user_agent] || USER_AGENT
        # self.http_req_options["Connection"] = "keep-alive"
        self.oauth_token = options[:oauth_token]
        self.oauth_secret = options[:oauth_token_secret]
        self.consumer_key = options[:consumer_key]
        self.consumer_secret = options[:consumer_secret]
        self.site = options[:site]
        self.authorize_path = options[:authorize_path]
      end

      def request_token(options={})
        consumer.options[:authorize_path] = @authorize_path
        consumer.get_request_token(options)
      end

      def authorize(token, secret, options = {})
        request_token = OAuth::RequestToken.new(
          consumer, token, secret
        )
        @access_token = request_token.get_access_token(options)
        @token = @access_token.token
        @secret = @access_token.secret
        @access_token
      end

      def get_access_token
      end

      def oauth_token
        @oauth_token
      end
      
      def oauth_secret
        @oauth_secret
      end
      
      def consumer
        @consumer ||= OAuth::Consumer.new(
          @consumer_key,
          @consumer_secret,
          { :site => @site }
        )
      end
    
      def access_token
        @access_token ||= OAuth::AccessToken.new(consumer, @token, @secret)
      end

      def session_key
      end
      
      # authenticate request
      def authenticate req
        get_session_key unless session_key
      end

      
    end

  end
end
