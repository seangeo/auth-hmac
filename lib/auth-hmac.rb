# Copyright (c) 2008 The Kaphan Foundation
#
# See License.txt for licensing information.
#

$:.unshift(File.dirname(__FILE__)) unless
  $:.include?(File.dirname(__FILE__)) || $:.include?(File.expand_path(File.dirname(__FILE__)))

require 'openssl'
require 'base64'

# This module provides a HMAC Authentication method for HTTP requests. It should work with
# net/http request classes and CGIRequest classes and hence Rails.
#
# It is loosely based on the Amazon Web Services Authentication mechanism but
# generalized to be useful to any application that requires HMAC based authentication.
# As a result of the generalization, it won't work with AWS because it doesn't support
# the Amazon extension headers.
#
class AuthHMAC
  module Headers # :nodoc:
    # Gets the headers for a request.
    #
    # Attempts to deal with known HTTP header representations in Ruby.
    # Currently handles net/http and Rails.
    #
    def headers(request)
      if request.respond_to?(:[])
        request
      elsif request.respond_to?(:headers)
        request.headers
      else
        raise ArgumentError, "Don't know how to get the headers from #{request.inspect}"
      end
    end
    
    def find_header(keys, headers)
      keys.map do |key|
        headers[key]
      end.compact.first
    end
  end
  
  include Headers
  
  # Signs a request using a given access key id and secret.
  #
  def AuthHMAC.sign!(request, access_key_id, secret)
    self.new(access_key_id => secret).sign!(request, access_key_id)
  end
  
  def AuthHMAC.authenticated?(request, access_key_id, secret)
    self.new(access_key_id => secret).authenticated?(request)
  end
  
  # Create an AuthHMAC instance using a given credential store.
  #
  # A credential store must respond to the [] method and return
  # the secret for the access key id passed to [].
  #
  def initialize(credential_store)
    @credential_store = credential_store
  end
  
  # Signs a request using the access_key_id and the secret associated with that id
  # in the credential store.
  #
  # Signing a requests adds an Authorization header to the request in the format:
  #
  #  AuthHMAC <access_key_id>:<signature>
  #
  # where <signature> is the Base64 encoded HMAC-SHA1 of the CanonicalString and the secret.
  #
  def sign!(request, access_key_id)
    secret = @credential_store[access_key_id]
    raise ArgumentError, "No secret found for key id '#{access_key_id}'" if secret.nil?
    request['Authorization'] = build_authorization_header(request, access_key_id, secret)
  end
  
  # Authenticates a request using HMAC
  #
  # Returns true if the request has an AuthHMAC Authorization header and
  # the access id and HMAC match an id and HMAC produced for the secret
  # in the credential store. Otherwise returns false.
  #
  def authenticated?(request)
    if md = /^AuthHMAC ([^:]+):(.+)$/.match(find_header(%w(Authorization HTTP_AUTHORIZATION), headers(request)))
      access_key_id = md[1]
      hmac = md[2]
      secret = @credential_store[access_key_id]      
      !secret.nil? && hmac == build_signature(request, secret)
    else
      false
    end
  end
  
  private
    def build_authorization_header(request, access_key_id, secret)
      "AuthHMAC #{access_key_id}:#{build_signature(request, secret)}"      
    end
    
    def build_signature(request, secret)
      canonical_string = CanonicalString.new(request)
      digest = OpenSSL::Digest::Digest.new('sha1')
      Base64.encode64(OpenSSL::HMAC.digest(digest, secret, canonical_string)).strip
    end
  
  # Build a Canonical String for a HTTP request.
  #
  # A Canonical String has the following format:
  #
  # CanonicalString = HTTP-Verb    + "\n" +
  #                   Content-Type + "\n" +
  #                   Content-MD5  + "\n" +
  #                   Date         + "\n" +
  #                   request-uri;
  #
  #
  # If the Date header doesn't exist, one will be generated since
  # Net/HTTP will generate one if it doesn't exist and it will be
  # used on the server side to do authentication.
  #
  class CanonicalString < String # :nodoc:
    include Headers
    
    def initialize(request)
      self << request_method(request) + "\n"
      self << header_values(headers(request)) + "\n"
      self << request_path(request)
    end
    
    private
      def request_method(request)
        if request.respond_to?(:request_method) && request.request_method.is_a?(String)
          request.request_method
        elsif request.respond_to?(:method) && request.method.is_a?(String)
          request.method
        elsif request.respond_to?(:env) && request.env
          request.env['REQUEST_METHOD']
        else
          raise ArgumentError, "Don't know how to get the request method from #{request.inspect}"
        end
      end
      
      def header_values(headers)
        [ content_type(headers),
          content_md5(headers),
          (date(headers) or headers['Date'] = Time.now.getutc.httpdate)
        ].join("\n")
      end
      
      def content_type(headers)
        find_header(%w(CONTENT-TYPE CONTENT_TYPE HTTP_CONTENT_TYPE), headers)
      end
      
      def date(headers)
        find_header(%w(DATE HTTP_DATE), headers)
      end
      
      def content_md5(headers)
        find_header(%w(CONTENT-MD5 CONTENT_MD5), headers)
      end
      
      def request_path(request)
        # Try unparsed_uri in case it is a Webrick request
        path = if request.respond_to?(:unparsed_uri)
          request.unparsed_uri
        else
          request.path
        end
        
        path[/^[^?]*/]
      end
  end
    
  # Integration with Rails
  #
  class Rails # :nodoc:
    module ControllerFilter # :nodoc:
      module ClassMethods
        # Call within a Rails Controller to initialize HMAC authentication for the controller.
        #
        # * +credentials+ must be a hash that indexes secrets by their access key id.
        # * +options+ supports the following arguments:
        #   * +failure_message+: The text to use when authentication fails.
        #   * +only+: A list off actions to protect.
        #   * +except+: A list of actions to not protect.
        #
        def with_auth_hmac(credentials, options = {})
          unless credentials.nil?
            self.credentials = credentials
            self.authhmac = AuthHMAC.new(self.credentials)
            self.authhmac_failure_message = (options.delete(:failure_message) or "HMAC Authentication failed")
            before_filter(:hmac_login_required, options)
          else
            $stderr << "with_auth_hmac called with nil credentials - authentication will be skipped\n"
          end
        end
      end
      
      module InstanceMethods # :nodoc:
        def hmac_login_required          
          unless hmac_authenticated?
            response.headers['WWW-Authenticate'] = 'AuthHMAC'
            render :text => self.class.authhmac_failure_message, :status => :unauthorized
          end
        end
        
        def hmac_authenticated?
          self.class.authhmac.authenticated?(request)
        end
      end
      
      unless defined?(ActionController)
        begin
          require 'rubygems'
          gem 'actionpack'
          gem 'activesupport'
          require 'action_controller'
          require 'active_support'
        rescue
          nil
        end
      end
      
      if defined?(ActionController::Base)        
        ActionController::Base.class_eval do
          class_inheritable_accessor :authhmac
          class_inheritable_accessor :credentials
          class_inheritable_accessor :authhmac_failure_message
        end
        
        ActionController::Base.send(:include, ControllerFilter::InstanceMethods)
        ActionController::Base.extend(ControllerFilter::ClassMethods)
      end
    end
    
    module ActiveResourceExtension  # :nodoc:
      module BaseHmac # :nodoc:
        def self.included(base)
          base.extend(ClassMethods)
          
          base.class_inheritable_accessor :hmac_access_id
          base.class_inheritable_accessor :hmac_secret
          base.class_inheritable_accessor :use_hmac
        end
        
        module ClassMethods
          # Call with an Active Resource class definition to sign
          # all HTTP requests sent by that class with the provided
          # credentials.
          #
          # Can be called with either a hash or two separate parameters
          # like so:
          #
          #   class MyResource < ActiveResource::Base
          #     with_auth_hmac("my_access_id", "my_secret")
          #   end
          # 
          # or
          #
          #   class MyOtherResource < ActiveResource::Base
          #     with_auth_hmac("my_access_id" => "my_secret")
          #   end
          #
          #
          # This has only been tested with Rails 2.1 and since it is virtually a monkey
          # patch of the internals of ActiveResource it might not work with past or
          # future versions.
          #
          def with_auth_hmac(access_id, secret = nil)
            if access_id.is_a?(Hash)
              self.hmac_access_id = access_id.keys.first
              self.hmac_secret = access_id[self.hmac_access_id]
            else
              self.hmac_access_id = access_id
              self.hmac_secret = secret
            end
            self.use_hmac = true
            
            class << self
              alias_method_chain :connection, :hmac
            end
          end
          
          def connection_with_hmac(refresh = false) # :nodoc: 
            c = connection_without_hmac(refresh)
            c.hmac_access_id = self.hmac_access_id
            c.hmac_secret = self.hmac_secret
            c.use_hmac = self.use_hmac
            c
          end          
        end
        
        module InstanceMethods # :nodoc:
        end
      end
      
      module Connection # :nodoc:
        def self.included(base)
          base.send :alias_method_chain, :request, :hmac
          base.class_eval do
            attr_accessor :hmac_secret, :hmac_access_id, :use_hmac
          end
        end

        def request_with_hmac(method, path, *arguments)
          if use_hmac && hmac_access_id && hmac_secret
            arguments.last['Date'] = Time.now.httpdate if arguments.last['Date'].nil?
            temp = "Net::HTTP::#{method.to_s.capitalize}".constantize.new(path, arguments.last)
            AuthHMAC.sign!(temp, hmac_access_id, hmac_secret)
            arguments.last['Authorization'] = temp['Authorization']
          end
          
          request_without_hmac(method, path, *arguments)
        end
      end
            
      unless defined?(ActiveResource)
        begin
          require 'rubygems'
          gem 'activeresource'
          require 'activeresource'
        rescue
          nil
        end
      end
      
      if defined?(ActiveResource)
        ActiveResource::Base.send(:include, BaseHmac)        
        ActiveResource::Connection.send(:include, Connection)
      end     
    end
  end
end
