# Copyright (c) 2008 The Kaphan Foundation
#
# Possession of a copy of this file grants no permission or license
# to use, modify, or create derivate works.
# Please contact info@peerworks.org for further information.
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
  
  private
    def build_authorization_header(request, access_key_id, secret)
      "AuthHMAC #{access_key_id}:#{build_signature(request, secret)}"      
    end
    
    def build_signature(request, secret)
      digest = OpenSSL::Digest::Digest.new('sha1')
      Base64.encode64(OpenSSL::HMAC.digest(digest, secret, CanonicalString.new(request))).strip
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
  class CanonicalString < String
    def initialize(request)
      self << request.method + "\n"
      self << header_values(request) + "\n"
      self << request_path(request)
    end
    
    private
      def header_values(request)
        [ request.content_type, 
          request['content-md5'], 
          request['date']
        ].join("\n")
      end
      
      def request_path(request)
        request.path[/^[^?]*/]
      end
  end
end