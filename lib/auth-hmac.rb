# Copyright (c) 2008 The Kaphan Foundation
#
# Possession of a copy of this file grants no permission or license
# to use, modify, or create derivate works.
# Please contact info@peerworks.org for further information.
#

$:.unshift(File.dirname(__FILE__)) unless
  $:.include?(File.dirname(__FILE__)) || $:.include?(File.expand_path(File.dirname(__FILE__)))

# This module provides a HMAC Authentication method for HTTP requests.
#
# It is loosely based on the Amazon Web Services Authentication mechanism but
# generalized to be useful to any application that requires HMAC based authentication.
# As a result of the generalization, it won't work with AWS because it doesn't support
# the Amazon extension headers.
#
module AuthHMAC
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