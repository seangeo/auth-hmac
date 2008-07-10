require File.dirname(__FILE__) + '/spec_helper.rb'
require "net/http"
require 'time'

include AuthHMAC
describe AuthHMAC do
  
  describe CanonicalString do
    it "should include the http verb when it is GET" do
      request = Net::HTTP::Get.new("/")
      CanonicalString.new(request).should match(/GET/)
    end
    
    it "should include the http verb when it is POST" do
      request = Net::HTTP::Post.new("/")
      CanonicalString.new(request).should match(/POST/)
    end
    
    it "should include the content-type" do
      request = Net::HTTP::Put.new("/", {'Content-Type' => 'application/xml'})
      CanonicalString.new(request).should match(/application\/xml/)
    end
    
    it "should include the content-type even if the case is messed up" do
      request = Net::HTTP::Put.new("/", {'cOntent-type' => 'text/html'})
      CanonicalString.new(request).should match(/text\/html/)
    end
    
    it "should include the content-md5" do
      request = Net::HTTP::Put.new("/", {'Content-MD5' => 'skwkend'})
      CanonicalString.new(request).should match(/skwkend/)
    end    
    
    it "should include the content-md5 even if the case is messed up" do
      request = Net::HTTP::Put.new("/", {'content-md5' => 'adsada'})
      CanonicalString.new(request).should match(/adsada/)
    end
    
    it "should include the date" do
      date = Time.now.httpdate
      request = Net::HTTP::Put.new("/", {'Date' => date})
      CanonicalString.new(request).should match(/#{date}/)
    end
    
    it "should include the request path" do
      request = Net::HTTP::Get.new("/path/to/file")
      CanonicalString.new(request).should match(/\/path\/to\/file[^?]?/)
    end
    
    it "should ignore the query string of the request path" do
      request = Net::HTTP::Get.new("/other/path/to/file?query=foo")
      CanonicalString.new(request).should match(/\/other\/path\/to\/file[^?]?/)
    end
    
    it "should build the correct string" do
      date = Time.now.httpdate
      request = Net::HTTP::Put.new("/path/to/put?foo=bar&bar=foo", 
                                    'content-type' => 'text/plain', 
                                    'content-md5' => 'blahblah', 
                                    'date' => date)
      CanonicalString.new(request).should == "PUT\ntext/plain\nblahblah\n#{date}\n/path/to/put"                                            
    end
    
    it "should build the correct string when some elements are missing" do
      date = Time.now.httpdate
      request = Net::HTTP::Get.new("/path/to/get?foo=bar&bar=foo",
                                    'date' => date)
      CanonicalString.new(request).should == "GET\n\n\n#{date}\n/path/to/get"
    end
  end
end
