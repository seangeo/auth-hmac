require File.dirname(__FILE__) + '/spec_helper.rb'
require "net/http"
require 'time'
require 'yaml'

describe AuthHMAC do
  describe ".sign!" do
    it "should sign using the key passed in as a parameter" do
      request = Net::HTTP::Put.new("/path/to/put?foo=bar&bar=foo", 
                                    'content-type' => 'text/plain', 
                                    'content-md5' => 'blahblah', 
                                    'date' => "Thu, 10 Jul 2008 03:29:56 GMT")
      AuthHMAC.sign!(request, "my-key-id", "secret")
      request['Authorization'].should == "AuthHMAC my-key-id:71wAJM4IIu/3o6lcqx/tw7XnAJs="
    end
  end
  
  describe "#sign!" do
    before(:each) do
      @store = mock('store')
      @store.stub!(:[]).and_return("")
      @authhmac = AuthHMAC.new(@store)
    end
    
    it "should add an Authorization header" do
      request = Net::HTTP::Get.new("/")
      @authhmac.sign!(request, 'key-id')
      request.key?("Authorization").should be_true
    end
    
    it "should fetch the secret from the store" do
      request = Net::HTTP::Get.new("/")
      @store.should_receive(:[]).with('key-id').and_return('secret')
      @authhmac.sign!(request, 'key-id')
    end
    
    it "should prefix the Authorization Header with AuthHMAC" do
      request = Net::HTTP::Get.new("/")
      @authhmac.sign!(request, 'key-id')
      request['Authorization'].should match(/^AuthHMAC /)
    end
    
    it "should include the key id as the first part of the Authorization header value" do
      request = Net::HTTP::Get.new("/")
      @authhmac.sign!(request, 'key-id')
      request['Authorization'].should match(/^AuthHMAC key-id:/)
    end
    
    it "should include the base64 encoded HMAC signature as the last part of the header value" do
      request = Net::HTTP::Get.new("/path")
      @authhmac.sign!(request, 'key-id')
      request['Authorization'].should match(/:LANuM6GQA23WwIFdfC3IXm60dx4=$/)
    end
    
    it "should create a complete signature" do
      @store.should_receive(:[]).with('my-key-id').and_return('secret')
      request = Net::HTTP::Put.new("/path/to/put?foo=bar&bar=foo", 
                                    'content-type' => 'text/plain', 
                                    'content-md5' => 'blahblah', 
                                    'date' => "Thu, 10 Jul 2008 03:29:56 GMT")
      @authhmac.sign!(request, "my-key-id")
      request['Authorization'].should == "AuthHMAC my-key-id:71wAJM4IIu/3o6lcqx/tw7XnAJs="
    end
  end
  
  describe "#sign! with YAML credentials" do
    before(:each) do
      @authhmac = AuthHMAC.new(YAML.load(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml'))))
      @request = Net::HTTP::Get.new("/path/to/get?foo=bar&bar=foo", 'date' => "Thu, 10 Jul 2008 03:29:56 GMT")
    end
    
    it "should raise an argument error if credentials are missing" do
      lambda { @authhmac.sign!(@request, 'missing') }.should raise_error(ArgumentError)
    end
    
    it "should sign with the secret" do
      @authhmac.sign!(@request, "access key 1")
      @request['Authorization'].should == "AuthHMAC access key 1:ovwO0OBERuF3/uR3aowaUCkFMiE="
    end
    
    it "should sign with the other secret" do
      @authhmac.sign!(@request, "access key 2")
      @request['Authorization'].should == "AuthHMAC access key 2:vT010RQm4IZ6+UCVpK2/N0FLpLw="
    end
  end
  
  describe AuthHMAC::CanonicalString do
    it "should include the http verb when it is GET" do
      request = Net::HTTP::Get.new("/")
      AuthHMAC::CanonicalString.new(request).should match(/GET/)
    end
    
    it "should include the http verb when it is POST" do
      request = Net::HTTP::Post.new("/")
      AuthHMAC::CanonicalString.new(request).should match(/POST/)
    end
    
    it "should include the content-type" do
      request = Net::HTTP::Put.new("/", {'Content-Type' => 'application/xml'})
      AuthHMAC::CanonicalString.new(request).should match(/application\/xml/)
    end
    
    it "should include the content-type even if the case is messed up" do
      request = Net::HTTP::Put.new("/", {'cOntent-type' => 'text/html'})
      AuthHMAC::CanonicalString.new(request).should match(/text\/html/)
    end
    
    it "should include the content-md5" do
      request = Net::HTTP::Put.new("/", {'Content-MD5' => 'skwkend'})
      AuthHMAC::CanonicalString.new(request).should match(/skwkend/)
    end    
    
    it "should include the content-md5 even if the case is messed up" do
      request = Net::HTTP::Put.new("/", {'content-md5' => 'adsada'})
      AuthHMAC::CanonicalString.new(request).should match(/adsada/)
    end
    
    it "should include the date" do
      date = Time.now.httpdate
      request = Net::HTTP::Put.new("/", {'Date' => date})
      AuthHMAC::CanonicalString.new(request).should match(/#{date}/)
    end
    
    it "should include the request path" do
      request = Net::HTTP::Get.new("/path/to/file")
      AuthHMAC::CanonicalString.new(request).should match(/\/path\/to\/file[^?]?/)
    end
    
    it "should ignore the query string of the request path" do
      request = Net::HTTP::Get.new("/other/path/to/file?query=foo")
      AuthHMAC::CanonicalString.new(request).should match(/\/other\/path\/to\/file[^?]?/)
    end
    
    it "should build the correct string" do
      date = Time.now.httpdate
      request = Net::HTTP::Put.new("/path/to/put?foo=bar&bar=foo", 
                                    'content-type' => 'text/plain', 
                                    'content-md5' => 'blahblah', 
                                    'date' => date)
      AuthHMAC::CanonicalString.new(request).should == "PUT\ntext/plain\nblahblah\n#{date}\n/path/to/put"                                            
    end
    
    it "should build the correct string when some elements are missing" do
      date = Time.now.httpdate
      request = Net::HTTP::Get.new("/path/to/get?foo=bar&bar=foo",
                                    'date' => date)
      AuthHMAC::CanonicalString.new(request).should == "GET\n\n\n#{date}\n/path/to/get"
    end
  end
end
