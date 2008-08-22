require File.dirname(__FILE__) + '/spec_helper.rb'
require "net/http"
require 'time'
require 'yaml'
require 'rubygems'
gem 'actionpack'
gem 'activeresource'
require 'action_controller'
require 'action_controller/test_process'
require 'active_resource'
require 'active_resource/http_mock'

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
      request['Authorization'].should match(/:[A-Za-z0-9+\/]{26,28}[=]{0,2}$/)
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
  
  describe "authenticated?" do
    before(:each) do
      @authhmac = AuthHMAC.new(YAML.load(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml'))))
      @request = Net::HTTP::Get.new("/path/to/get?foo=bar&bar=foo", 'date' => "Thu, 10 Jul 2008 03:29:56 GMT")
    end
    
    it "should return false when there is no Authoization Header" do
      @authhmac.authenticated?(@request).should be_false
    end
    
    it "should return false when the Authorization value isn't prefixed with HMAC" do
      @request['Authorization'] = "id:secret"
      @authhmac.authenticated?(@request).should be_false
    end
    
    it "should return false when the access key id can't be found" do
      @request['Authorization'] = 'AuthHMAC missing-key:blah'
      @authhmac.authenticated?(@request).should be_false
    end    
    
    it "should return false when there is no hmac" do
      @request['Authorization'] = 'AuthHMAC missing-key:'
      @authhmac.authenticated?(@request).should be_false
    end
    
    it "should return false when the hmac doesn't match" do
      @request['Authorization'] = 'AuthHMAC access key 1:blah'
      @authhmac.authenticated?(@request).should be_false
    end
    
    it "should return false if the request was modified after signing" do
      @authhmac.sign!(@request, 'access key 1')
      @request.content_type = 'text/plain'
      @authhmac.authenticated?(@request).should be_false
    end
    
    it "should return true when the hmac does match" do
      @authhmac.sign!(@request, 'access key 1')
      @authhmac.authenticated?(@request).should be_true
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
  
  describe AuthHMAC::Rails::ControllerFilter do
    class TestController < ActionController::Base
      with_auth_hmac YAML.load(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml'))),
        :only => [:index]
      
      def index
        render :nothing => true, :status => :ok
      end
      
      def public
        render :nothing => true, :status => :ok
      end
      
      def rescue_action(e) raise(e) end
    end
    
    class MessageTestController < ActionController::Base
      with_auth_hmac YAML.load(File.read(File.join(File.dirname(__FILE__), 'fixtures', 'credentials.yml'))),
                      :failure_message => "Stay away!", :except => :public
      
      def index
        render :nothing => true, :status => :ok
      end
      
      def public
        render :nothing => true, :status => :ok
      end
      
      def rescue_action(e) raise(e) end
    end
    
    class NilCredentialsController < ActionController::Base
      with_auth_hmac nil
      before_filter :force_auth
      
      def index
        render :nothing => true, :status => :ok
      end
      
      def public
        render :nothing => true, :status => :ok
      end
      
      def rescue_action(e) raise(e) end
        
      private
      def force_auth
        hmac_authenticated?
      end
    end
    
    it "should not raise an error when credentials are nil" do
      request = ActionController::TestRequest.new
      request.action = 'index'
      request.path = "/index"
      lambda do
        NilCredentialsController.new.process(request, ActionController::TestResponse.new).code.should == "200"
      end.should_not raise_error
    end
    
    it "should allow a request with the proper hmac" do
      request = ActionController::TestRequest.new
      request.env['Authorization'] = "AuthHMAC access key 1:6BVEVfAyIDoI3K+WallRMnDxROQ="
      request.env['DATE'] = "Thu, 10 Jul 2008 03:29:56 GMT"
      request.action = 'index'
      request.path = "/index"
      TestController.new.process(request, ActionController::TestResponse.new).code.should == "200"
    end
    
    it "should reject a request with no hmac" do
      request = ActionController::TestRequest.new
      request.action = 'index'
      TestController.new.process(request, ActionController::TestResponse.new).code.should == "401"
    end
    
    it "should reject a request with the wrong hmac" do
      request = ActionController::TestRequest.new
      request.action = 'index'
      request.env['Authorization'] = "AuthHMAC bogus:bogus"
      TestController.new.process(request, ActionController::TestResponse.new).code.should == "401"
    end
    
    it "should include a WWW-Authenticate header with the schema AuthHMAC" do
      request = ActionController::TestRequest.new
      request.action = 'index'
      request.env['Authorization'] = "AuthHMAC bogus:bogus"
      TestController.new.process(request, ActionController::TestResponse.new).headers['WWW-Authenticate'].should == "AuthHMAC"
    end
    
    it "should include a default error message" do
      request = ActionController::TestRequest.new
      request.action = 'index'
      request.env['Authorization'] = "AuthHMAC bogus:bogus"
      TestController.new.process(request, ActionController::TestResponse.new).body.should == "HMAC Authentication failed"
    end
    
    it "should reject a request with a given message" do
      request = ActionController::TestRequest.new
      request.action = 'index'
      request.env['Authorization'] = "AuthHMAC bogus:bogus"
      MessageTestController.new.process(request, ActionController::TestResponse.new).body.should == "Stay away!"
    end
    
    it "should allow anything to access the public action (using only)" do
      request = ActionController::TestRequest.new
      request.action = 'public'
      TestController.new.process(request, ActionController::TestResponse.new).code.should == "200"
    end
    
    it "should allow anything to access the public action (using except)" do
      request = ActionController::TestRequest.new
      request.action = 'public'
      MessageTestController.new.process(request, ActionController::TestResponse.new).code.should == "200"
    end
  end
  
  describe AuthHMAC::Rails::ActiveResourceExtension do
    class TestResource < ActiveResource::Base
      with_auth_hmac("access_id", "secret")
      self.site = "http://localhost/"
    end
        
    it "should send requests using HMAC authentication" do
      now = Time.parse("Thu, 10 Jul 2008 03:29:56 GMT")
      Time.should_receive(:now).at_least(1).and_return(now)
      ActiveResource::HttpMock.respond_to do |mock|
        mock.get "/test_resources/1.xml", 
                    {'Authorization' => 'AuthHMAC access_id:n8UlshMa8ve66U36XD3ZCbAIctg=', 'Content-Type' => 'application/xml', 'Date' => "Thu, 10 Jul 2008 03:29:56 GMT" },
                    {:id => "1"}.to_xml(:root => 'test_resource')
      end
      
      TestResource.find(1)
    end
  end
end
