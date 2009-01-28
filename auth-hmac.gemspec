# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{auth-hmac}
  s.version = "1.0.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Sean Geoghegan"]
  s.date = %q{2009-01-27}
  s.description = %q{A gem providing HMAC based authentication for HTTP}
  s.email = ["seangeo@gmail.com"]
  s.extra_rdoc_files = ["History.txt", "License.txt", "Manifest.txt", "PostInstall.txt", "README.txt"]
  s.files = ["History.txt", "License.txt", "Manifest.txt", "PostInstall.txt", "README.txt", "Rakefile", "config/hoe.rb", "config/requirements.rb", "lib/auth-hmac.rb", "lib/auth-hmac/version.rb", "script/console", "script/destroy", "script/generate", "setup.rb", "spec/auth-hmac_spec.rb", "spec/spec.opts", "spec/spec_helper.rb", "tasks/deployment.rake", "tasks/environment.rake", "tasks/rspec.rake", "tasks/website.rake"]
  s.has_rdoc = true
  s.homepage = %q{http://auth-hmac.rubyforge.org}
  s.post_install_message = %q{
For more information on auth-hmac, see http://auth-hmac.rubyforge.org

NOTE: Change this information in PostInstall.txt 
You can also delete it if you don't want it.


}
  s.rdoc_options = ["--main", "README.rdoc"]
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{auth-hmac}
  s.rubygems_version = %q{1.3.1}
  s.summary = %q{A gem providing HMAC based authentication for HTTP}

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 2

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<hoe>, [">= 1.8.0"])
    else
      s.add_dependency(%q<hoe>, [">= 1.8.0"])
    end
  else
    s.add_dependency(%q<hoe>, [">= 1.8.0"])
  end
end
