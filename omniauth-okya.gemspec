# frozen_string_literal: true

require_relative "lib/omniauth-okya/version"

Gem::Specification.new do |spec|
  spec.name = "omniauth-okya"
  spec.version = OmniAuth::Okya::VERSION
  spec.authors = ["Htoo"]
  spec.email = ["htooeainlwin12@gmail.com"]
  spec.homepage = "https://github.com/htoo-eain-lwin/omniauth-okya"
  spec.summary = "OmniAuth OAuth2 strategy for the Okya."
  spec.description = "OmniAuth OAuth2 strategy for the Okya."

  spec.required_ruby_version = ">= 3.3.3"

  spec.require_paths = ["lib"]
  spec.add_runtime_dependency "omniauth"
  spec.add_runtime_dependency "omniauth-oauth2"

  spec.add_development_dependency "bundler"
  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
