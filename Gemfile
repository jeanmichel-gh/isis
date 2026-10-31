# frozen_string_literal: true

source "https://rubygems.org"

gemspec

# The gemspec depends on datalink-socket ~> 1.0. During development this
# overrides it with the sibling checkout, so both repos can change together.
gem "datalink-socket", path: "../datalink-socket"

group :development, :test do
  gem "minitest", "~> 5.0"
  gem "rake", "~> 13.0"
end
