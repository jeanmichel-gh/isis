# frozen_string_literal: true

source "https://rubygems.org"

# datalink-socket is a path dependency during the PoC, so both repos can
# change together. Once datalink-socket is published, pin a version here.
gem "datalink-socket", path: "../datalink-socket"

group :development, :test do
  gem "minitest", "~> 5.0"
  gem "rake", "~> 13.0"
end
