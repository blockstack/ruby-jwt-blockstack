# encoding: utf-8
# frozen_string_literal: true

# Moments version builder module
module JWTB
  def self.gem_version
    Gem::Version.new VERSION::STRING
  end

  # Moments version builder module
  module VERSION
    # major version
    MAJOR = 2
    # minor version
    MINOR = 0
    # tiny version
    TINY  = 0
    # alpha, beta, etc. tag
    PRE   = 'beta2.bsk1'.freeze

    # Build version string
    STRING = [MAJOR, MINOR, TINY, PRE].compact.join('.')
  end
end
