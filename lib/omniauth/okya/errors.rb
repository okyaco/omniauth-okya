# frozen_string_literal: true

module OmniAuth
  module Okya
    class TokenValidationError < StandardError
      attr_reader :error_reason

      def initialize(msg)
        @error_reason = msg
        super
      end
    end
  end
end
