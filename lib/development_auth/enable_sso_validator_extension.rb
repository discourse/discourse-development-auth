# frozen_string_literal: true

module DevelopmentAuth
  module EnableSsoValidatorExtension
    extend ActiveSupport::Concern

    def valid_value?(val)
      return true if SiteSetting.development_authentication_enabled
      super
    end
  end
end
