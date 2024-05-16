# frozen_string_literal: true

module DevelopmentAuth
  module DiscourseConnectExtension
    extend ActiveSupport::Concern

    def sso_url
      if SiteSetting.development_authentication_enabled
        return "#{Discourse.base_path}/development-auth/fake-discourse-connect"
      end
      super
    end
  end
end
