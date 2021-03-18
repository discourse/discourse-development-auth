# frozen_string_literal: true

# name: discourse-development-auth
# about: A fake authentication provider for development puposes only
# version: 1.0
# authors: David Taylor
# url: https://github.com/discourse/discourse-development-auth

raise "discourse-development-auth is highly insecure and should not be installed in production" if Rails.env.production?

enabled_site_setting :development_authentication_enabled

module ::OmniAuth
  module Strategies
    class Development
      include ::OmniAuth::Strategy

      FIELDS = %w{
        uid
        name
        email
        email_verified
        nickname
        first_name
        last_name
        location
        description
        image
      }

      COOKIE = "development-auth-defaults"

      def request_phase
        return fail!("DISCOURSE_DEV_ALLOW_ANON_TO_IMPERSONATE must equal 1 to use this plugin") if ENV['DISCOURSE_DEV_ALLOW_ANON_TO_IMPERSONATE'] != "1"
        if (env['REQUEST_METHOD'] == 'POST') && (request.params['uid'])
          data = request.params.slice(*FIELDS)

          r = Rack::Response.new
          r.set_cookie(COOKIE, {value: data.to_json, path: "/", expires: 1.month.from_now})

          uri = URI.parse(callback_path)
          uri.query = URI.encode_www_form(data)
          r.redirect(uri)

          return r.finish
        end

        build_form.to_response
      end

      def build_form
        token = begin
          verifier = CSRFTokenVerifier.new
          verifier.call(env)
          verifier.form_authenticity_token
        end

        request = Rack::Request.new(env)
        raw_defaults = request.cookies[COOKIE] || "{}"
        defaults = JSON.parse(raw_defaults) rescue {}
        defaults["uid"] = SecureRandom.hex(8) unless defaults["uid"].present?
        defaults["email_verified"] = "true" unless defaults["email_verified"].present?

        OmniAuth::Form.build(:title => "Fake Authentication Provider") do
          html "\n<input type='hidden' name='authenticity_token' value='#{token}'/>"

          FIELDS.each do |f|
            label_field(f, f)
            if f == "email_verified"
              html "<input type='checkbox' id='#{f}' name='#{f}' value='true' #{"checked" if defaults[f] == "true"}/>"
            else
              html "<input type='text' id='#{f}' name='#{f}' value='#{defaults[f]}'/>"
            end
          end
        end
      end

      def callback_phase
        return fail!("DISCOURSE_DEV_ALLOW_ANON_TO_IMPERSONATE must equal 1 to use this plugin") if ENV['DISCOURSE_DEV_ALLOW_ANON_TO_IMPERSONATE'] != "1"
        super
      end

      def auth_hash
        info = request.params.slice(*FIELDS)
        uid = info.delete("uid")
        email_verified = (info.delete("email_verified") == "true")
        OmniAuth::Utils.deep_merge(super, {
          'uid' => uid,
          'info' => info,
          'extra' => { "raw_info" => { "email_verified" => email_verified } }
        })
      end
    end
  end
end

class DevelopmentAuthenticator < Auth::ManagedAuthenticator
  def name
    'developmentauth'
  end

  def can_revoke?
    true
  end

  def can_connect_existing_user?
    true
  end

  def enabled?
    SiteSetting.development_authentication_enabled
  end

  def register_middleware(omniauth)
    omniauth.provider :development, name: :developmentauth
  end

  def primary_email_verified?(auth)
    auth['extra']['raw_info']['email_verified']
  end
end

auth_provider authenticator: DevelopmentAuthenticator.new
