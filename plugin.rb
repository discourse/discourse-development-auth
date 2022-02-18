# frozen_string_literal: true

# name: discourse-development-auth
# about: A fake authentication provider for development puposes only
# version: 1.0
# authors: David Taylor
# url: https://github.com/discourse/discourse-development-auth

raise "discourse-development-auth is highly insecure and should not be installed in production" if Rails.env.production?

enabled_site_setting :development_authentication_enabled

PLUGIN_NAME = "discourse-development-auth"

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
        groups
      }

      COOKIE = "development-auth-defaults"

      def request_phase
        return fail!("DISCOURSE_DEV_ALLOW_ANON_TO_IMPERSONATE must equal 1 to use this plugin") if ENV['DISCOURSE_DEV_ALLOW_ANON_TO_IMPERSONATE'] != "1"
        if (env['REQUEST_METHOD'] == 'POST') && (request.params['uid'])
          data = request.params.slice(*FIELDS)

          r = Rack::Response.new
          r.set_cookie(COOKIE, { value: data.to_json, path: "/", expires: 1.month.from_now })

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

        OmniAuth::Form.build(title: "Fake Authentication Provider") do
          html "\n<input type='hidden' name='authenticity_token' value='#{token}'/>"

          FIELDS.each do |f|
            label_field(f, f)
            if f == "email_verified"
              html "<input type='checkbox' id='#{f}' name='#{f}' value='true' #{"checked" if defaults[f] == "true"}/>"
            elsif f == "groups"
              html "<input type='text' id='#{f}' name='#{f}' value='#{defaults[f]}' placeholder='id1:group1,id2:group2...'/>"
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
        groups = info.delete("groups")&.split(",").map do |g|
          id, name = g.split(":", 2)
          { id: id, name: name }
        end
        OmniAuth::Utils.deep_merge(super, {
          'uid' => uid,
          'info' => info,
          'extra' => { "raw_info" => { "email_verified" => email_verified }, "raw_groups" => groups }
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

  def after_authenticate(auth_token, existing_account: nil)
    result = super
    if provides_groups? && (groups = auth_token[:extra][:raw_groups]).any?
      result.associated_groups = groups.map { |group| group.slice(:id, :name) }
    end
    result
  end

  def provides_groups?
    SiteSetting.development_authentication_provides_groups
  end
end

auth_provider authenticator: DevelopmentAuthenticator.new


### DiscourseConnect
after_initialize do
  module ::DevelopmentAuth
    class Engine < ::Rails::Engine
      engine_name PLUGIN_NAME
      isolate_namespace ::DevelopmentAuth
    end
  end

  class ::DevelopmentAuth::FakeDiscourseConnectController < ::ApplicationController
    requires_plugin "discourse-development-auth"

    skip_before_action :check_xhr, :preload_json, :redirect_to_login_if_required, :verify_authenticity_token

    SIMPLE_FIELDS = %w{
      external_id
      email
      username
      name
    }
    ADVANCED_FIELDS = DiscourseConnectBase::ACCESSORS.map(&:to_s) - SIMPLE_FIELDS
    CUSTOM_FIELDS = ::UserField.all.pluck(:id, :name)&.map{|id, name| {"#{name}": "custom.user_field_#{id}"}}&.reduce(:merge!) || {}
    FIELDS = SIMPLE_FIELDS + ADVANCED_FIELDS + CUSTOM_FIELDS.values

    BOOLS = DiscourseConnectBase::BOOLS.map(&:to_s)

    COOKIE = "development-auth-discourseconnect-defaults"

    def auth
      raise "DISCOURSE_DEV_ALLOW_ANON_TO_IMPERSONATE must equal 1 to use this plugin" if ENV['DISCOURSE_DEV_ALLOW_ANON_TO_IMPERSONATE'] != "1"

      params.require(:sso)
      @payload = request.query_string
      sso = DiscourseConnectBase.parse(@payload, SiteSetting.discourse_connect_secret)

      if request.method == "POST" && params[:external_id]
        data = {}
        FIELDS.each do |f|
          if field = f.to_s[/^custom\.(.+)$/, 1]
            sso.custom_fields[field] = params[f]
          else
            sso.send(:"#{f}=", params[f])
          end
          data[f] = params[f]
          cookies[COOKIE] = { value: data.to_json, path: "/", expires: 1.month.from_now }
        end

        return redirect_to sso.to_url(sso.return_sso_url)
      end

      raw_defaults = cookies[COOKIE] || "{}"
      @defaults = JSON.parse(raw_defaults) rescue {}
      @defaults["return_sso_url"] = sso.return_sso_url
      @defaults["nonce"] = sso.nonce
      @defaults["external_id"] = SecureRandom.hex(8) unless @defaults["external_id"].present?
      render_form
    end

    private

    def render_form
      @simple_fields = SIMPLE_FIELDS
      @advanced_fields = ADVANCED_FIELDS
      @custom_fields = CUSTOM_FIELDS
      @bools = BOOLS
      append_view_path(File.expand_path("../app/views", __FILE__))
      render template: "fake_discourse_connect/form", layout: false
    end
  end 

  DevelopmentAuth::Engine.routes.draw do
    get "/fake-discourse-connect" => "fake_discourse_connect#auth"
    post "/fake-discourse-connect" => "fake_discourse_connect#auth"
  end

  Discourse::Application.routes.append do
    mount ::DevelopmentAuth::Engine, at: "/development-auth"
  end

  DiscourseConnect.singleton_class.prepend(Module.new do
    def sso_url
      if SiteSetting.development_authentication_enabled
        return "#{Discourse.base_path}/development-auth/fake-discourse-connect"
      end
      super
    end
  end)

  EnableSsoValidator.prepend(Module.new do
    def valid_value?(val)
      return true if SiteSetting.development_authentication_enabled
      super
    end
  end)
end
