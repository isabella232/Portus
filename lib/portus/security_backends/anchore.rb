# frozen_string_literal: true

require "portus/security_backends/base"

module Portus
  module SecurityBackend
    # Dummy implements a backend that simply returns fixture data. This backend
    # is meant to be used only for development/testing purposes.
    class Anchore < ::Portus::SecurityBackend::Base

      def initialize(repo, tag, digest)
        super(repo, tag, digest)
        @username = APP_CONFIG["security"]["anchore"]["username"]
        @password = APP_CONFIG["security"]["anchore"]["password"]
      end

      def vulnerabilities(params)

        @registry_url = params[:registry_url]

        # Now we fetch the vulnerabilities discovered by Anchore on that digest.
        uri, req = get_request("/v1/images/#{@digest}/vuln/all", "get")
        req["Accept"] = "application/json"
        req.basic_auth(@username, @password)
        begin
          res = get_response_token(uri, req)
        rescue *::Portus::Errors::NET => e
          Rails.logger.tagged("anchore.get") { Rails.logger.debug e.message }
          return
        end

        # Parse the given response and return the result.
        if res.code.to_i == 200
          msg = JSON.parse(res.body)
          Rails.logger.tagged("anchore.get") { Rails.logger.debug msg }
          vulnerabilities = msg["vulnerabilities"]
          print("anchore vulnerabilities: ", vulnerabilities, "\n")
          vulnerabilities.map do |v|
            { "Name" => v["vuln"], "Link" => v["url"], "Severity" => v["severity"] }
          end

        elsif res.code.to_i == 404
          uri, req = get_request("/v1/images", "post")
          req["Accept"] = "application/json"
          req["Content-Type"] = "application/json"
          req.basic_auth(@username, @password)
          req.body = {tag: "registry:5000/#{@repo}:#{@tag}"}.to_json
          begin
            res = get_response_token(uri, req)
            handle_response(res, @digest, "anchore.post")
            return
          rescue *::Portus::Errors::NET => e
            Rails.logger.tagged("anchore.post") { Rails.logger.debug e.message }
            return
          end
        else
          handle_response(res, @digest, "anchore.get")
        end
      end

      def self.config_key
        "anchore"
      end

      def handle_response(response, digest, kind)
        code = response.code.to_i
        Rails.logger.tagged(kind) { Rails.logger.debug "Handling code: #{code}" }
        return if code == 200 || code == 201

        msg = response.body
        Rails.logger.tagged(kind) do
          Rails.logger.debug "Could not post '#{digest}': #{msg}"
        end

        nil
      end
    end
  end
end
