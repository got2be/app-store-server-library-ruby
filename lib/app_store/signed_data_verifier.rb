# frozen_string_literal: true

require 'openssl'
require 'json'
require 'base64'
require 'jwt'

module AppStore
  class SignedDataVerifier
    ENVIRONMENTS = {
      sandbox: 'Sandbox',
      production: 'Production',
      xcode: 'Xcode',
      local_testing: 'LocalTesting'
    }.freeze
    MAX_SKEW = 60_000

    attr_reader :root_certificates, :bundle_id, :environment, :app_apple_id

    def initialize(root_certificates, environment, bundle_id, app_apple_id = nil)
      @root_certificates = root_certificates.map { |cert| OpenSSL::X509::Certificate.new(cert) }
      @bundle_id = bundle_id
      @environment = environment
      @app_apple_id = app_apple_id
      return unless environment == ENVIRONMENTS[:production] && app_apple_id.nil?

      raise 'app_apple_id is required when the environment is Production'
    end

    def verify_and_decode_transaction(signed_transaction_info)
      decoded_jwt = verify_jwt(signed_transaction_info)
      raise VerificationException, :invalid_app_identifier if decoded_jwt['bundleId'] != bundle_id
      raise VerificationException, :invalid_environment if decoded_jwt['environment'] != environment

      decoded_jwt
    end

    def verify_and_decode_renewal_info(signed_renewal_info)
      decoded_renewal_info = verify_jwt(signed_renewal_info)
      raise VerificationException, :invalid_environment if decoded_renewal_info['environment'] != @environment

      decoded_renewal_info
    end

    def verify_and_decode_notification(signed_payload)
      decoded_jwt = verify_jwt(signed_payload)
      payload = decoded_jwt['data'] || decoded_jwt['summary'] || decoded_jwt['externalPurchaseToken']
      app_apple_id = payload['appAppleId']
      bundle_id = payload['bundleId']
      environment = payload['environment']
      if payload['externalPurchaseId']
        environment = payload['externalPurchaseId']&.start_with?('SANDBOX') ? ENVIRONMENTS[:sandbox] : ENVIRONMENTS[:production]
      end
      verify_notification(bundle_id, app_apple_id, environment)
      decoded_jwt
    end

    def verify_and_decode_app_transaction(signed_app_transaction)
      decoded_app_transaction = verify_jwt(signed_app_transaction) do |t|
        t['receiptCreationDate'].nil? ? Time.now : Time.parse(t['receiptCreationDate'])
      end
      environment = decoded_app_transaction['receiptType']
      if @bundle_id != decoded_app_transaction['bundleId'] || (@environment == :production && @app_apple_id != decoded_app_transaction['appAppleId'])
        raise VerificationException, :invalid_app_identifier
      end
      raise VerificationException, :invalid_environment if @environment != environment

      decoded_app_transaction
    end

    private

    def verify_jwt(jws)
      decoded_jwt = JWT.decode(jws, nil, false)
      payload = decoded_jwt[0]
      chain = decoded_jwt[1]['x5c'] || []
      raise VerificationException, :invalid_chain_length if chain.size != 3

      certificate_chain = chain[0..1].map { |cert| OpenSSL::X509::Certificate.new(Base64.decode64(cert)) }
      effective_date = payload['signedDate'] ? Time.at(payload['signedDate'] / 1000) : Time.current
      public_key = verify_certificate_chain(root_certificates, certificate_chain[0], certificate_chain[1], effective_date)
      JWT.decode(jws, public_key, true, algorithm: 'ES256')

      payload
    rescue JWT::DecodeError, JWT::VerificationError => e
      raise VerificationException, :verification_failure
    end

    def verify_certificate_chain(trusted_roots, leaf, intermediate, effective_date)
      root_cert = trusted_roots.find do |root|
        intermediate.verify(root.public_key) && intermediate.issuer == root.subject
      rescue OpenSSL::X509::CertificateError => _e
        next
      end

      validity = !root_cert.nil?
      validity &&= leaf.verify(intermediate.public_key) && leaf.issuer == intermediate.subject
      validity &&= intermediate.extensions.any? { |ext| ext.oid == 'basicConstraints' && ext.value.start_with?('CA:TRUE') }
      validity &&= leaf.extensions.any? { |ext| ext.oid == '1.2.840.113635.100.6.11.1' }
      validity &&= intermediate.extensions.any? { |ext| ext.oid == '1.2.840.113635.100.6.2.1' }

      raise VerificationException, :verification_failure unless validity

      check_dates(leaf, effective_date)
      check_dates(intermediate, effective_date)
      check_dates(root_cert, effective_date)

      leaf.public_key
    end

    def check_dates(cert, effective_date)
      valid_from = cert.not_before
      valid_to = cert.not_after
      return unless valid_from > effective_date + MAX_SKEW || valid_to < effective_date - MAX_SKEW

      raise VerificationException, :invalid_certificate
    end

    def verify_notification(bundle_id, app_apple_id, environment)
      if @bundle_id != bundle_id || (environment == ENVIRONMENTS[:production] && @app_apple_id != app_apple_id)
        raise VerificationException, :invalid_app_identifier
      end
      raise VerificationException, :invalid_environment if @environment != environment
    end
  end
end
