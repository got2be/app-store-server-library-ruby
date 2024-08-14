# frozen_string_literal: true

module AppStore
  module VerificationStatus
    OK = :ok
    VERIFICATION_FAILURE = :verification_failure
    INVALID_APP_IDENTIFIER = :invalid_app_identifier
    INVALID_ENVIRONMENT = :invalid_environment
    INVALID_CHAIN_LENGTH = :invalid_chain_length
    INVALID_CERTIFICATE = :invalid_certificate
    FAILURE = :failure
  end
end
