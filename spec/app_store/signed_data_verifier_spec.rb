require 'spec_helper'

describe AppStore::SignedDataVerifier do
  describe '#ENVIRONMENTS' do
    subject { described_class::ENVIRONMENTS }

    it 'returns a hash with the environments' do
      expect(subject).to eq({
        sandbox: 'Sandbox',
        production: 'Production',
        xcode: 'Xcode',
        local_testing: 'LocalTesting'
      })
    end
  end

  let(:root_certificate) { OpenSSL::X509::Certificate.new(File.read('spec/fixtures/root_cert.pem')) }
  let(:intermediate_certificate) { OpenSSL::X509::Certificate.new(File.read('spec/fixtures/intermediate_cert.pem')) }
  let(:leaf_certificate) { OpenSSL::X509::Certificate.new(File.read('spec/fixtures/leaf_cert.pem')) }
  let(:root_certificates) { [root_certificate.to_pem] }
  let(:bundle_id) { 'com.example.app' }
  let(:environment) { 'Sandbox' }
  let(:app_apple_id) { '123456789' }
  let(:signed_transaction_info) { 'signed_jwt_here' }
  let(:signed_renewal_info) { 'signed_jwt_here' }
  let(:signed_payload) { 'signed_jwt_here' }
  let(:signed_app_transaction) { 'signed_jwt_here' }
  let(:instance) { described_class.new(root_certificates, environment, bundle_id, app_apple_id) }

  describe '#initialize' do
    subject { instance }

    context 'app_apple_id is not provided' do
      let(:app_apple_id) { nil }

      context 'when environment is production' do
        let(:environment) { 'Production' }

        it 'raises an error' do
          expect { subject }.to raise_error(StandardError, 'app_apple_id is required when the environment is Production')
        end
      end

      context 'when environment is not production' do
        let(:environment) { 'Sandbox' }

        it 'does not raise an error' do
          expect { subject }.not_to raise_error
        end
      end
    end
  end

  describe '#verify_and_decode_transaction' do
    subject { instance.verify_and_decode_transaction(signed_transaction_info) }

    it 'raises an error if the bundleId does not match' do
      allow(instance).to receive(:verify_jwt).and_return({ 'bundleId' => 'wrong_bundle_id', 'environment' => environment })
      expect { subject }.to raise_error(AppStore::VerificationException, 'invalid_app_identifier')
    end

    it 'raises an error if the environment does not match' do
      allow(instance).to receive(:verify_jwt).and_return({ 'bundleId' => bundle_id, 'environment' => 'wrong_environment' })
      expect { subject }.to raise_error(AppStore::VerificationException, 'invalid_environment')
    end

    it 'returns the decoded JWT if verification passes' do
      decoded_jwt = { 'bundleId' => bundle_id, 'environment' => environment }
      allow(instance).to receive(:verify_jwt).and_return(decoded_jwt)
      expect(subject).to eq(decoded_jwt)
    end
  end

  describe '#verify_and_decode_renewal_info' do
    subject { instance.verify_and_decode_renewal_info(signed_renewal_info) }

    it 'raises an error if the environment does not match' do
      allow(instance).to receive(:verify_jwt).and_return({ 'environment' => 'wrong_environment' })
      expect { subject }.to raise_error(AppStore::VerificationException, 'invalid_environment')
    end

    it 'returns the decoded renewal info if verification passes' do
      decoded_renewal_info = { 'environment' => environment }
      allow(instance).to receive(:verify_jwt).and_return(decoded_renewal_info)
      expect(subject).to eq(decoded_renewal_info)
    end
  end

  describe '#verify_and_decode_notification' do
    subject { instance.verify_and_decode_notification(signed_payload) }

    it 'raises an error if the bundleId or appAppleId do not match' do
      allow(instance).to receive(:verify_jwt).and_return({ 'data' => { 'bundleId' => 'wrong_bundle_id', 'appAppleId' => app_apple_id } })
      expect { subject }.to raise_error(AppStore::VerificationException, 'invalid_app_identifier')
    end

    context 'when the environment does not match' do
      let(:environment) { 'Production' }

      it 'raises an error if the environment' do
        allow(instance).to receive(:verify_jwt).and_return({ 'data' => { 'bundleId' => bundle_id, 'appAppleId' => app_apple_id }, 'externalPurchaseToken' => { 'externalPurchaseId' => 'SANDBOX-123' } })
        expect { subject }.to raise_error(AppStore::VerificationException, 'invalid_environment')
      end
    end

    it 'returns the decoded JWT if verification passes' do
      decoded_jwt = { 'data' => { 'bundleId' => bundle_id, 'appAppleId' => app_apple_id }, 'externalPurchaseToken' => { 'externalPurchaseId' => 'SANDBOX-123' } }
      allow(instance).to receive(:verify_jwt).and_return(decoded_jwt)
      expect(subject).to eq(decoded_jwt)
    end
  end

  describe '#verify_and_decode_app_transaction' do
    subject { instance.verify_and_decode_app_transaction(signed_app_transaction) }

    it 'raises an error if the bundleId or appAppleId do not match' do
      allow(instance).to receive(:verify_jwt).and_return({ 'bundleId' => 'wrong_bundle_id', 'appAppleId' => 'wrong_app_apple_id', 'receiptType' => environment })
      expect { subject }.to raise_error(AppStore::VerificationException, 'invalid_app_identifier')
    end

    it 'raises an error if the environment does not match' do
      allow(instance).to receive(:verify_jwt).and_return({ 'bundleId' => bundle_id, 'appAppleId' => app_apple_id, 'receiptType' => 'wrong_environment' })
      expect { subject }.to raise_error(AppStore::VerificationException, 'invalid_environment')
    end

    it 'returns the decoded app transaction if verification passes' do
      decoded_app_transaction = { 'bundleId' => bundle_id, 'appAppleId' => app_apple_id, 'receiptType' => environment }
      allow(instance).to receive(:verify_jwt).and_return(decoded_app_transaction)
      expect(subject).to eq(decoded_app_transaction)
    end
  end
end
