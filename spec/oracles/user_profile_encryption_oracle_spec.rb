require 'spec_helper'

RSpec.describe CryptoToolbox::Oracles::UserProfileEncryptionOracle do
  let(:sample_email)   { "foo@bar.com" }
  let(:sample_role)    { "guest" }
  let(:sample_uid)     { "10" }
  let(:sample_hash)    { { email: sample_email, uid: sample_uid, role: sample_role } }
  let(:sample_profile) { "email=foo@bar.com&uid=10&role=guest" }
  let(:key)            { "super-secret" }
  let(:aes)            { Ciphers::Aes.new }
  let(:ciphertext)     { aes.encipher_ecb(key,sample_profile) }
  
  it "parses a string" do
    expect(subject.parse_profile(sample_profile)).to eq(sample_hash)
  end

  it "encodes the profile" do
    expect(subject.profile_for(sample_email)).to eq(sample_profile)
  end

  it "encryption and decryption works" do
    plaintext  = aes.decipher_ecb(key,ciphertext).to_crypt_buffer.strip_padding.str
    
    expect(plaintext).to eq(sample_profile)
  end

end
