require 'test/unit'
require 'nacl'

class TestNaclCryptoSign < Test::Unit::TestCase
  def setup
    @pub, @sec = NaCl.crypto_sign_keypair
  end

  def test_crypto_sign_keypair
    result = NaCl.crypto_sign_keypair
    assert_equal 2, result.length
    assert_equal 32, result[0].length
    assert_equal 64, result[1].length
  end

  def test_with_normal_message
    message = "This is a test message."
    crypted = NaCl.crypto_sign(message, @sec)
    assert_equal message, NaCl.crypto_sign_open(crypted, @pub)
  end
end

