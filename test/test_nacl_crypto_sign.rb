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

  def test_with_empty_message
    message = ""
    crypted = NaCl.crypto_sign(message, @sec)
    assert_equal message, NaCl.crypto_sign_open(crypted, @pub)
  end

  def test_with_invalid_arguments
    assert_raise(ArgumentError) do
      NaCl.crypto_sign("message", "invalid seckey")
    end
    assert_raise(ArgumentError) do
      NaCl.crypto_sign_open("message", "invalid pubkey")
    end
  end

  def test_open_with_empty_message
    assert_raise(NaCl::OpenError) do
      NaCl.crypto_sign_open("", @pub)
    end
  end

  def test_open_with_changed_signedtext
    signed = NaCl.crypto_sign("This is a test message", @sec)
    mangled = signed.gsub("test message", "best message")
    assert_not_equal signed, mangled
    assert_raise(NaCl::OpenError) do
      NaCl.crypto_sign_open(mangled, @pub)
    end
  end
end

