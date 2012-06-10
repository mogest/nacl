require 'test/unit'
require 'nacl'

class TestNaclCryptoSecretBox < Test::Unit::TestCase
  def setup
    @key = ""
    NaCl::SECRETBOX_KEY_LENGTH.times { @key << Random.rand(256).chr }
    @nonce = "X" * NaCl::SECRETBOX_NONCE_LENGTH
  end

  def test_with_normal_message
    message = "This is a test message."
    crypted = NaCl.crypto_secretbox(message, @nonce, @key)
    assert_equal message, NaCl.crypto_secretbox_open(crypted, @nonce, @key)
  end

  def test_with_blank_message
    message = ""
    crypted = NaCl.crypto_secretbox(message, @nonce, @key)
    assert crypted.length >= 16
    assert_equal message, NaCl.crypto_secretbox_open(crypted, @nonce, @key)
  end

  def test_with_long_message
    message = "Test message\0" * 100
    crypted = NaCl.crypto_secretbox(message, @nonce, @key)
    assert_equal message, NaCl.crypto_secretbox_open(crypted, @nonce, @key)
  end

  def test_with_invalid_arguments
    assert_raise(ArgumentError) do
      NaCl.crypto_box("test message", "invalid nonce", @key)
    end
    assert_raise(ArgumentError) do
      NaCl.crypto_box("test message", @nonce, "invalid key")
    end
    assert_raise(ArgumentError) do
      NaCl.crypto_box_open("", @nonce, @key)
    end
  end

  def test_open_with_changed_ciphertext
    crypted = NaCl.crypto_secretbox("This is a test message", @nonce, @key)
    char = crypted[14..14]
    char = char == "\0" ? "\1" : "\0"
    mangled = "#{crypted[0..13]}#{char}#{crypted[15..-1]}"
    assert_not_equal crypted, mangled
    assert_raise(NaCl::OpenError) do
      NaCl.crypto_secretbox_open(mangled, @nonce, @key)
    end
  end

  def test_constants
    assert_equal 24, NaCl::SECRETBOX_NONCE_LENGTH
    assert_equal 32, NaCl::SECRETBOX_KEY_LENGTH
  end
end
