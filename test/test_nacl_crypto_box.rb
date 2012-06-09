require 'test/unit'
require 'nacl'

class TestNaclCryptoBox < Test::Unit::TestCase
  def setup
    @pub_a, @sec_a = NaCl.crypto_box_keypair
    @pub_b, @sec_b = NaCl.crypto_box_keypair
    @nonce = "X" * 24
  end

  def test_crypto_box_keypair
    result = NaCl.crypto_box_keypair
    assert_equal 2, result.length
    assert_equal 32, result[0].length
    assert_equal 32, result[1].length
  end

  def test_with_normal_message
    message = "This is a test message."
    crypted = NaCl.crypto_box(message, @nonce, @pub_b, @sec_a)
    assert_equal message, NaCl.crypto_box_open(crypted, @nonce, @pub_a, @sec_b)
  end

  def test_with_blank_message
    message = ""
    crypted = NaCl.crypto_box(message, @nonce, @pub_b, @sec_a)
    assert crypted.length >= 16
    assert_equal message, NaCl.crypto_box_open(crypted, @nonce, @pub_a, @sec_b)
  end

  def test_with_long_message
    message = "Test message\0" * 100
    crypted = NaCl.crypto_box(message, @nonce, @pub_b, @sec_a)
    assert_equal message, NaCl.crypto_box_open(crypted, @nonce, @pub_a, @sec_b)
  end

  def test_with_invalid_arguments
    assert_raise(ArgumentError) do
      NaCl.crypto_box("test message", "invalid nonce", @pub_b, @sec_a)
    end
    assert_raise(ArgumentError) do
      NaCl.crypto_box("test message", @nonce, "invalid pubkey", @sec_a)
    end
    assert_raise(ArgumentError) do
      NaCl.crypto_box("test message", @nonce, @pub_b, "invalid seckey")
    end
    assert_raise(ArgumentError) do
      NaCl.crypto_box_open("", @nonce, @pub_a, @sec_b)
    end
  end

  def test_open_with_changed_ciphertext
    crypted = NaCl.crypto_box("This is a test message", @nonce, @pub_b, @sec_a)
    char = crypted[14..14]
    char = char == "\0" ? "\1" : "\0"
    mangled = "#{crypted[0..13]}#{char}#{crypted[15..-1]}"
    assert_not_equal crypted, mangled
    assert_raise(NaCl::OpenError) do
      p NaCl.crypto_box_open(mangled, @nonce, @pub_a, @sec_b)
    end
  end
end
