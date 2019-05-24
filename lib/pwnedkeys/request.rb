require "base64"
require "json"
require "net/http"
require "openssl"

require "openssl/x509/spki"

# All the keys that are fit to be pwned.
module Pwnedkeys
  # Make a query against the pwnedkeys.com API.
  #
  class Request
    # Generic error relating to API requests.
    #
    class Error < StandardError; end

    # Raised if the signature on the pwnedkeys response cannot be
    # validated.  This almost certainly indicates something very wrong
    # in the API itself, as the correctness of the key is ensured by the
    # query protocol.
    #
    class VerificationError < Error; end

    # Prepare to the make a request to the pwnedkeys API.
    #
    # @param spki [OpenSSL::X509::SPKI, OpenSSL::PKey::PKey, String] the
    #   public key to query for.  Can be provided as a key object itself,
    #   an SPKI object (most likely derived from an X509 certificate or
    #   CSR), or a string containing a DER-encoded `SubjectPublicKeyInfo`
    #   ASN.1 structure.
    #
    #   If in doubt, just pass in a key and we'll take care of the rest.
    #
    # @raise [Pwnedkeys::Request::Error] if the passed-in key representation
    #   can't be induced into something useable.
    #
    def initialize(spki)
      @spki = if spki.is_a?(OpenSSL::X509::SPKI)
        spki
      elsif spki.is_a?(String)
        begin
          OpenSSL::X509::SPKI.new(spki)
        rescue OpenSSL::ASN1::ASN1Error, OpenSSL::X509::SPKIError
          raise Error,
                "Invalid SPKI ASN.1 string"
        end
      elsif spki.is_a?(OpenSSL::PKey::PKey)
        spki.to_spki
      else
        raise Error,
              "Invalid argument type passed to Pwnedkeys::Request.new (need OpenSSL::X509::SPKI, PKey, or string, got #{spki.class})"
      end

      # Verify key type is OK
      key_params
    end

    # Query the pwnedkeys API and tell whether the key is exposed.
    #
    # @return [Boolean] whether the key embodied in this request is contained
    #   within the pwnedkeys database.
    #
    # @raise [VerificationError] if a response was provided, but the signature
    #   on the response was not able to be verified.
    #
    # @raise [Error] if the request to the API could not be successfully
    #   completed.
    #
    def pwned?
      retry_count = 10
      uri = URI(ENV["PWNEDKEYS_API_URL"] || "https://v1.pwnedkeys.com")
      uri.path += "/#{@spki.spki_fingerprint.hexdigest}"

      loop do
        res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") do |http|
          req = Net::HTTP::Get.new(uri.path)
          req["User-Agent"] = "pwnedkeys-tools/0.0.0"
          http.request(req)
        end

        if res.code == "200"
          verify!(res.body)
          return true
        elsif res.code == "404"
          return false
        elsif (500..599) === res.code.to_i && retry_count > 0
          # Server-side error, let's try a few more times
          sleep 1
          retry_count -= 1
        else
          raise Error,
                "Unable to determine pwnage, error status code returned from #{uri}: #{res.code}"
        end
      end
    end

    private

    # Do the dance of the signature verification.
    #
    def verify!(res)
      json = JSON.parse(res)
      header = JSON.parse(unb64(json["protected"]))

      key = @spki.to_key

      verify_data = "#{json["protected"]}.#{json["payload"]}"

      unless key.verify(hash_func.new, format_sig(unb64(json["signature"])), verify_data)
        raise VerificationError,
              "Response signature cannot be validated by provided key"
      end

      unless header["alg"] == key_alg
        raise VerificationError,
              "Incorrect alg parameter.  Got #{header["alg"]}, expected #{key_alg} for #{key.class} key"
      end

      unless header["kid"] == @spki.spki_fingerprint.hexdigest
        raise VerificationError,
              "Key ID in response doesn't match.  Got #{header["kid"]}, expected #{@spki.spki_fingerprint.hexdigest}"
      end

      unless unb64(json["payload"]) =~ /key is pwned/
        raise VerificationError,
              "Response payload does not include magic string 'key is pwned', got #{unb64(json["payload"])}"
      end

      # The gauntlet has been run and you have been found... worthy
    end

    # Strip off the base64 barnacles.
    #
    def unb64(s)
      Base64.urlsafe_decode64(s)
    end

    def key_alg
      key_params[:key_alg]
    end

    def hash_func
      key_params[:hash_func]
    end

    def format_sig(sig)
      key_params[:format_sig].call(sig)
    end

    # Turn a JOSE EC sig into a "proper" EC sig that OpenSSL can use.
    #
    def ec_sig(jose_sig)
      # *Real* EC signatures are a two-element ASN.1 sequence containing
      # the R and S values.  RFC7518, in its infinite wisdom, has decided that
      # that is not good enough, and instead it wants the signatures in raw
      # concatenated R/S as octet strings.  Because of *course* it does.
      OpenSSL::ASN1::Sequence.new(split_in_two_equal_halves(jose_sig).map do |i|
        OpenSSL::ASN1::Integer.new(i.unpack("C*").inject(0) { |v, i| v * 256 + i })
      end).to_der
    end

    def split_in_two_equal_halves(s)
      [s[0..(s.length / 2 - 1)], s[(s.length / 2)..(s.length - 1)]]
    end

    # Return all the relevant parameters required to validate the API response,
    # based on the type of key being queried.
    #
    def key_params
      case @spki.to_key
      when OpenSSL::PKey::RSA then {
        key_alg: "RS256",
        hash_func: OpenSSL::Digest::SHA256,
        format_sig: ->(sig) { sig },
      }
      when OpenSSL::PKey::EC
        case @spki.to_key.public_key.group.curve_name
        when "secp256k1" then {
          key_alg: "ES256K",
          hash_func: OpenSSL::Digest::SHA256,
          format_sig: ->(sig) { ec_sig(sig) },
        }
        when "prime256v1" then {
          key_alg: "ES256",
          hash_func: OpenSSL::Digest::SHA256,
          format_sig: ->(sig) { ec_sig(sig) },
        }
        when "secp384r1"  then {
          key_alg: "ES384",
          hash_func: OpenSSL::Digest::SHA384,
          format_sig: ->(sig) { ec_sig(sig) },
        }
        when "secp521r1"  then {
          key_alg: "ES512",
          hash_func: OpenSSL::Digest::SHA512,
          # The components of P-521 keys are 521 bits each, which is padded
          # out to be 528 bits -- 66 octets.
          format_sig: ->(sig) { ec_sig(sig) },
        }
        else
          raise Error, "EC key containing unsupported curve #{@spki.to_key.group.curve_name}"
        end
      else
        raise Error, "Unsupported key type #{@key.class}"
      end
    end
  end
end
