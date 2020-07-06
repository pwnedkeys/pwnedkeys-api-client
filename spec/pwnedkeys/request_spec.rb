require_relative "../spec_helper"

require "pwnedkeys/request"
require "pwnedkeys/response"

describe Pwnedkeys::Request do
  describe ".new" do
    it "accepts an SPKI object" do
      expect { described_class.new(OpenSSL::X509::SPKI.new(OpenSSL::PKey::RSA.new(2048).public_key.to_der)) }.to_not raise_error
    end

    it "accepts a DER string" do
      expect { described_class.new(OpenSSL::PKey::RSA.new(2048).public_key.to_der) }.to_not raise_error
    end

    it "accepts a key" do
      expect { described_class.new(OpenSSL::PKey::RSA.new(2048)) }.to_not raise_error
    end

    it "does not accept an unrecognised string" do
      expect { described_class.new("ohaithere") }.to raise_error(Pwnedkeys::Request::Error)
    end

    it "does not accept other types of argument" do
      expect { described_class.new(nil) }.to raise_error(Pwnedkeys::Request::Error)
      expect { described_class.new(42) }.to raise_error(Pwnedkeys::Request::Error)
      expect { described_class.new(:fortytwo) }.to raise_error(Pwnedkeys::Request::Error)
    end

    context "with an unsupported curve key" do
      let(:key) { OpenSSL::PKey::EC.new("wap-wsg-idm-ecid-wtls6").generate_key }

      it "raises an error" do
        expect{ described_class.new(key.to_spki) }.to raise_error(Pwnedkeys::Request::Error)
      end
    end

    context "with a DSA key" do
      let(:key)  { OpenSSL::PKey::DSA.new(1024) }
      let(:spki) { OpenSSL::X509::SPKI.new(key.public_key.to_der) }

      it "raises an error" do
        expect{ described_class.new(spki) }.to raise_error(Pwnedkeys::Request::Error)
      end
    end
  end

  describe "#pwned?" do
    def generate_response(key)
      Pwnedkeys::Response.new(key).to_json
    end

    def b64(s)
      Base64.urlsafe_encode64(s).sub(/=*\z/, "")
    end

    let(:req)           { Pwnedkeys::Request.new(spki) }
    let(:key)           { OpenSSL::PKey::RSA.new(2048) }
    let(:spki)          { key.to_spki }
    let(:fingerprint)   { spki.spki_fingerprint }
    let(:uri)           { URI("https://v1.pwnedkeys.com/#{fingerprint}") }
    let(:mock_http)     { instance_double(Net::HTTP) }
    let(:response_code) { "" }
    let(:response_body) { generate_response(key) }
    let(:response) do
      instance_double(Net::HTTPResponse).tap do |res|
        allow(res).to receive(:code).and_return(response_code)
        allow(res).to receive(:body).and_return(response_body)
      end
    end

    before(:each) do
      allow(Net::HTTP).to receive(:start).with("v1.pwnedkeys.com", 443, use_ssl: true).and_yield(mock_http)
      allow(mock_http).to receive(:request) do |req|
        expect(req.path).to eq(uri.path)
        expect(req["User-Agent"]).to match(/pwnedkeys/)

        response
      end
    end

    context "when the fingerprint isn't found" do
      let(:response_code) { "404" }

      it "returns false" do
        expect(req.pwned?).to be(false)
      end
    end

    context "when the fingerprint is found" do
      let(:response_code) { "200" }

      def modified_response(resign: true)
        h = JSON.parse(generate_response(key))
        yield h
        if resign
          h["signature"] = b64(key.sign(OpenSSL::Digest::SHA256.new, "#{h["protected"]}.#{h["payload"]}"))
        end
        h.to_json
      end

      context "when the response is valid" do
        it "returns true" do
          expect(req.pwned?).to be(true)
        end
      end

      context "when the signature doesn't match" do
        let(:response_body) do
          modified_response(resign: false) do |r|
            r["payload"] = b64("this key is pwned by the sigs shouldn't match")
          end
        end

        it "raises a verification error" do
          expect { req.pwned? }.to raise_error(Pwnedkeys::Request::VerificationError)
        end
      end

      context "when the JWS algorithm doesn't match" do
        let(:response_body) do
          modified_response do |r|
            r["protected"] = b64({ alg: "HS256", kid: spki.spki_fingerprint.hexdigest }.to_json)
          end
        end

        it "raises a verification error" do
          expect { req.pwned? }.to raise_error(Pwnedkeys::Request::VerificationError)
        end
      end

      context "when the kid doesn't match" do
        let(:response_body) do
          modified_response do |r|
            r["protected"] = b64(({ alg: "RS256", kid: "ohai!" }).to_json)
          end
        end

        it "raises a verification error" do
          expect { req.pwned? }.to raise_error(Pwnedkeys::Request::VerificationError)
        end
      end

      context "when the payload doesn't have the magic string" do
        let(:response_body) do
          modified_response do |r|
            r["payload"] = b64("this key is NOT pwned")
          end
        end

        it "raises a verification error" do
          expect { req.pwned? }.to raise_error(Pwnedkeys::Request::VerificationError)
        end
      end

      context "with a P-256 key" do
        let(:key) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

        it "validates successfully" do
          expect(req.pwned?).to be(true)
        end
      end

      context "with a P-384 key" do
        let(:key) { OpenSSL::PKey::EC.new("secp384r1").generate_key }

        it "validates successfully" do
          expect(req.pwned?).to be(true)
        end
      end

      context "with a P-521 key" do
        let(:key) { OpenSSL::PKey::EC.new("secp521r1").generate_key }

        it "validates successfully" do
          expect(req.pwned?).to be(true)
        end
      end

      context "with a SECG Koblitz 256 bit key" do
        let(:key) { OpenSSL::PKey::EC.new("secp256k1").generate_key }

        it "validates successfully" do
          expect(req.pwned?).to be(true)
        end
      end
    end

    context "when the request is invalid" do
      let(:response_code) { "400" }

      it "raises an error" do
        expect { req.pwned? }.to raise_error(Pwnedkeys::Request::Error)
      end
    end

    context "when the server craps out" do
      let(:response_code) { "500" }

      it "retries for a while then raises an error" do
        expect(Net::HTTP).to receive(:start).at_least(5).times
        allow(req).to receive(:sleep)

        expect { req.pwned? }.to raise_error(Pwnedkeys::Request::Error)
      end
    end

    context "with a filter defined" do
      let(:filter_file) { File.expand_path("../../fixtures/filter.pkbf", __FILE__) }
      let(:req) { Pwnedkeys::Request.new(spki, filter: filter_file) }
      let(:response_code) { "404" }

      let(:included_key) do
        OpenSSL::PKey.read <<~EOF.unpack("m").first
          MIIBPAIBAAJBAMXBUC1SALNO3nIX8l7bn+SIUpTQwZNs3vYuFPUrClrtVF400e9v4MazsDLf
          GfTPgTxpKvz0ovJ+5pDodKDes5sCAwEAAQJBAIwgslaa3+IvBdMlAtqSl9dRferzjeeQYuFg
          v/sGF51bheGzDIfYQP+W8JatHXpe51glWLH7OPyqHw9vrVCPCqkCIQDj+KuATcxubMH/N2jC
          eSTnxRlxcZ/jmjHgy+pMEa0sLwIhAN4RmKdXjkM5lHYMkcyXGb2g5Q0aQcMfJqw/R8qtp3hV
          AiAETYxHJrDGIM1kmNIkYY79xO2fA4sGC8IHQTIR7396RwIhAMZslKlaK6zXw1cj7hcQIJj3
          LhNiFcbCi+y28nAgcJatAiEAnSWQvDPCeQhxKlhihWj6BgXhbaGcAH+r1KdGf/L/zWo=
        EOF
      end

      let(:not_included_key) do
        OpenSSL::PKey.read <<~EOF.unpack("m").first
          MIIBOQIBAAJBANBdbS2W+xYLUV7IINfdRYV4ll5SOIglukj0I9RwpZaRUQGKM9o0E2+QBQM9
          OjWQ6+uIzlDZkT+wTaFA678v0psCAwEAAQJAGWcqhmJf3kIm+30+s9KgRTN8cadoiQDAg2Bw
          ddf9+Csq8+0SsH1JUY10udP67OuJDh9kJP6B5Ax67a6DWnCrgQIhAO3tTZqbkbg9ksH8EBcW
          oAw9KQE5XoX+SidvNeTI+LchAiEA4DFDoLElZ/wCULM1cYar/QpxaiPDXK72z43S3CAv3jsC
          IGm3x4OrHFSBB3SqS3v20aaehlnE4/slwk1DXO8LXXgBAiBztrmzHPuzmg0P3g99kwb+Sf+T
          yvWwxtW49viYiTxrtQIgGED64JUFf8WREjgMEnZLghw2idFMhItumExPq+iGUdY=
        EOF
      end

      context "on a key in the filter" do
        let(:key) { included_key }

        it "checks the API" do
          expect(mock_http).to receive(:request)

			 req.pwned?
        end
      end

      context "with a key not in the filter" do
        let(:key) { not_included_key }

        it "reports the key as not pwned" do
          expect(req.pwned?).to be(false)
        end

        it "does not check the API" do
          expect(Net::HTTP).to_not receive(:start)

          req.pwned?
        end
      end
    end
  end
end
