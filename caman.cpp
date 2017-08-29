// Compile with
//   c++ src/main.cpp -std=c++17 -I/usr/include/botan-2/ -lbotan-2 -lstdc++fs

#include <botan/auto_rng.h>
#include <botan/pk_algs.h>
#include <botan/pkcs8.h>
#include <botan/x509self.h>
#include <botan/x509_ca.h>
#include <botan/secmem.h>

#include <iostream>
#include <fstream>
#include <sstream>

#if __has_include(<filesystem>)
#	include <filesystem>
	namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
#	include <experimental/filesystem>
	namespace fs = std::experimental::filesystem;
#else
#	error "std::filesystem required"
#endif

using namespace Botan;

#define DOMAIN_BASE "example.net"

#define CA_FILENAME DOMAIN_BASE ".ca"
#define CA_DURATION 86400*365*10

#define IM_FILENAME DOMAIN_BASE ".im"
#define IM_DURATION 86400*365*5


#define FILE_EXT_KEY ".key.pem"
#define FILE_EXT_CSR ".csr.pem"
#define FILE_EXT_CERT ".crt.pem"

#define DEFAULT_ALGO "ECDSA"
#define DEFAULT_PARAM "secp256r1"
#define DEFAULT_HASH "SHA-3"
#define DEFAULT_DURATION 86400*365*2

std::string read_pw(std::string desc = "")
{
	std::cerr << "Enter password";
	if(!desc.empty()) std::cerr << " " << desc;
	std::cerr << ": ";

	std::string pw;
	std::cin >> pw;
	return pw;
}

std::unique_ptr<Private_Key> summon_key(const std::string& filename, RandomNumberGenerator& rng, bool encrypt = false, const std::string& param = DEFAULT_PARAM)
{
	std::unique_ptr<Private_Key> key;
	if(fs::exists(filename))
		key.reset(PKCS8::load_key(filename, rng, [&]() { return read_pw("to open "+filename); }));
	else
	{
		std::cerr << "Generating key '" << filename << "'..." << std::endl;
		key = create_private_key(DEFAULT_ALGO, rng, param);
		std::string pemKey = encrypt ?
					PKCS8::PEM_encode(*key, rng, read_pw("to create key")) :
					PKCS8::PEM_encode(*key);
		std::ofstream(filename) << pemKey;
	}
	return key;
}


int main(int argc, char *argv[])
{
	AutoSeeded_RNG rng;
	std::unique_ptr<Private_Key> caKey;
	std::unique_ptr<X509_CA> ca;

	if(!fs::exists(IM_FILENAME FILE_EXT_CERT))
	{
		// ROOT
		////////
		caKey = summon_key(CA_FILENAME FILE_EXT_KEY, rng, true, "secp521r1");
		if(!fs::exists(CA_FILENAME FILE_EXT_CERT))
		{
			std::cerr << "Creating cert for root CA..." << std::endl;
			X509_Cert_Options opt(DOMAIN_BASE " CA/DE/" DOMAIN_BASE, CA_DURATION);
			opt.CA_key();

			auto crt = X509::create_self_signed_cert(opt, *caKey, DEFAULT_HASH, rng);
			std::cerr << crt.to_string();
			std::ofstream(CA_FILENAME FILE_EXT_CERT) << crt.PEM_encode();

			ca = std::make_unique<X509_CA>(crt, *caKey, DEFAULT_HASH, rng);
		}

		// INTERMEDIATE
		////////////////
		auto imKey = summon_key(IM_FILENAME FILE_EXT_KEY, rng, true);

		std::cerr << "Creating cert for intermediate CA..." << std::endl;
		X509_Cert_Options opt(DOMAIN_BASE " ImCA/DE/" DOMAIN_BASE, IM_DURATION);
		opt.CA_key(0);

		auto crt = ca->sign_request(X509::create_cert_req(opt, *imKey, DEFAULT_HASH, rng), rng, opt.start, opt.end);
		std::cerr << crt.to_string();
		std::ofstream(IM_FILENAME FILE_EXT_CERT) << crt.PEM_encode();
		std::ofstream(DOMAIN_BASE ".chain" FILE_EXT_CERT) << crt.PEM_encode() << ca->ca_certificate().PEM_encode();

		caKey.swap(imKey);
		ca = std::make_unique<X509_CA>(crt, *caKey, DEFAULT_HASH, rng);
	} else
	{
		caKey.reset(PKCS8::load_key(IM_FILENAME FILE_EXT_KEY, rng, []() { return read_pw("to open CA key"); }));
		ca = std::make_unique<X509_CA>(X509_Certificate(IM_FILENAME FILE_EXT_CERT), *caKey, DEFAULT_HASH, rng);
	}

	// END POINT
	/////////////
	for(int i = 1; i < argc; ++i)
	{
		std::string cn = argv[i];

		auto fqdn = cn + "." DOMAIN_BASE;
		auto keyName = fqdn + FILE_EXT_KEY, certName = fqdn + FILE_EXT_CERT;

		if(fs::exists(certName)) continue;

		auto key = summon_key(keyName, rng);

		std::cerr << "Creating cert for " << fqdn << "..." << std::endl;
		X509_Cert_Options opt(fqdn + "/DE/" DOMAIN_BASE, DEFAULT_DURATION);
		opt.dns = fqdn;
		opt.constraints = Key_Constraints(DIGITAL_SIGNATURE);
		opt.add_ex_constraint("PKIX.ClientAuth");
		opt.add_ex_constraint("PKIX.ServerAuth");

		auto crt = ca->sign_request(X509::create_cert_req(opt, *key, DEFAULT_HASH, rng), rng, opt.start, opt.end);

		std::cerr << crt.to_string();
		std::ofstream(certName) << crt.PEM_encode();
	}

	return 0;
}
