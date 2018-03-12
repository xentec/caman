// Compile with
//   c++ caman.cpp -o caman -std=c++17 -I/usr/include/botan-2/ -lbotan-2 -lstdc++fs

#include <botan/system_rng.h>
#include <botan/pk_algs.h>
#include <botan/pkcs8.h>
#include <botan/x509self.h>
#include <botan/x509_ca.h>

#include <iostream>
#include <fstream>
#include <sstream>

#include <unistd.h>
#include <termios.h>

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

#define CA_DURATION 86400*365*10
#define IM_DURATION 86400*365*5

#define FILE_EXT_KEY ".key.pem"
#define FILE_EXT_CSR ".csr.pem"
#define FILE_EXT_CERT ".crt.pem"
#define FILE_CHAIN ".chain"

#define DEFAULT_ALGO "ECDSA"
#define DEFAULT_PARAM "secp256r1"
#define DEFAULT_HASH "SHA-256"
#define DEFAULT_DURATION 86400*365*2

auto read_pw(std::string desc = "") -> std::string
{
	std::cerr << "Enter password";
	if(!desc.empty()) std::cerr << " " << desc;
	std::cerr << ": ";

	struct termios tty;
	tcgetattr(STDIN_FILENO, &tty);
	tty.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &tty);

	std::string pw;
	std::cin >> pw;

	tty.c_lflag |= ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &tty);

	return pw;
}

auto summon_key(const std::string& filename, RandomNumberGenerator& rng, bool encrypt = false, const std::string& param = DEFAULT_PARAM) -> std::unique_ptr<Private_Key>
{
	std::unique_ptr<Private_Key> key;
	if(fs::exists(filename))
		key.reset(PKCS8::load_key(filename, rng, [&]() { return read_pw("to open "+filename); }));
	else
	{
		std::cerr << "Generating key '" << filename << "'..." << std::endl;
		key = create_private_key(DEFAULT_ALGO, rng, param, "base");
		std::string pemKey = encrypt ?
					PKCS8::PEM_encode(*key, rng, read_pw("to create key")) :
					PKCS8::PEM_encode(*key);
		std::ofstream(filename) << pemKey;
	}
	return key;
}


int main(int argc, char *argv[])
{
	System_RNG rng;
	std::unique_ptr<Private_Key> caKey;
	std::unique_ptr<X509_CA> ca;

	if(argc < 2) {
		std::cout << "usage: " << (*argv ?: "caman") << " <ca_domain> [subdomain...]" << std::endl;
		return 1;
	}

	const std::string domain_base = argv[1];
	const std::string im_filename = domain_base + ".im";
	if(!fs::exists(im_filename + FILE_EXT_CERT))
	{
		// ROOT
		////////
		const std::string ca_filename = domain_base + ".ca";
		caKey = summon_key(ca_filename + FILE_EXT_KEY, rng, true, "secp384r1");
		if(!fs::exists(ca_filename + FILE_EXT_CERT))
		{
			std::cerr << "Creating cert for root CA..." << std::endl;
			X509_Cert_Options opt(domain_base + " CA/DE/" + domain_base, CA_DURATION);
			opt.CA_key();

			auto crt = X509::create_self_signed_cert(opt, *caKey, DEFAULT_HASH, rng);
			std::cerr << crt.to_string();
			std::ofstream(ca_filename + FILE_EXT_CERT) << crt.PEM_encode();

			ca = std::make_unique<X509_CA>(crt, *caKey, DEFAULT_HASH, rng);
		}

		// INTERMEDIATE
		////////////////
		auto imKey = summon_key(im_filename + FILE_EXT_KEY, rng, true, "secp384r1");

		std::cerr << "Creating cert for intermediate CA..." << std::endl;
		X509_Cert_Options opt(domain_base + " ImCA/DE/" + domain_base, IM_DURATION);
		opt.CA_key(0);

		auto crt = ca->sign_request(X509::create_cert_req(opt, *imKey, DEFAULT_HASH, rng), rng, opt.start, opt.end);
		std::cerr << crt.to_string();
		std::ofstream(im_filename + FILE_EXT_CERT) << crt.PEM_encode();

		std::ofstream(domain_base + FILE_CHAIN FILE_EXT_CERT) << crt.PEM_encode() << ca->ca_certificate().PEM_encode();

		caKey.swap(imKey);
		ca = std::make_unique<X509_CA>(crt, *caKey, DEFAULT_HASH, rng);
	} else
	{
		caKey.reset(PKCS8::load_key(im_filename + FILE_EXT_KEY, rng, []() { return read_pw("to open CA key"); }));
		ca = std::make_unique<X509_CA>(X509_Certificate(im_filename + FILE_EXT_CERT), *caKey, DEFAULT_HASH, rng);
	}

	// END POINT
	/////////////
	for(int i = 2; i < argc; ++i)
	{
		const std::string fqdn = std::string(argv[i]) + "." + domain_base;
		auto keyName = fqdn + FILE_EXT_KEY, certName = fqdn + FILE_EXT_CERT;

		if(fs::exists(certName)) continue;

		auto key = summon_key(keyName, rng);

		std::cerr << "Creating cert for " << fqdn << "..." << std::endl;
		X509_Cert_Options opt(fqdn + "/DE/" + domain_base, DEFAULT_DURATION);
		opt.dns = fqdn;
		opt.constraints = Key_Constraints(DIGITAL_SIGNATURE);
		opt.add_ex_constraint("PKIX.ServerAuth");
//		opt.add_ex_constraint("PKIX.ClientAuth");

		auto crt = ca->sign_request(X509::create_cert_req(opt, *key, DEFAULT_HASH, rng), rng, opt.start, opt.end);

		std::cerr << crt.to_string();
		std::ofstream(certName) << crt.PEM_encode();
		std::ofstream(fqdn + FILE_CHAIN FILE_EXT_CERT) << crt.PEM_encode() << std::ifstream(domain_base + ".chain" FILE_EXT_CERT).rdbuf();
	}

	return 0;
}
