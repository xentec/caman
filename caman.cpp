// Compile with
//   c++ caman.cpp -o caman -std=c++17 -I/usr/include/botan-2/ -lbotan-2 -lstdc++fs
// or for maximum static
//   c++ src/main.cpp -o caman -std=c++17 -I/usr/include/botan-2/ -flto -O3 -Wl,-O3,--strip-all -pthread -stdlib=libc++ -static -L/usr/local/lib/ -lbotan-2 -lc++experimental -lc++ -lc++abi

#include <botan/data_src.h>
#include <botan/pk_algs.h>
#include <botan/pkcs8.h>
#include <botan/system_rng.h>
#include <botan/x509self.h>
#include <botan/x509_ca.h>
#include <botan/version.h>

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

# if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(2,5,0)
#    warning "Botan older than 2.5.0 creates compressed ECDSA keys, which might be a compatibility issue"
# endif


using namespace Botan;

constexpr auto CA_COUNTRY = "DE";
constexpr auto CA_ROOT_NAME = "CA ROOT X18";
constexpr auto CA_ROOT_DURATION = 86400*365*10;

constexpr auto CA_IM_NAME = "CA INTERMEDIATE X18";
constexpr auto CA_IM_DURATION = 86400*365*5;

constexpr auto NAME_KEY = "key.pem";
//constexpr auto NAME_CSR = "csr.pem";
constexpr auto NAME_CERT = "crt.pem";
constexpr auto NAME_CHAIN = "chain.pem";

constexpr auto DEFAULT_ALGO = "ECDSA";
constexpr auto DEFAULT_PARAM = "secp256r1";
constexpr auto DEFAULT_HASH = "SHA-256";
constexpr auto DEFAULT_DURATION = 86400*365*2;

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
	std::cerr << std::endl;

	tty.c_lflag |= ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &tty);

	return pw;
}

auto summon_key(const fs::path& filename, RandomNumberGenerator& rng, bool encrypt = false, const std::string& param = DEFAULT_PARAM) -> std::unique_ptr<Private_Key>
{
	std::unique_ptr<Private_Key> key;
	if(fs::exists(filename))
	{
		DataSource_Stream dss(filename);
		key = PKCS8::load_key(dss, [&]() { return read_pw("to open "+filename.string()); });
	} else
	{
		std::cerr << "Generating key " << filename << "..." << std::endl;
		key = create_private_key(DEFAULT_ALGO, rng, param, "base");
		std::string pemKey = encrypt ?
					PKCS8::PEM_encode(*key, rng, read_pw("to create key")) :
					PKCS8::PEM_encode(*key);

		std::ofstream(filename) << pemKey << std::endl;
		fs::permissions(filename, fs::perms::owner_read);
	}
	return key;
}

void usage(const char *name, int code = EXIT_SUCCESS)
{
	std::cout << "usage: " << (name ?: "caman") << " <ca_domain> [subdomain...]" << std::endl;
	std::exit(EXIT_SUCCESS);
}


int main(int argc, char *argv[])
{
	using fs::path;

	System_RNG rng;
	std::unique_ptr<Private_Key> ca_key;
	std::unique_ptr<X509_CA> ca;

	if(argc < 2 || !*argv[1])
		usage(*argv, 1);

	const path domain_base = argv[1];
	if(!fs::exists(domain_base)) fs::create_directories(domain_base);

	const path im_path = domain_base / "ca-im";
	const path im_cert_path = im_path / NAME_CERT;
	const path im_chain_path = im_path / NAME_CHAIN;
	if(!fs::exists(im_cert_path))
	{
		// ROOT
		////////
		const path ca_path = domain_base / "ca-root";
		fs::create_directories(ca_path);

		ca_key = summon_key(ca_path / NAME_KEY, rng, true, "secp384r1");
		const path ca_cert_path = ca_path / NAME_CERT;
		if(!fs::exists(ca_cert_path))
		{
			std::cerr << "Creating cert for root CA..." << std::endl;
			X509_Cert_Options opt(domain_base.string() +" "+ CA_ROOT_NAME +"/"+ CA_COUNTRY +"/"+ domain_base.c_str(), CA_ROOT_DURATION);
			opt.CA_key();

			auto crt = X509::create_self_signed_cert(opt, *ca_key, DEFAULT_HASH, rng);
			std::cerr << crt.to_string();
			std::ofstream(ca_cert_path) << crt.PEM_encode();

			ca = std::make_unique<X509_CA>(crt, *ca_key, DEFAULT_HASH, rng);
		}

		// INTERMEDIATE
		////////////////
		fs::create_directories(im_path);
		auto im_key = summon_key(im_path / NAME_KEY, rng, true, "secp384r1");

		std::cerr << "Creating cert for intermediate CA..." << std::endl;
		X509_Cert_Options opt(domain_base.string() +" "+ CA_IM_NAME +"/"+ CA_COUNTRY +"/"+ domain_base.c_str(), CA_IM_DURATION);
		opt.CA_key(0);

		auto crt = ca->sign_request(X509::create_cert_req(opt, *im_key, DEFAULT_HASH, rng), rng, opt.start, opt.end);
		const auto crt_data = crt.PEM_encode();
		std::cerr << crt.to_string();
		std::ofstream(im_cert_path) << crt_data;
		std::ofstream(im_chain_path) << crt_data << ca->ca_certificate().PEM_encode();

		ca_key.swap(im_key);
		ca = std::make_unique<X509_CA>(crt, *ca_key, DEFAULT_HASH, rng);
	} else
	{
		if(argc < 3) usage(*argv);

		ca_key.reset(PKCS8::load_key(im_path / NAME_KEY, rng, []() { return read_pw("to open INTERMEDIATE CA key"); }));
		ca = std::make_unique<X509_CA>(X509_Certificate(im_cert_path), *ca_key, DEFAULT_HASH, rng);
	}

	// END POINT
	/////////////
	const path issued = domain_base / "issued";
	fs::create_directories(issued);
	for(int i = 2; i < argc; ++i)
	{
		const std::string sub = std::string(argv[i]);
		std::string fqdn;

		if(sub.empty())
			fqdn = domain_base.string();
		else if(sub.find(".") != std::string::npos)
			fqdn = sub;
		else
			fqdn = sub + "." + domain_base.string();

		const path sub_path = issued / fqdn;
		const path cert_path = sub_path / NAME_CERT;

		if(fs::exists(cert_path))
		{
			std::cerr << fqdn << " already exists!\n";
			continue;
		}

		fs::create_directories(sub_path);

		const path key_path = sub_path / NAME_KEY;
		auto key = summon_key(key_path, rng);

		std::cerr << "Creating cert for " << fqdn << "..." << std::endl;
		X509_Cert_Options opt(fqdn +"/"+ CA_COUNTRY +"/"+ domain_base.string(), DEFAULT_DURATION);
		opt.constraints = Key_Constraints(DIGITAL_SIGNATURE);
		opt.add_ex_constraint("PKIX.ServerAuth");
		opt.dns = fqdn;

		const auto crt = ca->sign_request(X509::create_cert_req(opt, *key, DEFAULT_HASH, rng), rng, opt.start, opt.end);
		const auto crt_data = crt.PEM_encode();
		const path chain_path = sub_path / NAME_CHAIN;

		std::cerr << crt.to_string();
		std::ofstream(cert_path) << crt_data;
		std::ofstream(chain_path) << crt_data << std::ifstream(im_chain_path).rdbuf();

		std::cerr
			<< "Private key: " << key_path.string() << "\n"
			<< "Certificate: " << cert_path.string() << "\n"
			<< "Chain:       " << chain_path.string() << std::endl;
	}

	return 0;
}
