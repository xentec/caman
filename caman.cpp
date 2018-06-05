// Compile with
//   c++ caman.cpp -o caman -std=c++17 -O3 -I/usr/include/botan-2/ -lbotan-2 -lstdc++fs

/* Use like
 *	caman example.org          # generate 'example.org' cert authority
 *	caman example.org www mail # generate certs for {www,mail}.example.org
 *  caman example.org legacy/a:RSA:2048 # a RSA cert legacy.example.org
 *	caman example.org uk.example.net/c:UK # certs for foreign TLD
 *  caman example.org highend/a:Ed25519/h:SHA-3(512)/d:2y
*/

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

using namespace std::literals;

using namespace Botan;

constexpr auto CA_ALGO_PARAM = "secp384r1";
constexpr auto CA_HASH = "SHA-256";

constexpr auto CA_ROOT_NAME = "CA ROOT X18";
constexpr auto CA_ROOT_DURATION = 86400*365*10;

constexpr auto CA_IM_NAME = "CA INTERMEDIATE X18";
constexpr auto CA_IM_DURATION = 86400*365*5;

constexpr auto NAME_KEY = "key.pem";
//constexpr auto NAME_CSR = "csr.pem"; soon
constexpr auto NAME_CERT = "crt.pem";
constexpr auto NAME_CHAIN = "chain.pem";

struct Opts
{
	std::string
		algo = "ECDSA"s,
		algo_param = ""s,
		hash = "SHA-256"s,
		country = "DE"s;
	uint32_t duration = 86400*365*2;
};

static const Opts default_opts;

template<typename _CharT, typename _Traits>
inline std::basic_ostream<_CharT, _Traits>& nl(std::basic_ostream<_CharT, _Traits>& __os)
{
	  return __os.put(__os.widen('\n'));
}


auto read_pw(const std::string_view &desc = "") -> std::string
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

auto key_load(const fs::path& filename) -> std::unique_ptr<Private_Key> try
{
	DataSource_Stream dss(filename);
	return PKCS8::load_key(dss, [&]() { return read_pw("to open "+filename.string()); });
} catch(const Botan::Decoding_Error& ex)
{
	std::cerr << "Failed to decode " << filename << ": " << ex.what() << nl
			  << "Wrong passphrase?" << std::endl;
	return nullptr;
}

auto key_summon(const fs::path& filename, RandomNumberGenerator& rng, bool encrypt = false,
				const std::string& algo = default_opts.algo,
				const std::string& param = "") -> std::unique_ptr<Private_Key>
{

	if(fs::exists(filename))
		return key_load(filename);

	std::cerr << "Generating key " << filename << "..." << std::endl;
	auto key = create_private_key(algo, rng, param, "base");
	if(!key)
		std::cerr << "Failed to create " << filename << " with " << algo << nl
				  << "Wrong algorithm?" << std::endl;
	else
	{
		std::string pemKey = encrypt ?
			PKCS8::PEM_encode(*key, rng, read_pw("to create key")) :
			PKCS8::PEM_encode(*key);

		std::ofstream(filename) << pemKey << std::endl;
		fs::permissions(filename, fs::perms::owner_read);
	}

	return key;
}


bool parse_duration(const std::string_view& param, u_int32_t& dur)
{
	uint32_t mul = 1;
	if(!std::isdigit(param.front())) return false;
	if(!std::isdigit(param.back()))
	{
		switch(param.back())
		{
		case 'y': mul *= 365;
		case 'd': mul *= 24;
		case 'h': mul *= 3600;
		case 's': break;
		default:
			return false;
		}
	}
	dur = std::atol(param.data()) * mul;
	return true;
}

void parse_opts(std::string_view spec, std::string_view& subdomain, Opts& opts)
{
	size_t b = 0, e = 0;
	while(e != std::string_view::npos)
	{
		e = spec.find('/', b);
		const auto arg = spec.substr(b, e-b);
		b = e+1;

		if(arg.empty())
			continue;

		const auto d = arg.find(':');
		if(d == std::string_view::npos)
		{
			subdomain = arg;
			continue;
		}

		const auto type = arg.substr(0, d),
				   param = arg.substr(d+1);

		if(type.empty() || param.empty())
			continue;

		switch(type.front())
		{
		case 'a':
		{
			const auto ap = param.find(':', d+1);
			if(ap != std::string_view::npos)
				opts.algo_param = param.substr(ap+1);

			opts.algo = param.substr(0,ap);
			break;
		}
		case 'h': opts.hash = param; break;
		case 'c': opts.country = param;	break;
		case 'd':
			if(!parse_duration(param, opts.duration))
				std::cerr
					<< "domain " << subdomain << ": ignoring invalid duration '"<< param.back()
					<< "'. valid is <num>[s|h|d|y]" << nl;
			break;
		default:
			std::cerr
				<< "domain " << subdomain << ": ignoring invalid parameter '"<< type.front()
				<< "'. valid is <a|p|h|c|d>:<arg>" << nl;
		}
	}
}

void usage(const char *name, int code = EXIT_SUCCESS)
{
	std::cerr << "usage: " << (name ?: "caman") << " <ca_domain> [ca_subdomain|domain ...]" << nl
			  << "where  ca_domain := <rfc-domain>" << nl
			  << "       ca_subdomain := <rfc-label>[;opt[/...]]" << nl
			  << "       domain := <rfc-domain>[/opt[/...]]" << nl
			  << "       opt := a[lgo]:<Botan-algo>[:<Botan-algo-parameter>]" << nl
			  << "            | h[hash]:<Botan-hash>" << nl
			  << "            | c[ountry]:<x509-country>" << nl
			  << "            | d[uration]:<natural-number>[s|h|d|y]" << nl
	;
	std::exit(code);
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
		/////////
		const path ca_path = domain_base / "ca-root";
		fs::create_directories(ca_path);

		ca_key = key_summon(ca_path / NAME_KEY, rng, true, default_opts.algo, CA_ALGO_PARAM);
		if(!ca_key) return 2;

		const path ca_cert_path = ca_path / NAME_CERT;
		if(!fs::exists(ca_cert_path))
		{
			std::cerr << "Creating cert for root CA..." << std::endl;
			X509_Cert_Options opt(domain_base.string() +" "+ CA_ROOT_NAME +"/"+ default_opts.country +"/"+ domain_base.c_str(), CA_ROOT_DURATION);
			opt.CA_key();

			auto crt = X509::create_self_signed_cert(opt, *ca_key, CA_HASH, rng);
			std::cerr << crt.to_string();
			std::ofstream(ca_cert_path) << crt.PEM_encode();

			ca = std::make_unique<X509_CA>(crt, *ca_key, CA_HASH, rng);
		}

		 // INTERMEDIATE
		/////////////////
		fs::create_directories(im_path);
		auto im_key = key_summon(im_path / NAME_KEY, rng, true, default_opts.algo, CA_ALGO_PARAM);
		if(!im_key) return 2;

		std::cerr << "Creating cert for intermediate CA..." << std::endl;
		X509_Cert_Options opt(domain_base.string() +" "+ CA_IM_NAME +"/"+ default_opts.country +"/"+ domain_base.c_str(), CA_IM_DURATION);
		opt.CA_key(0);

		auto crt = ca->sign_request(X509::create_cert_req(opt, *im_key, CA_HASH, rng), rng, opt.start, opt.end);
		const auto crt_data = crt.PEM_encode();
		std::cerr << crt.to_string();
		std::ofstream(im_cert_path) << crt_data;
		std::ofstream(im_chain_path) << crt_data << ca->ca_certificate().PEM_encode();

		ca_key.swap(im_key);
		ca = std::make_unique<X509_CA>(crt, *ca_key, CA_HASH, rng);
	} else
	{
		if(argc < 3) usage(*argv);

		ca_key = key_load(im_path / NAME_KEY);
		if(!ca_key)
			return 2;
		ca = std::make_unique<X509_CA>(X509_Certificate(im_cert_path), *ca_key, CA_HASH, rng);
	}


	 // END POINT
	//////////////
	const path issued = domain_base / "issued";
	fs::create_directories(issued);
	for(int i = 2; i < argc; ++i)
	{
		const auto arg = std::string_view(argv[i]);
		std::string_view sub;

		auto opts = default_opts;
		parse_opts(arg, sub, opts);

		std::string fqdn;
		if(sub.find(".") != std::string::npos)
			fqdn = sub;
		else
		{
			if(sub != "*")
				fqdn = std::string(sub) + ".";

			fqdn += domain_base.string();
		}


		const path sub_path = issued / fqdn;
		const path cert_path = sub_path / NAME_CERT;

		if(fs::exists(cert_path))
		{
			std::cerr << fqdn << " already exists!\n";
			continue;
		}

		fs::create_directories(sub_path);

		const path key_path = sub_path / NAME_KEY;
		auto key = key_summon(key_path, rng, false, opts.algo, opts.algo_param);
		if(!key) return 2;

		std::cerr << "Creating cert for " << fqdn << "..." << std::endl;
		X509_Cert_Options copt(fqdn +"/"+ opts.country +"/"+ domain_base.string(), opts.duration);

		std::map<std::string, Key_Constraints> algo_constr_map
		{
			{ "RSA"s,  Key_Constraints(DIGITAL_SIGNATURE | KEY_ENCIPHERMENT) },
			{ "ECDSA"s,  Key_Constraints(DIGITAL_SIGNATURE) },
			{ "Curve25519"s,  Key_Constraints() },
		};

		if(const auto kci = algo_constr_map.find(opts.algo); kci != algo_constr_map.end())
			copt.constraints = kci->second;
		else
			copt.constraints = Key_Constraints(DIGITAL_SIGNATURE); // worst most of the time

		copt.add_ex_constraint("PKIX.ServerAuth");
		copt.dns = fqdn;

		const auto crt = ca->sign_request(X509::create_cert_req(copt, *key, opts.hash, rng), rng, copt.start, copt.end);
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
