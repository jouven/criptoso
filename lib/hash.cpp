#include "hash.hpp"
//crc32c
#include "crc32cso/crc32c.hpp"
//xxhash
#include "xxhashso/xxhash.h"
//cryptopp
#include <hex.h>
#include <sha.h>
#include <whrlpool.h>
#include <base64.h>
#include <integer.h>

#ifdef DEBUGJOUVEN
#include "comuso/loggingMacros.hpp"
#include "backwardSTso/backward.hpp"
#endif

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <vector>

#define BUFFERSIZE 32768
//#define TENGIGABYTES 10737418240L

struct XXH64_state_s
{
   uint_fast64_t total_len;
   uint_fast64_t v1;
   uint_fast64_t v2;
   uint_fast64_t v3;
   uint_fast64_t v4;
   uint_fast64_t mem64[4];   /* buffer defined as U64 for alignment */
   uint_fast64_t memsize;
};
typedef XXH64_state_s XXH64_state_t;
//#define DISPLAYRESULT(...) fprintf(stdout, __VA_ARGS__)
//static void BMK_display_BigEndian(const void* ptr, size_t length)
//{
//	const uint8_t* p = (const uint8_t*)ptr;
//	size_t index;
//	for (index=0; index<length; index++)
//	DISPLAYRESULT("%02x", p[index]);
//}

namespace eines
{
namespace crypto
{
namespace hash
{

class hasher_c::Impl_c
{
	private:
		bool emptyInput_pri = false;
		inputType_ec inputType_pri = inputType_ec::empty;
		std::string input_pri;
		outputType_ec outputType_pri = outputType_ec::empty;
		hashType_ec hashType_pri = hashType_ec::empty;

		std::vector<byte> digest_pri;

		uint_fast64_t hashResult_pri = 0; //for crc32c or xxhash
		bool hashResultSet_pri = false;
		std::string hashResultStr_pri;
	public:
		Impl_c() = default;
		Impl_c(
			const inputType_ec inputType_par_con,
			const std::string& input_par_con,
		    const outputType_ec outputType_par_con,
			const hashType_ec hashType_par_con) :
		    	inputType_pri(inputType_par_con),
				input_pri(input_par_con),
				outputType_pri(outputType_par_con),
				hashType_pri(hashType_par_con)
		{}
		~Impl_c() = default;

		void executeOperation_f()
		{
//#ifdef DEBUGJOUVEN
//			DEBUGSOURCEBEGIN
//#endif
			if (not input_pri.empty())
			{
//#ifdef DEBUGJOUVEN
//				std::cout << DEBUGDATETIME << "_input.size() > 0\n";
//#endif
				switch (inputType_pri)
				{
					case inputType_ec::file:
						{
							std::ifstream inFile(input_pri);
							if (inFile.is_open())
							{
								doHash_f(inFile);
								doEncode_f();
							}
						}
						break;
					case inputType_ec::string:
						{
							std::istringstream inStream(input_pri);
							doHash_f(inStream);
							doEncode_f();
						}
						break;
					case inputType_ec::empty:
						{
							return;
						}
						break;
				};
			}
//#ifdef DEBUGJOUVEN
//			DEBUGSOURCEEND
//#endif
		}

		void doHash_f(std::istream& inStream_par)
		{
//#ifdef DEBUGJOUVEN
//			DEBUGSOURCEBEGIN
//#endif
			inStream_par.seekg(0, inStream_par.end);
			size_t length = inStream_par.tellg();
			if (length == 0)
			{
				emptyInput_pri = true;
				return;
			}
			inStream_par.seekg(0, inStream_par.beg);
			uint_fast32_t readSize(0);
			std::vector<char> buffer;
			if (length > BUFFERSIZE)
			{
				buffer.reserve(BUFFERSIZE);
				readSize = BUFFERSIZE;
			}
			else
			{
				buffer.reserve(length);
				readSize = length;
			}

			//char buffer[BUFFERSIZE];
			switch (hashType_pri)
			{
				case hashType_ec::crc32c:
					{
						while (inStream_par.read(&buffer[0], readSize))
						{
							hashResult_pri = crc32c_append(hashResult_pri,
														reinterpret_cast<const uint8_t*>(&buffer[0]),
														readSize);
						}
						if (inStream_par.gcount() > 0)
						{
							hashResult_pri = crc32c_append(hashResult_pri,
														reinterpret_cast<const uint8_t*>(&buffer[0]),
														inStream_par.gcount());
						}
						hashResultSet_pri = true;
					}
					break;
				case hashType_ec::XXHASH64:
					{
						#define XXHSUM64_DEFAULT_SEED 0
						if (length > BUFFERSIZE)
						{
							XXH64_state_t state64;
							XXH64_reset(&state64, XXHSUM64_DEFAULT_SEED);
							//std::cout << "canResult: 2\n";
							while (inStream_par.read(&buffer[0], readSize))
							{
								XXH64_update(&state64, &buffer[0], readSize);
							}
							if (inStream_par.gcount() > 0)
							{
								XXH64_update(&state64, &buffer[0], inStream_par.gcount());
							}
							//std::cout << "canResult: 3\n";
							hashResult_pri = XXH64_digest(&state64);
						}
						else
						{
							inStream_par.read(&buffer[0], readSize);
							hashResult_pri = XXH64(&buffer[0], readSize, XXHSUM64_DEFAULT_SEED);
						}
						hashResultSet_pri = true;
					}
					break;
				case hashType_ec::whirlpool:
					{
						CryptoPP::Whirlpool hash;
						while (inStream_par.read(&buffer[0], readSize))
						{
							hash.Update(reinterpret_cast<const byte*>(&buffer[0]), readSize);
						}
						if (inStream_par.gcount() > 0)
						{
							hash.Update(reinterpret_cast<const byte*>(&buffer[0]), inStream_par.gcount());
						}
						digest_pri.resize(CryptoPP::Whirlpool::DIGESTSIZE);
						hash.Final(&digest_pri[0]);
					}
					break;
				case hashType_ec::SHA256:
					{
						CryptoPP::SHA256 hash;
						while (inStream_par.read(&buffer[0], readSize))
						{
							hash.Update(reinterpret_cast<const byte*>(&buffer[0]), readSize);
						}
						if (inStream_par.gcount() > 0)
						{
							hash.Update(reinterpret_cast<const byte*>(&buffer[0]), inStream_par.gcount());
						}
						digest_pri.resize(CryptoPP::SHA256::DIGESTSIZE);
						hash.Final(&digest_pri[0]);
					}
					break;
				case hashType_ec::empty:
					{
						return;
					}
					break;
			};
//#ifdef DEBUGJOUVEN
//			DEBUGSOURCEEND
//#endif
		}

		void doEncode_f()
		{
//#ifdef DEBUGJOUVEN
//			DEBUGSOURCEBEGIN
//#endif
			if (emptyInput_pri)
			{
				hashResultStr_pri = "-1";
				return;
			}

			switch (outputType_pri)
			{
				case outputType_ec::base64:
					{
						if (hashResultSet_pri)
						{
							hashResultStr_pri = CryptoPP::IntToString<uint_fast64_t>(hashResult_pri, 64);
						}

						if (hashResultStr_pri.empty() and not digest_pri.empty())
						{
							CryptoPP::Base64Encoder encoder;
							encoder.Attach(new CryptoPP::StringSink(hashResultStr_pri));
							encoder.Put(&digest_pri[0], digest_pri.size());
							encoder.MessageEnd();
						}
					}
					break;
				case outputType_ec::hex:
					{
						if (hashResultSet_pri)
						{
							hashResultStr_pri = CryptoPP::IntToString<uint_fast64_t>(hashResult_pri, 16);
						}

						if (hashResultStr_pri.empty() and not digest_pri.empty())
						{
							CryptoPP::HexEncoder encoder;
							encoder.Attach(new CryptoPP::StringSink(hashResultStr_pri));
							encoder.Put(&digest_pri[0], digest_pri.size());
							encoder.MessageEnd();
						}
					}
					break;
				case outputType_ec::empty:
					{
						return;
					}
					break;
			};
//#ifdef DEBUGJOUVEN
//			DEBUGSOURCEEND;
//#endif
		}
		const response_s getResponse_f() const
		{
			return response_s(emptyInput_pri, hashResult_pri, hashResultStr_pri);
		}
};
hasher_c::hasher_c() : impl_pri(std::make_unique<hasher_c::Impl_c>())
{}
hasher_c::hasher_c(const inputType_ec inputType_par_con
                   , const std::string& input_par_con
                   , const outputType_ec outputType_par_con
                   , const hashType_ec hashType_par_con) :
	impl_pri(std::make_unique<hasher_c::Impl_c>(inputType_par_con, input_par_con, outputType_par_con, hashType_par_con))
{}
////copy ctor
//hasher_c::hasher_c(const hasher_c& src) = delete;
//hasher_c& hasher_c::operator=(const hasher_c& src) = delete;
////move ctors
//hasher_c::hasher_c(hasher_c&&) = delete;
//hasher_c& hasher_c::operator=(hasher_c&&) = delete;
//dtor
hasher_c::~hasher_c() = default;
void hasher_c::executeOperation_f()
{
	impl_pri->executeOperation_f();
}
const hasher_c::response_s hasher_c::getResponse_f() const
{
	return impl_pri->getResponse_f();
}

}
}
}
