#ifndef CRIPTOSO_HASHER_H_
#define CRIPTOSO_HASHER_H_

#include <memory>
#include <string>


namespace eines
{
namespace crypto
{
namespace hash
{
class hasher_c
{
	public:
		struct response_s
		{
			const bool emptyInput_pub_con = true;
			//crc32c or xxhash
			const uint_fast64_t hashResult_pub_con = 0;
			//for everything
			const std::string hashResultStr_pub_con;
			response_s() = default;
			response_s(
				const bool emptyInput_par_con
				, const uint_fast64_t hashResult_par_con
			    , const std::string& hashResultStr_par_con
			           ) :
				   emptyInput_pub_con(emptyInput_par_con)
				   , hashResult_pub_con(hashResult_par_con)
				   , hashResultStr_pub_con(hashResultStr_par_con)
			{}
			bool operator==(const response_s& b_par_con) const
			{
				return b_par_con.hashResult_pub_con == hashResult_pub_con
				       and b_par_con.hashResultStr_pub_con == hashResultStr_pub_con
				       and b_par_con.emptyInput_pub_con == emptyInput_pub_con;
			}
		};
		enum class inputType_ec
		{
			empty, string, file
		};
		//empty works for crc32c and xxhash because it outputs to hashResult (a 64 bit unsigned integer)
		//the others need hex or base64, they are too big to fit in a 64bit integer
		enum class outputType_ec
		{
			empty,
			hex,
			base64
		};
		enum class hashType_ec
		{
			empty, crc32c, whirlpool, SHA256, XXHASH64
		};
		class Impl_c;
	private:
		std::unique_ptr<Impl_c> impl_pri;
	public:
		hasher_c();
		hasher_c(
			const inputType_ec inputType_par_con
			, const std::string& input_par_con
			, const outputType_ec outputType_par_con
			, const hashType_ec hashType_par_con
		);

		//copy constructor
		hasher_c(const hasher_c& src) = delete;
		hasher_c& operator=(const hasher_c& src) = delete;
		//move ctor
		hasher_c(hasher_c&&) = delete;
		hasher_c& operator=(hasher_c&&) = delete;
		//dtor
		~hasher_c();

		void executeOperation_f();
		const response_s getResponse_f() const;
};

}
}
}
#endif /* CRIPTOSO_HASHER_H_ */
