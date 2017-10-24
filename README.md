# criptoso
C++ library to hash string or files in several types of hash (crc32c, xxhash, whirlpool and SHA256)

The folder structure comes from eclipse. Requires https://github.com/jouven/crc32cso, https://github.com/Cyan4973/xxHash in library form (I use master, don't know about dev) and https://github.com/weidai11/cryptopp, Debug additionally depends on https://github.com/bombela/backward-cpp it links, dynamically, against it, the name I choose for it as a dynamic library is backwardSTso, https://github.com/jouven/timeso, boost_date_time and a macro header (only) found in https://github.com/jouven/comuso.

There are some fixed paths on the make files, "-L/usr/local/lib" and "-L/home/jouven/mylibs/debug" might need to be edited/removed depending on the circumstances.
