################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../lib/hash.cpp 

OBJS += \
./lib/hash.o 

CPP_DEPS += \
./lib/hash.d 


# Each subdirectory must supply rules for building sources it contributes
lib/%.o: ../lib/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	ccache g++ -std=c++14 -I/home/jouven/sources/plain/cryptopp-CRYPTOPP_5_6_5 -I/home/jouven/mylibs/include/ -O2 -g -c -fmessage-length=0 -mtune=sandybridge -flto=jobserver -fPIC -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


