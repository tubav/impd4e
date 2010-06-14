################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../bobhash.o \
../hash.o \
../hsieh.o \
../main.o \
../twmx.o 

C_SRCS += \
../bobhash.c \
../hash.c \
../hsieh.c \
../main.c \
../twmx.c 

OBJS += \
./bobhash.o \
./hash.o \
./hsieh.o \
./main.o \
./twmx.o 

C_DEPS += \
./bobhash.d \
./hash.d \
./hsieh.d \
./main.d \
./twmx.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I/usr/local/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

main.o: ../main.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -Iipfix -Imisc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"main.d" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


