###############################################################################
#                                                                             #
#         ~    .__ °.__   0       o                    ^   .__ °__  `´        #
#  °____) __ __|  | | °|   ______°____ 0 ____  __ _________|__|/  |_ ___.__.  #
#  /    \|  | °\  |°|  | °/  ___// __ \_/ ___\|  | °\_  __ \ o\   __<   |  |  #
# | o°|  \  |  /  |_|  |__\___ \\  ___/\ °\___| o|  /|  | \/  ||  |° \___ O|  #
# |___|  /____/|____/____/____ °>\___  >\___  >____/ |__|° |__||__|  / ____|  #
# `´´`´\/´`nullsecurity team`´\/`´´`´\/`´``´\/  ``´```´```´´´´`´``0_o\/´´`´´  #
#                                                                             #
# Hyperion: A runtime PE-Crypter                                              #
#                                                                             #
# VERSION                                                                     #
# 2.0                                                                         #
#                                                                             #
# DATE                                                                        #
# 08/06/2019                                                                  #
#                                                                             #
# AUTHOR                                                                      #
# belial - http://www.phobosys.de/hyperion                                    #
#                                                                             #
# LICENSE                                                                     #
# BSD-License                                                                 #
#                                                                             #
# DESCRIPTION                                                                 #
# Hyperion is a runtime encrypter for 32/64 bit portable executables. It is a #
# reference implementation and bases on the paper "Hyperion: Implementation   #
# of a PE-Crypter". The paper describes the implementation details which      #
# aren't in the scope of this readme file.                                    #
# The crypter is a C project and can be compiled with the corresponding       #
# makefile (tested with Mingw and Visual Studio). Afterwards it is started    #
# via the command line and encrypts an input executable with AES-128. The     #
# encrypted file decrypts itself on startup (bruteforcing the AES key which   #
# may take a few seconds) and generates a log file for debug purpose.         #
#                                                                             #
# TODO                                                                        #
# - Support late Binding of DLLs/APIs                                         #
# - AV evasion (obfuscate sbox, strings, reduce entropy, etc.)                #
# - Polymorphic generation of the container                                   #
# - Add .NET Support                                                          #
# - Preserve Icon and GUI/Console Flag                                        #
# - Check for correct DLL Version Numbers before Loading                      #
# - 64 bit asm code cleanup (container and aes payload)                       #
# - Remove macros in Asm Code                                                 #
#                                                                             #
# CHANGELOG:                                                                  #
#                                                                             #
# v2.0:                                                                       #
# - added 64-bit support                                                      #
# - upgraded fasm.exe to 1.71                                                 #
# - flexible payload structure to add your own ecryption algos                #
# - removed c++ code and added pure c instead                                 #
#                                                                             #
# v1.2:                                                                       #
# - added windows 8 and 8.1 support (thx to CoolOppo)                         #
#                                                                             #
# v1.1:                                                                       #
# - code cleanup and refactoring (more leightweighted and increased           #
#   maintainability)                                                          #
# - change key space size via the command line                                #
# - change key length via the command line                                    #
# - disable logfile generation of the container via commandline               #
# - display verbose informations while running                                #
#                                                                             #
# v1.0:                                                                       #
# - initial release                                                           #
#                                                                             #
###############################################################################
