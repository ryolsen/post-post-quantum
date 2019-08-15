#!/usr/bin/env python3

import socket
import random
import argparse
import math
import copy
import time

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 27501        # The port used by the server

# (0) Initialization =============================================================================
print('\nPublic Key Transport Protocol: Transmitting Bit Strings', '\n')

start_time = time.time()

# Note: prefix sat_ indicates that the object is used for the satellite bit string,
#       and performs the same functions as the original object for the satellite

# Initialize variables
loop_counter = 0    #Tracks current loop trial
counter = 0         #Counts number of successes
bad_range = 0       #Counts number of times probability q does not fall in given ranges
sat_counter = 0
sat_bad_range = 0
restarted = 0       #Counts number of times mu needs to be recalculated

# Get parameters
# Suggested parameters: m = R = 5000000, n = 100
parser = argparse.ArgumentParser(prog='Information Security', usage='Gets the required parameters m, n, R')
parser.add_argument('-m', default=5000000, metavar='m', type=int,
                    help='Integer > 0, number of pairs')
parser.add_argument('-n', default=100, metavar='n', type=int,
                    help='Natural number, defines boundary of interval [0, n-1] for b')
parser.add_argument('-R', default=5000000, metavar='R', type=int,
                    help='Even integer > 0, length of bit string, MUST be equal to m')
args = parser.parse_args()

# Re-naming parameters
m, n, R = args.m, args.n, args.R
assert(m == R)
# Bounds for B
B_more_than, B_less_than = 1, n - 2

# Random number generator
random.seed()


# (1) Creating pairs (b_i, B_i) ==========================================================================================

print("Step 1: Creating Bob's (b, B) pairs and converting them into bit strings", '\n\t', "[this might take a minute...]")

# Initializing the "libraries"
pairs_dict = dict()          # Initializing the "library" of pairs (b_i, B_i), for each value of sigma
pairs_to_bits = dict()       # Initialize dictionary of converted pair bit strings
string_class_dict = dict()   # Creates a dictionary for class SatelliteString

# Initialize sigma and P sets
sigma_set = {0.3 * n, 0.4 * n, 0.6 * n, 1.5 * n}
P_set = {0.2, 0.3, 0.7, 0.8}


# Creates a class for the satellite strings in order to conveniently hold information
class SatelliteString:

    # Initialization of a class variable
    def __init__(self, *args):
        self.string = args      # Note: this class must be supplied with an arg to make the functions work
        self.number = random.randint(1, m + 1)  # Pseudo-random generation of an integer for number of indices to change
        self.indices = random.sample(range(len(self.string[0])), self.number) # Randomly selects which indices to change
        self.positions = [0] * m                                              # Used to store changed positions

    # Call to change random indices of the satellite bit string
    def change_and_save_places(self):

        for g in self.indices:
            self.string[0][g] = (self.string[0][g] + 1) % 2 # change specific bit
            self.positions[g] = 1   # store changed location


# For each sigma, make a list of pairs, create its bit string, and create a copy of the bit string to be altered
for val in sigma_set:
    print(val) # Use to track what the current sigma is

    # Initialize empty lists
    pairs_dict[val] = list()        # List used for pair values
    pairs_to_bits[val] = list()     # List used for bits

    # Pair creation main loop
    # While the number of pairs in the library is < m, keep creating new pairs
    while len(pairs_dict[val]) < m:

        # (i) Selecting b_i
        b = random.randint(0, n - 1)

        # (ii) Selecting B_i
        B = random.normalvariate(b, val)

        # (iii) Dropping B_i that lie outside the interval [1, n-2]
        if B_more_than <= B <= B_less_than and B != ((n - 1) / 2):
            pair = (b, B)
            pairs_dict[val].append(pair)

            # Create Bit String
            if pair[1] >= (n - 1) / 2:          # If B is greater than the midpoint,
                pairs_to_bits[val].append(1)    # Add a 1 to the string
            else:
                pairs_to_bits[val].append(0)    # Else add a 0

    # For the given sigma value, create a SatelliteString object, and supply its string a copy of the respective bit string
    string_class_dict[val] = SatelliteString(copy.copy(pairs_to_bits[val]))
    # For each SatelliteString, change random indices and store the changed locations
    string_class_dict[val].change_and_save_places()

print('...done!', '\n')



with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(bytes(pairs_to_bits[val]))
    data = s.recv(1024)

print('Received', repr(data))