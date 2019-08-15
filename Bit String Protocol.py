import random
import argparse
import math
import copy
import time

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
    #print(val) # Use to track what the current sigma is

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


# Main loop for multiple trials
# Note: this loop can be placed before Step 1 to create a fresh library each trial, yet this saves time
while loop_counter < 100:

    print("\033[1m" + 'Trial ', loop_counter + 1, "\033[0;0m")

    # While mu is too small, repeat from Step 2
    while True:

        # (2) Initialization of Protocol 2 ========================================================================================

        # Checks parity of R (just in case)
        if R % 2 != 0:
            print('[ERROR] R is not even')
            exit(0)

        # Selects random sigma and P
        sigma = random.choice(list(sigma_set))
        P = random.choice(list(P_set))
        P_round = round(1 - P, 1)   # We calculate 1-P as use that as our 'printed' P value
        # This is done so that our table of values created by the first program is matched here
        # e.g., values of q created by P actually lie in the table for 1-P

        print('Chosen private values:', '\n\tP = ', P_round, '\n\tsigma = ', sigma)

        # (3) Building a bit string ==========================================================================================

        print("Step 2: Creating Alice's random bit string")

        # Generates a random integer k in given bounds
        k = random.randint(int(math.sqrt(R)), R / 2)

        # Guarantees k is even (this is used to guarantee Q1 and Q0 are integers by our method of generation)
        if k % 2 == 1:
            k += 1

        # Coin flip to decide if k should be negative
        flip = random.randint(0, 1)
        if flip == 1:
            k = k * -1

        # Initializes an empty bit string
        bit_string = [0] * R

        # Q1_holder is the number of 1's we will place randomly in the string
        Q1_holder = int((k + R) / 2)

        # Randomly selects a Q1_holder number of indices to be changed to 1
        position_list = random.sample(range(R), Q1_holder)
        for position in position_list:
            bit_string[position] = 1

        # Number of 1's
        Q1_original = sum(bit_string)
        # Number of 0's
        Q0_original = R - Q1_original

        # Alternate expression of Q0
        #diffQ0 = int((R - k) / 2)
        #assert(diffQ0, '\t', Q0_original)

        # Checks if the formula for k holds
        assert (k == Q1_original - Q0_original)

        # Creates a copy of the generated bit string for use in satellite bit string testing
        sat_bit_string = copy.copy(bit_string)

        print('Bit string created with the following values:', '\n\tk = ', k)
        print('\tQ1 = ', Q1_original, '\n\tQ0 = ', Q0_original)


        # (4) Main loop: distorting the bit string ============================================================================

        # Renames library of pairs for simplicity below
        pairs = pairs_dict[sigma]

        # Rename chosen bit string
        convert_pairs = pairs_to_bits[sigma]
        sat_convert_pairs = string_class_dict[sigma]    # Note: this chosen value is a SatelliteString, not a list


        print("Step 3: Distorting Alice's bit string")

        secret_bit = -1 # Initialize Alice's secret bit to an impossible value
        pick = random.randint(1, m + 1) # Choose a random bit in Bob's string
        if pairs[pick][1] == 1:     # If Bob's bit is a 1, Alice chooses the interval [0, Bi]
            secret_bit = 0
        else:
            secret_bit = 1          # If the bit is a 0, she chooses the interval [Bi, n-1]
        assert (secret_bit >= 0)


        # Main loop
        # For each bit in the string
        for i in range(R):

            # Probability to do the correct bit transmission
            if random.random() < P:

                # If Bob's bit does not match Alice's secret bit, she changes it
                if convert_pairs[i] == (secret_bit + 1) % 2:

                    bit_string[i] = (bit_string[i] + 1) % 2         # this code changes the bit if conditions are met
                    #bit_string[i] = 0 if bit_string[i] else 1      # this code sets the bit to 0 if conditions are met

                # Same as above, but for the satellite bit string
                if sat_convert_pairs.string[0][i] == (secret_bit + 1) % 2:     # Storage of the string of the SatelliteString requires this double index

                    sat_bit_string[i] = (sat_bit_string[i] + 1) % 2         # this code changes the bit if conditions are met
                    #sat_bit_string[i] = 0 if sat_bit_string[i] else 1      # this code sets the bit to 0 if conditions are met

            # 'Incorrectly' transmit bit
            else:

                # If Bob's bit matches Alice's secret bit, she changes it
                if convert_pairs[i] == secret_bit:
                    #bit_string[i] = 0 if bit_string[i] else 1
                    bit_string[i] = (bit_string[i] + 1) % 2

                if sat_convert_pairs.string[0][i] == secret_bit:
                    #sat_bit_string[i] = 0 if sat_bit_string[i] else 1
                    sat_bit_string[i] = (sat_bit_string[i] + 1) % 2

        # Bob's retrieval of b
        for i in range(R):

            # 0 < b < B and Left interval chosen
            if (pairs[i][0] < pairs[i][1]) and (bit_string[i] == 0):
                bit_string[i] = secret_bit # Bob retrieves Alice's chosen interval labeling

            # B < b < n-1 and Right interval chosen
            elif (pairs[i][0] > pairs[i][1]) and (bit_string[i] == 1):
                bit_string[i] = secret_bit

            # other two cases: B < b < n-1 w/ Right interval; 0 < b < B w/ Left interval
            else:
                bit_string[i] = (secret_bit + 1) % 2 # Bob retrieves the other interval


            if (pairs[i][0] < pairs[i][1]) and (sat_bit_string[i] == 0):
                sat_bit_string[i] = secret_bit

            elif (pairs[i][0] > pairs[i][1]) and (sat_bit_string[i] == 1):
                sat_bit_string[i] = secret_bit

            else:
                sat_bit_string[i] = (secret_bit + 1) % 2


        # This code is used to change the satellite string values back
        for i in range(R):
            if sat_convert_pairs.positions[i] == 1:
                sat_bit_string[i] = (sat_bit_string[i] + 1) % 2


        # (5) Computing Q1' - Q0' =========================================================

        # New values after bit string distortion
        Q1_distorted = sum(bit_string)  # Q1'
        Q0_distorted = R - Q1_distorted  # Q0'
        mu = Q1_distorted - Q0_distorted  # Q1' - Q0'

        print('Bit string was distorted to the following values:')
        print('\tQ1* = ', Q1_distorted, '\n\tQ0* = ', Q0_distorted)
        print('\tmu = ', mu)

        sat_Q1_distorted = sum(sat_bit_string)
        sat_Q0_distorted = R - sat_Q1_distorted
        sat_mu = sat_Q1_distorted - sat_Q0_distorted

        print('Satellite bit string was distorted to the following values:')
        print('\tSQ1 = ', sat_Q1_distorted, '\n\tSQ0 = ', sat_Q0_distorted)
        print('\tSmu = ', sat_mu)

        # Requires that mu be a certain size, suggested abs(mu) > 10000
        if abs(mu) > 10000:
            break
        else:
            restarted += 1
            print('Value mu is too small, returning to Step 2', '\n')

    # (6) Computing q ========================================================================================================

    q = 0.5 + mu / (2 * k)
    sat_q = 0.5 + sat_mu / (2 * k)

    print('Probability q = ', round(q, 4))
    print('Satellite Prob q_s = ', round(sat_q, 4))

    # Our test sigma, which we check to see if it lines up with the actual sigma
    sample_sig = 0
    sat_sample_sig = 0

    # Table of values

    if P_round == 0.2:

        if (q >= 0.41) and (q <= 0.425):
            sample_sig = 0.3 * n
        elif (q >= 0.39) and (q <= 0.405):
            sample_sig = 0.4 * n
        elif (q >= 0.368) and (q <= 0.385):
            sample_sig = 0.6 * n
        elif (q >= 0.35) and (q <= 0.365):
            sample_sig = 1.5 * n
        else:
            print('\tq is not in range...')
            bad_range += 1

        if (sat_q >= 0.41) and (sat_q <= 0.425):
            sat_sample_sig = 0.3 * n
        elif (sat_q >= 0.39) and (sat_q <= 0.405):
            sat_sample_sig = 0.4 * n
        elif (sat_q >= 0.368) and (sat_q <= 0.385):
            sat_sample_sig = 0.6 * n
        elif (sat_q >= 0.35) and (sat_q <= 0.365):
            sat_sample_sig = 1.5 * n
        else:
            print('\tq_s is not in range')
            sat_bad_range += 1

    if P_round == 0.3:

        if (q >= 0.44) and (q <= 0.455):
            sample_sig = 0.3 * n
        elif (q >= 0.425) and (q <= 0.435):
            sample_sig = 0.4 * n
        elif (q >= 0.412) and (q <= 0.422):
            sample_sig = 0.6 * n
        elif (q >= 0.40) and (q <= 0.41):
            sample_sig = 1.5 * n
        else:
            print('\tq is not in range...')
            bad_range += 1

        if (sat_q >= 0.44) and (sat_q <= 0.455):
            sat_sample_sig = 0.3 * n
        elif (sat_q >= 0.425) and (sat_q <= 0.435):
            sat_sample_sig = 0.4 * n
        elif (sat_q >= 0.412) and (sat_q <= 0.422):
            sat_sample_sig = 0.6 * n
        elif (sat_q >= 0.40) and (sat_q <= 0.41):
            sat_sample_sig = 1.5 * n
        else:
            print('\tq_s is not in range')
            sat_bad_range += 1

    if P_round == 0.7:

        if (q >= 0.55) and (q <= 0.559):
            sample_sig = 0.3 * n
        elif (q >= 0.562) and (q <= 0.5725):
            sample_sig = 0.4 * n
        elif (q >= 0.575) and (q <= 0.587):
            sample_sig = 0.6 * n
        elif (q >= 0.59) and (q <= 0.60):
            sample_sig = 1.5 * n
        else:
            print('\tq is not in range...')
            bad_range += 1

        if (sat_q >= 0.55) and (sat_q <= 0.559):
            sat_sample_sig = 0.3 * n
        elif (sat_q >= 0.562) and (sat_q <= 0.5725):
            sat_sample_sig = 0.4 * n
        elif (sat_q >= 0.575) and (sat_q <= 0.587):
            sat_sample_sig = 0.6 * n
        elif (sat_q >= 0.59) and (sat_q <= 0.60):
            sat_sample_sig = 1.5 * n
        else:
            print('\tq_s is not in range')
            sat_bad_range += 1

    if P_round == 0.8:

        if (q >= 0.57) and (q <= 0.5875):
            sample_sig = 0.3 * n
        elif (q >= 0.59) and (q <= 0.609):
            sample_sig = 0.4 * n
        elif (q >= 0.615) and (q <= 0.628):
            sample_sig = 0.6 * n
        elif (q >= 0.63) and (q <= 0.65):
            sample_sig = 1.5 * n
        else:
            print('\tq is not in range...')
            bad_range += 1

        if (sat_q >= 0.57) and (sat_q <= 0.5875):
            sat_sample_sig = 0.3 * n
        elif (sat_q >= 0.59) and (sat_q <= 0.609):
            sat_sample_sig = 0.4 * n
        elif (sat_q >= 0.615) and (sat_q <= 0.628):
            sat_sample_sig = 0.6 * n
        elif (sat_q >= 0.63) and (sat_q <= 0.65):
            sat_sample_sig = 1.5 * n
        else:
            print('\tq_s is not in range')
            sat_bad_range += 1

    print('\nOur Sigma = ', sample_sig)

    if sample_sig == sigma:
        counter += 1
        print("\033[1m" + "Success!", "\033[0;0m", 'We correctly guessed sigma!\n')
    else:
        print("\033[1m" + "Failure...", "\033[0;0m" 'We did not get the correct sigma\n')

    print('Satellite Sigma = ', sat_sample_sig)

    if sat_sample_sig == sigma:
        sat_counter += 1
        print("\033[1m" + "Yes!", "\033[0;0m", 'The satellite correctly guessed sigma!\n\n')
    else:
        print("\033[1m" + "No...", "\033[0;0m", 'The satellite failed to guess sigma...\n\n')

    # Increases the loop count
    loop_counter += 1

print('Results:')
print('\tNumber of successes: ', counter)
print('\tNumber of range fails: ', bad_range)
print('\tNumber of true failures: ', loop_counter - (counter + bad_range))
print('\tNumber of mu restarts: ', restarted)

print('\nSatellite Results:')
print('\tNumber of successes: ', sat_counter)
print('\tNumber of range fails: ', sat_bad_range)
print('\tNumber of true failures: ', loop_counter - (sat_counter + sat_bad_range))

elapsed_time = round(time.time() - start_time)
sec = elapsed_time % 60
min = int(elapsed_time / 60) % 60
hr = int(elapsed_time / 3600)
print("\nTime elapsed:", hr, "hours, ", min, "minutes, and ", sec, "seconds.")
