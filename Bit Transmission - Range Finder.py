import random
import argparse

# (0) Initialization =============================================================================

Q_List = []  # Keeps a list of q values
trial = 0  # Tracks current loop
testmin = 10000  # Used to display updates for max and min values
testmax = -10000

inputP = ""
while True:
    try:
        inputP = float(input('Enter p: '))  # User input P value and attempts to convert to float
    except ValueError:
        print("Invalid positive float value, please enter p: ")    # If not float, prompt again
        continue
    else:           # Exits loop when true
        break

inputSig = ""
while True:
    try:
         # sigma = {0.3, 0.4, 0.6, 1.5}
         inputSig = float(input('Enter sigma constant (e.g. sigma = constant * n): '))  # user input sigma
    except ValueError:
        print("Invalid positive float value, please enter new constant: ")
        continue
    else:
        break

assert(inputP > 0) and (inputSig > 0) #Checks that values are positive

# Argument parser for parameters m, n, N, P;  used for command line
parser = argparse.ArgumentParser(prog='Information Security', usage='Gets the required parameters m, n, N, P')

parser.add_argument('-m', default=30000, metavar='m', type=int,
                    help='Integer > 0, number of pairs')
parser.add_argument('-n', default=100, metavar='n', type=int,
                    help='Natural number, defines boundary of interval [0, n-1] for b')
parser.add_argument('-N', default=500000, metavar='R', type=int,
                    help="Large integer > 0, number of times to test a Bob's pair against the labeled interval")
parser.add_argument('-P', default=inputP, metavar='P', type=float,
                    help='Real number in the interval [0, 1], probability to mark the interval [B, n-1] with bit one')
args = parser.parse_args()

# Rename parameters
m, n, N, P = args.m, args.n, args.N, args.P
print

B_more_than, B_less_than = 1, n - 2  # bounds for B

while trial < 100:

    # Initialize the random number generator
    random.seed()

    # (1) Creating (b_i, B_i) pairs ==========================================================================================

    # Initialization of the list of (b_i, B_i) pairs
    pairs = list()

    # Selecting sigma
    sigma = inputSig * n  # From user input

    # Main loop for creating (b_i, B_i) pairs
    while len(pairs) < m:  # While the number of pairs in the list is < m, we keep creating more pairs
        # (i) Selecting b_i
        b = random.randint(0, n - 1)

        # (ii) Selecting B_i
        B = random.normalvariate(b, sigma)

        # (iii) Discarding B_i if outside the interval
        # Adding a pair (b_i, B_i) to the list only if B_i is inside the interval 
        if ((B_more_than <= B <= B_less_than) and (B != (n - 1) / 2)):
            pair = (b, B)
            pairs.append(pair)



    # (2) Computing q experimentally =============================================================================
    # Initialize counter which tracks the number of b that lie in the intervals where Alice's bit is 1
    counter = 0

    # Main loop
    for i in range(N):
        # (i) Select a random (b_i, B_i) pair from the list
        b, B = random.choice(pairs)

        # (ii) Out of intervals [0, B) and (B, n-1], with probability P, label the larger interval with bit 1,
        #  and with probability 1 - P, label the larger interval 0

        if random.random() < P:
            # longer of the intervals is labeled 1
            if ((B < b <= n - 1) and (B < (n - 1) / 2)) or ((0 <= b < B) and (B > (n - 1) / 2)):
                # Bob retrieves b from interval where bit is 1
                counter += 1
        else:
            # shorter of the intervals is labeled 1
            if ((B < b <= n - 1) and (B > (n - 1) / 2)) or ((0 <= b < B) and (B < (n - 1) / 2)):
                counter += 1

    # Prints counter
    # print('Number of b in the intervals labeled 1:', counter)

    # (3) Computing q =======================================================================================

    q = counter / N  # Probability of successful retrieval
    Q_List.append(q)
    iconup = '\u25b2'
    icondown = '\u25bc'
    if q < testmin:
        testmin = q
        print(trial + 1, ' ', icondown, 'q=:', format(q, '.12g'))    # Displays if current q is a new max or min
    if q > testmax:
        testmax = q
        print(trial + 1, ' ', iconup, 'q=:', format(q, '.12g'))
    trial += 1

minimum = 10000
maximum = -10000
for x in Q_List:        # Scans through Q list and picks out max and min
    if x < minimum:     # This step is not necessary, as testmin/testmax should always be equivalent to this max/min
        minimum = x     # For large number of trials, omit this step for efficiently, else it works as a fail safe
    if x > maximum:
        maximum = x

print('minimum: ', minimum, ' maximum: ', maximum)
#print('tmin ', testmin, 'tmax', testmax)
print('p=: ', P, ' sigma=: ', sigma / n, '*n')
print('\a')
