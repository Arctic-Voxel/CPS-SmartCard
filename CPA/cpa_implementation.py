# Online Python compiler (interpreter) to run Python online.
# Write Python 3 code in this online editor and run it.

# https://trinket.io/embed/python3

import random
import matplotlib.pyplot as plot
import pandas as pd
import numpy as np
import os
import scipy
def hw(int_no):
    # Write Code to calculate the number of ones in a byte...
    c = 0
    while(int_no):
        int_no &= (int_no - 1)
        c += 1
    return c

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
# =========To Change to read the first bytes from waveform============
# Here, we generate random values for first byte of plaintext...
#  This is the array containing first byte of all the plaintexts...
# print(os.getcwd())
waveformFile = pd.read_csv("waveform.csv",index_col=None,header=None)
no_of_traces = waveformFile.shape[0]
firstBytes = []
plaintextRow = waveformFile.iloc[:,0]
print(plaintextRow)
for index in range(0,no_of_traces):
    firstBytes.append(int(plaintextRow[index][0],16))

# print("\nFirst byte of plaintexts.... This is the array containing first byte of all the plaintexts...\n")
# print(firstBytes)

# Now, let us try to build a model for all possible values of key byte using the plaintext inputs...

# Let a given first plaintext byte be denoted as x... For each first plaintext byte x, try to calculate Sbox(x xor k) where k is the first key byte...
# For example, let us build a model for k = 0x20...

k = 0x20
leaky_sbox_output_value_array = []
print("\n\nValue of Leaky Sbox values for first plaintext byte....\n")

# Write Code to fill up the leaky_sbox_output_value_array with Sbox(x xor k).

for byte_pos in range(0,no_of_traces):
    byte_now = firstBytes[byte_pos] ^ k
    Sbox_output_leaky_value = Sbox[byte_now]
    leaky_sbox_output_value_array.append(Sbox_output_leaky_value)

# print(leaky_sbox_output_value_array)

# Now, we know these are the leaky values... How do these values leak through the power side-channel... They leak as their hamming weights... So, we need to
# calculate the hamming weight of these leaky values...

hamming_weight_of_leaky_sbox_bytes = []
print("\n\nHamming Weight of Leaky Sbox values for first plaintext byte....\n")

# Write Code to fill up the hamming_weight_of_leaky_sbox_bytes with HW(Sbox(x xor k))...

for byte in range(0,no_of_traces):
    hamming_weight_of_leaky_sbox_bytes.append(hw(leaky_sbox_output_value_array[byte]))

# print(hamming_weight_of_leaky_sbox_bytes)

# hamming_weight_of_leaky_sbox_bytes is your hypothetical Power Model for k = 20...

# But, as an attacker you do not know what is the value of k, then you try to build a model for all values of k...

# Write Code to build a hypothetical power model for all values of k... This is called a power model matrix...

no_of_possible_values_of_key_byte = 256
power_model_matrix = [[]]*no_of_possible_values_of_key_byte

for key_byte_guess in range(0,no_of_possible_values_of_key_byte):
    k = key_byte_guess

    leaky_sbox_output_value_array = []
    for byte_pos in range(0,no_of_traces):
        byte_now = firstBytes[byte_pos] ^ k
        Sbox_output_leaky_value = Sbox[byte_now]
        leaky_sbox_output_value_array.append(Sbox_output_leaky_value)

    hamming_weight_of_leaky_sbox_bytes = []
    for byte in range(0,no_of_traces):
        hamming_weight_of_leaky_sbox_bytes.append(hw(leaky_sbox_output_value_array[byte]))

    power_model_matrix[key_byte_guess] = hamming_weight_of_leaky_sbox_bytes

# print(power_model_matrix)

# Now, we need to match the power model for each key byte guess, with the actual power trace...

# Here, we generate an actual power trace through simulations...

# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

noise_standard_deviation = 0.05

def generate_random_noise():
    n = random.normalvariate(0,noise_standard_deviation)
    return n

def generate_trace(trace_input):
    low_value = 0
    high_value = 8
    noisy_trace = []
    for i in range(0,len(trace_input)):
        trace_point = (trace_input[i]-float(low_value))/high_value + generate_random_noise()
        noisy_trace.append(trace_point)

    return noisy_trace

correct_key_byte = 21
correct_ideal_trace = power_model_matrix[correct_key_byte]
actual_power_trace = generate_trace(correct_ideal_trace)

# %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

# The actual power trace contains the trace corresponding to the Sbox operation... This corresponds to the key byte = 21...
# Now, lets try to match the hypothetical power model for all key bytes with the actual power trace...and see which one matches the best...
# Here, we use the pearson correlation coefficient to calculate relation between the hypothetical power model and actual trace...
# Use scipy.stats.pearsonr(vector1, vector2) to compute correlation between two vectors...

correlation_values = []

# Write code to compute correlation between model trace of every possible value of key byte and the actual trace and fill
# up the correlation_values array...

for key_byte_guess in range(0,no_of_possible_values_of_key_byte):
    model_trace = power_model_matrix[key_byte_guess]
    corr_value = scipy.stats.pearsonr(actual_power_trace,model_trace)
    correlation_values.append(corr_value[0])

# Here, we are sorting the correlation values and identifying which key byte has the largest correlation...

sorting_order = np.argsort(correlation_values)
sorting_order = sorting_order[::-1]

# Here, we identify the rank of the correct key byte...

rank_of_correct_key_byte = np.where(sorting_order == correct_key_byte)

print("No. of Traces: {}".format(no_of_traces))
print("Rank of Correct Key Byte: {}".format(rank_of_correct_key_byte[0]+1))

################################################################# Visualization Code #################################################

# Here, I am plotting correlation values for all key bytes...

plot.figure(1)

x_index = []
for i in range(0,no_of_possible_values_of_key_byte):
  x_index.append(i)
  
plot.plot(x_index,correlation_values)
plot.show()