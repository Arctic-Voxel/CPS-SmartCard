# Correlation Power Analysis
Welcome to Correlation Power Analysis, CZ4055 Cyber Physical System Lab.
## Requirements
The following is required for the experiment:

Waveform file (csv/excel): 
  - This file contains the full power trace for the victim device, for simplicity, the device would issue a trigger signal before and after encrpytion, which will determine the portion of the trace to collect

Python:
- This experiment is run with Python v3.11.2 

Required packages can be found under requirements.txt


##  Concept
Correlation Power Analysis (CPA) is an efficient technique for recovering secret key bytes of an algorithm by analyzing the power traces of its execution. This experiment focuses on AES-128 encryption.
### AES
![alt text](original_flow.png)

AES utilises four methods for encryption:
- SubBytes
- ShiftRows
- MixColumns
- AddRoundKey

The SubBytes operation requires information from the SBox, which is located in the memory. Power consumption can be detected depeding on the number of bits switching from one state to another. Given this, we can then build a hypothetical model for all possible  bytes (0x00 - 0xFF). 

By running the encryption multiple times and doing a Pearson Correlation between the actual and generated power traces, we are able to determine the byte with the highest correlation; the key byte.

## Initialising
To start, install the required python packages in your environment

```$ pip install -r requirements.txt```

Run the main file with the path of the waveform file as an argument

```$ python main.py waveform.csv```

Ensure sufficient time is allocated for the experiment, as CPA has a significantly large runtime without parallelisation.

## Result
A folder ```KeyGraphs``` will be created, containing the correlation graphs of each Key Byte. (Yes I know it looks ugly :/ ). 

A key.txt file will be created, containing the KeyBytes in hexadecimal format. 
