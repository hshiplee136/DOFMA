import warnings
warnings.filterwarnings("ignore")

import pickle
import os
import psutil
import argparse
import createminidump
from minidumpshell import MinidumpShell
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import csv
import logging
import time

from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer

startInit = time.time() # Timer to measure the initialisation phase

# Load the pickled machine learning algorithms
## MLP
with open('pickled/mlpModules.pkl', 'rb') as file:
    mlpModules = pickle.load(file)

with open('pickled/mlpThreads.pkl', 'rb') as file:
    mlpThreads = pickle.load(file)

## Logistic Regression
with open('pickled/lrMemory.pkl', 'rb') as file:
    lrMemory = pickle.load(file)

with open('pickled/lrModules.pkl', 'rb') as file:
    lrModules = pickle.load(file)

with open('pickled/lrThreads.pkl', 'rb') as file:
    lrThreads = pickle.load(file)

## SGD Classifier
with open('pickled/sgdMemory.pkl', 'rb') as file:
    sgdMemory = pickle.load(file)

with open('pickled/sgdModules.pkl', 'rb') as file:
    sgdModules = pickle.load(file)

with open('pickled/sgdThreads.pkl', 'rb') as file:
    sgdThreads = pickle.load(file)

## Random Forest
with open('pickled/rfMemory.pkl', 'rb') as file:
    rfMemory = pickle.load(file)

with open('pickled/rfModules.pkl', 'rb') as file:
    rfModules = pickle.load(file)

with open('pickled/rfThreads.pkl', 'rb') as file:
    rfThreads = pickle.load(file)

## Decision Tree
with open('pickled/dtMemory.pkl', 'rb') as file:
    dtMemory = pickle.load(file)

with open('pickled/dtModules.pkl', 'rb') as file:
    dtModules = pickle.load(file)

with open('pickled/dtThreads.pkl', 'rb') as file:
    dtThreads = pickle.load(file)

## K Neighbour
with open('pickled/knMemory.pkl', 'rb') as file:
    knMemory = pickle.load(file)

with open('pickled/knModules.pkl', 'rb') as file:
    knModules = pickle.load(file)

with open('pickled/knThreads.pkl', 'rb') as file:
    knThreads = pickle.load(file)

# Define the custom threads preprocessors
# Custom transformer to apply CountVectorizer to each column individually
class DataFrameVectorizer(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.vectorizers = {}

    def fit(self, X, y=None):
        for column in X.columns:
            vectorizer = TfidfVectorizer()
            vectorizer.fit(X[column])
            self.vectorizers[column] = vectorizer
        return self

    def transform(self, X, y=None):
        vectorized_data = []
        for column in X.columns:
            vectorizer = self.vectorizers[column]
            vectorized_column = vectorizer.transform(X[column]).toarray()
            vectorized_data.append(vectorized_column)
        return np.hstack(vectorized_data)

# Custom transformer to apply StandardScaler to each column individually
class DataFrameScaler(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.scalers = {}

    def fit(self, X, y=None):
        for column in X.columns:
            scaler = StandardScaler()
            scaler.fit(X[[column]])
            self.scalers[column] = scaler
        return self

    def transform(self, X, y=None):
        scaled_data = []
        for column in X.columns:
            scaler = self.scalers[column]
            scaled_column = scaler.transform(X[[column]])
            scaled_data.append(scaled_column)
        return np.hstack(scaled_data)
    
# Load the pickled preprocessors
with open('pickled/memoryPreprocessor.pkl', 'rb') as file:
    memoryPreprocessor = pickle.load(file)

with open('pickled/modulePreprocessor.pkl', 'rb') as file:
    modulesPreprocessor = pickle.load(file)

with open('pickled/threadsPreprocessor.pkl', 'rb') as file:
    threadsPreprocessor = pickle.load(file)

# Generate process memory dumps
## Minidump code, can be replaced with other code to generate a process dump
'''def generateDump(processID, dumpPath):
    mindumptype = createminidump.MINIDUMP_TYPE.MiniDumpNormal | createminidump.MINIDUMP_TYPE.MiniDumpWithFullMemory

    createminidump.create_dump(processID, dumpPath, mindumptype, with_debug=False)'''

# Generate process logs
## Minidump code, can be replaced with other code to generate a process log
'''def generateLog(dumpPath, logPath):
    parser = argparse.ArgumentParser(description='A parser for minidumnp files')
    parser.add_argument('-f', '--minidumpfile', help='path to the minidump file of lsass.exe')
    args = parser.parse_args()

    try:
        MiniDumpShell = MinidumpShell()
        MiniDumpShell.do_open(dumpPath)
        MiniDumpShell.do_threads(args, logPath)
    except Exception as e:
        logging.error(f"Error generating log: {e}")'''

# Generate CSV files
def generateCSV(inputDir, filePath, scanPath):
    inputFiles = [os.path.join(inputDir, f) for f in os.listdir(inputDir) if f.endswith('.txt')]
    
    with open(scanPath, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)

        #header = ['VA Start', 'RVA', 'Size', 'PID'] # Write the header row
        #header = ['Module Name', 'Base Address', 'Size', 'Endaddress', 'Timestamp', 'PID']
        header = ['ThreadID', 'SuspendCount', 'PriorityClass', 'Priority', 'Teb', 'PID']
        csvwriter.writerow(header)

        for logPath in inputFiles:
            if logPath == filePath:
                filename = os.path.basename(logPath)
                pid = filename.replace('.txt', '')

                with open(logPath, 'r') as file:
                    lines = file.readlines()[3:]

                '''for line in lines:
                    columns = line.strip().split('|')
                    row = columns + [pid]
                    csvwriter.writerow(row)'''
                for line in lines:
                    if not line.strip():  # Skip empty or whitespace-only lines
                        continue

                    columns = line.strip().split('|')
                    row = [col.strip() for col in columns]  # Remove extra spaces
                    row.append(pid)  # Add PID at the end
                    csvwriter.writerow(row)
            else:
                continue

# Compare new and old logs
def compareFiles(newFile, oldFile):
    with open(newFile, 'r') as nf, open(oldFile, 'r') as of:
        newFile_lines = nf.readlines()
        oldFile_lines = of.readlines()

    if len(newFile_lines) != len(oldFile_lines):
        return 1
    
    for nline, oline in zip(newFile_lines, oldFile_lines):
        if nline != oline:
            return 1
        
    return 0
    
# Evaluate the model
def evaluate_model(processID, model, X_test):
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    proba_class_benign = y_proba[:, 0]
    proba_class_infected = y_proba[:, 1]

    mean_proba_class_0 = np.mean(proba_class_benign)
    mean_proba_class_1 = np.mean(proba_class_infected)

    mean_proba_array = np.array([mean_proba_class_0, mean_proba_class_1])

    benign = 0
    infected = 0
    for i in range(len(y_pred)):
        if y_pred[i] == 0:
            benign += 1
        else:
            infected += 1
    
    total = benign + infected
    benign_percentage = (benign / total) * 100
    infected_percentage = (infected / total) * 100
    
    if (benign_percentage > (infected_percentage + 10)):
        prediction = 'Benign'
    elif infected_percentage > (benign_percentage + 10):
        prediction = 'Infected'
    else:
        prediction = 'Unsure'

    print('Scores are Benign: %s and Infected: %s. Predicted=%s' % (benign, infected, prediction))
    print(f"{processID} Mean probability: {mean_proba_array}")

def remove_files(directory):
    try:
        # List all files in the directory
        files = os.listdir(directory)
        for file in files:
            file_path = os.path.join(directory, file)  # Construct full file path
            if os.path.isfile(file_path):  # Check if it's a file
                os.remove(file_path)
    except Exception as e:
        print(f"Error removing files in {directory}: {e}")

# Main function
def main():
    # Menu
    while True:
        print('Welcome to the DOFMA Process Scanner\n')
        print('Select an option:')
        print('1. Scan user processes')
        print('2. Scan all processes')
        selection = input()

        if selection == '1' or selection == '2':
            break
        else:
            print('\nERROR: PLEASE SELECT A VALID OPTION\n')

    # Option 1: User Processes
    if selection == '1':
        print('\nINITIALISING SCAN...\n')

        userProcs = []
        processIDs = []
        logFiles = []
        excludedNames = ['Code.exe', 'conhost.exe', 'mc-fw-host.exe'] # Excluded processes because they break the script

        userName = os.getlogin()
        computerName = os.environ['COMPUTERNAME'].upper()
        user = f'{computerName}\\{userName}' # Generate the username

        for proc in psutil.process_iter(['pid', 'name', 'username']):
            userProcs.append(proc.info) # Retrieve the process information

        for userProc in userProcs:
            if userProc.get('username') == user and userProc.get('name') not in excludedNames:
                processIDs.append(userProc.get('pid'))

        for processID in processIDs:
            dumpPath = fr'dumps\{processID}.dmp'
            generateDump(processID, dumpPath)

        dumpDir = fr'.\dumps'
        dumpDirectory = os.listdir(dumpDir)

        for processID in processIDs:
            if fr'{processID}.dmp' in dumpDirectory:
                print(fr'{processID}.dmp was created')
            else:
                print(fr'{processID} REMOVED FROM SCAN')
                processIDs.remove(processID)

        for processID in processIDs:
            dumpPath = fr'dumps\{processID}.dmp'
            logPath = fr'logs\{processID}.txt'
            generateLog(dumpPath, logPath)

            try:
                os.remove(dumpPath)
                #print(fr'{processID}.dmp has been deleted')
            except FileNotFoundError:
                print(fr'{processID}.dmp does not exist')
            except PermissionError:
                print(fr'Permission denied: {dumpPath}')
            except Exception as e:
                print(fr'Error: {e}')

        logDir = fr'.\logs'
        logDirectory = os.listdir(logDir)

        for processID in processIDs:
            if fr'{processID}.txt' in logDirectory:
                logFiles.append(fr'.\logs\{processID}.txt')
            else:
                processIDs.remove(processID)

        print('\nINITIALISATION COMPLETE...\n')

        endInit = time.time()
        lengthInit = endInit - startInit
        print(lengthInit, "seconds")
        # End of timer for initialisation phase

        print('\nCOMMENCING SCAN OF USER PROCESSES...\n')

        while True:
            startTest = time.time() # Timer to measure the test phase
            userProcs = []
            processIDs = []
            excludedNames = ['Code.exe', 'conhost.exe', 'mc-fw-host.exe'] # Excluded processes because they break the script

            userName = os.getlogin()
            computerName = os.environ['COMPUTERNAME'].upper()
            user = f'{computerName}\\{userName}' # Generate the username

            for proc in psutil.process_iter(['pid', 'name', 'username']):
                userProcs.append(proc.info) # Retrieve th process information

            for userProc in userProcs:
                if userProc.get('username') == user and userProc.get('name') not in excludedNames:
                    processIDs.append(userProc.get('pid'))

            for processID in processIDs:
                dumpScanPath = fr'dumps\{processID}-scan.dmp'
                generateDump(processID, dumpScanPath)

                dumpDir = fr'.\dumps'
                dumpDirectory = os.listdir(dumpDir)

                if fr'{processID}-scan.dmp' in dumpDirectory:
                    logScanPath = fr'logs\{processID}-scan.txt'
                    generateLog(dumpScanPath, logScanPath)

                    try:
                        os.remove(dumpScanPath)
                        #print(fr'{processID}-scan.dmp has been deleted')
                    except FileNotFoundError:
                        print(fr'{processID}-scan.dmp does not exist')
                    except PermissionError:
                        print(fr'Permission denied: {dumpScanPath}')
                    except Exception as e:
                        print(fr'Error: {e}')

                    logDir = fr'.\logs'
                    logDirectory = os.listdir(logDir)

                    if fr'{processID}.txt' in logDirectory:
                        # Check if there is an old log file
                        compare = compareFiles(fr'logs\{processID}-scan.txt', fr'logs\{processID}.txt')

                        if compare == 1:
                            # If the log files are different, delete the old one
                            logPath = fr'{processID}.txt'
                            try:
                                os.remove(fr'logs\{processID}.txt')
                                #print(fr'{processID}.txt has been deleted')
                            except FileNotFoundError:
                                print(fr'{processID}.txt does not exist')
                            except PermissionError:
                                print(fr'Permission denied: {logPath}')
                            except Exception as e:
                                print(fr'Error: {e}')

                            scanDir = fr'.\scans'
                            scanDirectory = os.listdir(scanDir)

                            scanPath = fr'scans\{processID}.csv'

                            if fr'{processID}.csv' in scanDirectory:
                                try:
                                    os.remove(fr'scans\{processID}.csv')
                                    print(fr'{processID}.csv has been deleted')
                                except FileNotFoundError:
                                    print(fr'{processID}.csv does not exist')
                                except PermissionError:
                                    print(fr'Permission denied: {scanPath}')
                                except Exception as e:
                                    print(fr'Error: {e}')
                            
                            os.rename(fr'logs\{processID}-scan.txt', fr'logs\{processID}.txt') # Rename new file

                            scanPath = fr'scans\{processID}.csv'
                            filePath = fr'.\logs\{processID}.txt'
                            generateCSV(logDir, filePath, scanPath)

                            scanDir = fr'.\scans'
                            scanDirectory = os.listdir(scanDir)

                            if fr'{processID}.csv' in scanDirectory:
                                df = pd.read_csv(scanPath)

                                #dataMemory = df[['VA Start', 'RVA', 'Size', 'PID']].astype(str)
                                #dataModules = df[['Module Name', 'Base Address', 'Size', 'Endaddress', 'Timestamp', 'PID']].astype(str)
                                dataThreads = df[['ThreadID', 'SuspendCount', 'PriorityClass', 'Priority', 'Teb', 'PID']].copy()

                                dataThreads['ThreadID'] = dataThreads['ThreadID'].astype(str)
                                dataThreads['SuspendCount'] = dataThreads['SuspendCount'].astype(str)
                                dataThreads['PriorityClass'] = dataThreads['PriorityClass'].astype(str)
                                dataThreads['Priority'] = dataThreads['Priority'].astype(str)
                                dataThreads['Teb'] = dataThreads['Teb'].astype(str)
                                dataThreads['PID'] = dataThreads['PID'].astype(str)
                                
                                X_test = threadsPreprocessor.transform(dataThreads)

                                evaluate_model(processID, knThreads, X_test)
                                endTest = time.time()
                                lengthTest = endTest - startTest
                                print(lengthTest, 'seconds')
                                continue
                            else:
                                time.sleep(2)
                                os.remove(fr'logs\{processID}.txt')
                                #print(fr'No dump made for process {processID}')
                                endTest = time.time()
                                #print('Invalid time')
                                continue
                        else:
                            # If the log files are the same, delete the new file
                            time.sleep(2)
                            try:
                                os.remove(fr'logs\{processID}-scan.txt')
                                #print(fr'{processID}-scan.txt has been deleted')
                            except FileNotFoundError:
                                print(fr'{processID}-scan.txt does not exist')
                            except PermissionError:
                                print(fr'Permission denied: {logScanPath}')
                            except Exception as e:
                                print(fr'Error: {e}')

                            endTest = time.time()
                            lengthTest = endTest - startTest
                            print(lengthTest, 'seconds')
                            continue
                    else:
                        time.sleep(1)
                        os.rename(fr'logs\{processID}-scan.txt', fr'logs\{processID}.txt') # If there is no older file, rename

                        logPath = fr'{processID}.txt'

                        scanDir = fr'.\scans'
                        scanDirectory = os.listdir(scanDir)

                        scanPath = fr'scans\{processID}.csv'

                        if fr'{processID}.csv' in scanDirectory:
                            try:
                                os.remove(fr'scans\{processID}.csv')
                                print(fr'{processID}.csv has been deleted')
                            except FileNotFoundError:
                                print(fr'{processID}.csv does not exist')
                            except PermissionError:
                                print(fr'Permission denied: {scanPath}')
                            except Exception as e:
                                print(fr'Error: {e}')

                        scanPath = fr'scans\{processID}.csv'
                        filePath = fr'.\logs\{processID}.txt'
                        generateCSV(logDir, filePath, scanPath)

                        scanDir = fr'.\scans'
                        scanDirectory = os.listdir(scanDir)

                        if fr'{processID}.csv' in scanDirectory:
                            df = pd.read_csv(scanPath)

                            #dataMemory = df[['VA Start', 'RVA', 'Size', 'PID']].astype(str)
                            #dataModules = df[['Module Name', 'Base Address', 'Size', 'Endaddress', 'Timestamp', 'PID']].astype(str)
                            dataThreads = df[['ThreadID', 'SuspendCount', 'PriorityClass', 'Priority', 'Teb', 'PID']].copy()
  
                            dataThreads['ThreadID'] = dataThreads['ThreadID'].astype(str)
                            dataThreads['SuspendCount'] = dataThreads['SuspendCount'].astype(str)
                            dataThreads['PriorityClass'] = dataThreads['PriorityClass'].astype(str)
                            dataThreads['Priority'] = dataThreads['Priority'].astype(str)
                            dataThreads['Teb'] = dataThreads['Teb'].astype(str)
                            dataThreads['PID'] = dataThreads['PID'].astype(str)
                            
                            X_test = threadsPreprocessor.transform(dataThreads)

                            evaluate_model(processID, knThreads, X_test)
                            endTest = time.time()
                            lengthTest = endTest - startTest
                            print(lengthTest, 'seconds')
                            continue
                else:
                    #print(fr'No dump made for process {processID}')
                    ## !!!Remove Process ID if no dumps
                    processIDs.remove(processID)
                    endTest = time.time()
                    lengthTest = endTest - startTest
                    print(lengthTest, 'seconds')
                    continue # Check if a dump was made and move onto next process if not

    # Option 2: All Processes
    if selection == '2':
        exit

if __name__=='__main__':
    dumpDir = fr'.\dumps'
    logDir = fr'.\logs'
    scanDir = fr'.\scans'

    try:
        main()
    except KeyboardInterrupt:
        remove_files(dumpDir)
        remove_files(logDir)
        remove_files(scanDir)
    